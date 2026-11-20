//! Local Root CA lifecycle, on-demand ECDSA P-256 leaf certificate minting,
//! and OS trust-store management for selective AI-host TLS interception.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::{DateTime, Datelike, Duration as ChronoDuration, NaiveDate, NaiveDateTime, TimeZone, Timelike, Utc};
#[cfg(windows)]
use once_cell::sync::OnceCell;
use parking_lot::{Mutex, RwLock};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{compiler_fence, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

const CA_CERT_FILENAME: &str = "hide-go-ca.crt";
const CA_KEY_FILENAME: &str = "hide-go-ca.key";
const CA_BUNDLE_FILENAME: &str = "hide-go-ca-bundle.pem";
const CA_COMMON_NAME: &str = "Hide-Go Local Privacy CA";
const CA_ORG_NAME: &str = "Hide-Go Privacy Gateway";
const LEAF_CACHE_MAX_ENTRIES: usize = 512;
const LEAF_TTL_DAYS: i64 = 90;
const LEAF_CACHE_REFRESH_SECS: u64 = 60 * 60 * 24 * 60; // Refresh cached leaf after 60 days
const MAX_CONCURRENT_LEAF_MINTS: usize = 4;
const TRUST_CMD_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(windows)]
const SYSTEM_ROOTS_TIMEOUT: Duration = Duration::from_secs(25);

static TRUST_CMD_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn zeroize_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // Volatile write prevents dead-store elimination on sensitive key buffers.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

pub(crate) fn zeroize_string(s: &mut String) {
    // SAFETY: zero bytes are valid UTF-8.
    unsafe { zeroize_bytes(s.as_bytes_mut()) };
    s.clear();
}

#[cfg(windows)]
fn windows_system_binary(rel_path: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("WINDIR"))
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    root.join("System32").join(rel_path)
}

#[cfg(windows)]
fn hidden_system_command(rel_path: &str) -> Command {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let bin = windows_system_binary(rel_path);
    let mut cmd = Command::new(bin);
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

#[cfg(windows)]
fn current_windows_user_sid() -> Result<&'static str, String> {
    static SID_CACHE: OnceCell<Result<String, String>> = OnceCell::new();
    let res = SID_CACHE.get_or_init(|| {
        let mut cmd = hidden_system_command("whoami.exe");
        cmd.args(["/user", "/fo", "csv", "/nh"]);
        let out = run_command_with_timeout(cmd, Duration::from_secs(5))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return Err(format!("whoami /user failed: {stderr}"));
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if let Some(last_comma) = trimmed.rfind(',') {
                let sid = trimmed[last_comma + 1..].trim().trim_matches('"').trim();
                if sid.starts_with("S-1-")
                    && sid.len() <= 128
                    && sid.bytes().all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
                {
                    return Ok(sid.to_string());
                }
            }
        }
        Err("could not parse current Windows user SID from whoami output".to_string())
    });
    res.as_deref().map_err(Clone::clone)
}

const MAX_COMMAND_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;

fn spawn_pipe_reader<R: Read + Send + 'static>(pipe: Option<R>) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = pipe {
            let _ = p.take(MAX_COMMAND_OUTPUT_BYTES).read_to_end(&mut buf);
        }
        buf
    })
}

fn run_command_with_timeout(mut cmd: Command, timeout: Duration) -> Result<std::process::Output, String> {
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("failed to spawn command: {e}"))?;
    // Drain stdout/stderr concurrently so large outputs (e.g. Windows Root CA store) cannot fill the OS pipe buffer and deadlock try_wait().
    let stdout_handle = spawn_pipe_reader(child.stdout.take());
    let stderr_handle = spawn_pipe_reader(child.stderr.take());
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = stdout_handle.join().unwrap_or_default();
                let stderr = stderr_handle.join().unwrap_or_default();
                return Ok(std::process::Output { status, stdout, stderr });
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_handle.join();
                    let _ = stderr_handle.join();
                    return Err(format!("command timed out after {}s", timeout.as_secs()));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_handle.join();
                let _ = stderr_handle.join();
                return Err(format!("failed waiting for command: {e}"));
            }
        }
    }
}

pub(crate) fn harden_private_dir_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("failed to set 0700 permissions on {}: {e}", path.display()))?;
    }
    #[cfg(windows)]
    {
        let sid = current_windows_user_sid()?;
        let sid_grant = format!("*{sid}:(OI)(CI)F");
        let path_str = path.to_string_lossy().into_owned();
        let mut cmd = hidden_system_command("icacls.exe");
        cmd.args([
            path_str.as_str(),
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            sid_grant.as_str(),
        ]);
        let out = run_command_with_timeout(cmd, Duration::from_secs(10))?;
        if !out.status.success() {
            let detail = String::from_utf8_lossy(&out.stderr);
            return Err(format!("icacls failed on {}: {}", path.display(), detail.trim()));
        }
    }
    Ok(())
}

pub(crate) fn harden_private_file_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("failed to set 0600 permissions on {}: {e}", path.display()))?;
    }
    #[cfg(windows)]
    {
        let sid = current_windows_user_sid()?;
        let sid_grant = format!("*{sid}:F");
        let path_str = path.to_string_lossy().into_owned();
        let mut cmd = hidden_system_command("icacls.exe");
        cmd.args([
            path_str.as_str(),
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:F",
            sid_grant.as_str(),
        ]);
        let out = run_command_with_timeout(cmd, Duration::from_secs(10))?;
        if !out.status.success() {
            let detail = String::from_utf8_lossy(&out.stderr);
            return Err(format!("icacls failed on {}: {}", path.display(), detail.trim()));
        }
    }
    Ok(())
}

pub(crate) fn atomic_write_private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| format!("failed to create dir {}: {e}", dir.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir).map_err(|e| format!("failed to create dir {}: {e}", dir.display()))?;
    }

    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("private.tmp");
    let tmp_path = dir.join(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4().simple()));

    let write_res: Result<(), String> = (|| {
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)
                .map_err(|e| format!("failed to create {}: {e}", tmp_path.display()))?
        };
        #[cfg(not(unix))]
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .map_err(|e| format!("failed to create {}: {e}", tmp_path.display()))?;

        file.write_all(bytes)
            .map_err(|e| format!("failed to write {}: {e}", tmp_path.display()))?;
        file.sync_all()
            .map_err(|e| format!("failed to sync {}: {e}", tmp_path.display()))?;
        drop(file);
        harden_private_file_permissions(&tmp_path)?;
        std::fs::rename(&tmp_path, path).map_err(|e| format!("failed to replace {}: {e}", path.display()))?;
        Ok(())
    })();

    if write_res.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_res
}

/// Status of the local Hide-Go Root CA and OS trust store integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaStatus {
    pub ready: bool,
    pub ca_cert_path: String,
    pub ca_bundle_path: String,
    pub fingerprint_sha1: String,
    pub fingerprint_sha256: String,
    pub subject: String,
    pub not_after: String,
    pub installed_in_os_store: bool,
    pub os_trust_supported: bool,
    pub os_trust_detail: String,
}

/// Abstract OS Root Certificate Store adapter so production uses `certutil` / `security`
/// while automated tests run completely isolated in memory without mutating host trust.
pub trait CaTrustAdapter: Send + Sync {
    fn platform_supported(&self) -> bool;
    fn is_trusted(&self, sha1_thumbprint: &str, cert_path: &Path) -> Result<bool, String>;
    fn install_trust(&self, sha1_thumbprint: &str, cert_path: &Path) -> Result<String, String>;
    fn remove_trust(&self, sha1_thumbprint: &str, cert_path: &Path) -> Result<String, String>;
    fn system_roots_pem(&self) -> Option<String>;
}

/// Production OS certificate store adapter.
pub struct RealCaTrustAdapter;

impl CaTrustAdapter for RealCaTrustAdapter {
    fn platform_supported(&self) -> bool {
        cfg!(any(windows, target_os = "macos", target_os = "linux"))
    }

    fn is_trusted(&self, sha1_thumbprint: &str, _cert_path: &Path) -> Result<bool, String> {
        let _guard = TRUST_CMD_LOCK.lock();
        #[cfg(windows)]
        {
            let mut cmd = hidden_system_command("certutil.exe");
            cmd.args(["-user", "-verifystore", "Root", sha1_thumbprint]);
            let out =
                run_command_with_timeout(cmd, TRUST_CMD_TIMEOUT).map_err(|e| format!("failed to run certutil: {e}"))?;
            Ok(out.status.success())
        }
        #[cfg(target_os = "macos")]
        {
            let keychain = macos_login_keychain()?;
            let mut cmd = Command::new("security");
            cmd.args([
                "find-certificate",
                "-c",
                CA_COMMON_NAME,
                "-Z",
                keychain.to_string_lossy().as_ref(),
            ]);
            let out =
                run_command_with_timeout(cmd, TRUST_CMD_TIMEOUT).map_err(|e| format!("failed to run security: {e}"))?;
            if !out.status.success() {
                return Ok(false);
            }
            let stdout = String::from_utf8_lossy(&out.stdout).to_ascii_uppercase();
            Ok(stdout.contains(&sha1_thumbprint.to_ascii_uppercase()))
        }
        #[cfg(all(not(windows), not(target_os = "macos")))]
        {
            let sys_cert = Path::new("/usr/local/share/ca-certificates/hide-go-ca.crt");
            if let Ok(pem) = std::fs::read_to_string(sys_cert) {
                if let Ok(der) = decode_pem(&pem, "CERTIFICATE") {
                    if sha1_hex(&der).eq_ignore_ascii_case(sha1_thumbprint) {
                        return Ok(true);
                    }
                }
            }
            if let Some(nss) = linux_nss_db_dir() {
                let mut cmd = Command::new("certutil");
                cmd.args(["-L", "-d", &format!("sql:{}", nss.display()), "-n", CA_COMMON_NAME]);
                if let Ok(out) = run_command_with_timeout(cmd, TRUST_CMD_TIMEOUT) {
                    if out.status.success() {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
    }

    fn install_trust(&self, sha1_thumbprint: &str, cert_path: &Path) -> Result<String, String> {
        let _guard = TRUST_CMD_LOCK.lock();
        #[cfg(windows)]
        {
            let _ = sha1_thumbprint;
            let cert_str = cert_path.to_string_lossy().into_owned();
            let mut cmd = hidden_system_command("certutil.exe");
            cmd.args(["-user", "-addstore", "Root", &cert_str]);
            let out =
                run_command_with_timeout(cmd, TRUST_CMD_TIMEOUT).map_err(|e| format!("无法执行 certutil: {e}"))?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let detail = if !stderr.is_empty() { stderr } else { stdout };
                return Err(format!("导入 Windows 当前用户根证书失败: {detail}"));
            }
            Ok("已安装到 Windows 当前用户“受信任的根证书颁发机构”".to_string())
        }
        #[cfg(target_os = "macos")]
        {
            let _ = sha1_thumbprint;
            let keychain = macos_login_keychain()?;
            let mut cmd = Command::new("security");
            cmd.args([
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-k",
                keychain.to_string_lossy().as_ref(),
                cert_path.to_string_lossy().as_ref(),
            ]);
            let out =
                run_command_with_timeout(cmd, TRUST_CMD_TIMEOUT).map_err(|e| format!("无法执行 security: {e}"))?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                return Err(format!("导入 macOS 登录钥匙串根证书失败: {stderr}"));
            }
            Ok("已安装到 macOS 登录钥匙串并设为始终信任".to_string())
        }
        #[cfg(all(not(windows), not(target_os = "macos")))]
        {
            let _ = sha1_thumbprint;
            if let Some(nss) = linux_nss_db_dir() {
                let mut cmd = Command::new("certutil");
                cmd.args([
                    "-A",
                    "-d",
                    &format!("sql:{}", nss.display()),
                    "-n",
                    CA_COMMON_NAME,
                    "-t",
                    "C,,",
                    "-i",
                    cert_path.to_string_lossy().as_ref(),
                ]);
                if let Ok(out) = run_command_with_timeout(cmd, TRUST_CMD_TIMEOUT) {
                    if out.status.success() {
                        return Ok("已安装到用户 NSS 证书库 (~/.pki/nssdb)".to_string());
                    }
                }
            }
            Err(format!(
                "Linux 系统根证书需要管理员权限，请运行: sudo cp '{}' /usr/local/share/ca-certificates/hide-go-ca.crt && sudo update-ca-certificates",
                cert_path.display()
            ))
        }
    }

    fn remove_trust(&self, sha1_thumbprint: &str, cert_path: &Path) -> Result<String, String> {
        let _guard = TRUST_CMD_LOCK.lock();
        #[cfg(windows)]
        {
            let _ = cert_path;
            let mut cmd = hidden_system_command("certutil.exe");
            cmd.args(["-user", "-delstore", "Root", sha1_thumbprint]);
            let out =
                run_command_with_timeout(cmd, TRUST_CMD_TIMEOUT).map_err(|e| format!("无法执行 certutil: {e}"))?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let detail = if !stderr.is_empty() { stderr } else { stdout };
                return Err(format!("移除 Windows 根证书失败: {detail}"));
            }
            Ok("已从 Windows 当前用户根证书存储移除".to_string())
        }
        #[cfg(target_os = "macos")]
        {
            let _ = cert_path;
            let keychain = macos_login_keychain()?;
            let mut cmd = Command::new("security");
            cmd.args([
                "delete-certificate",
                "-Z",
                sha1_thumbprint,
                keychain.to_string_lossy().as_ref(),
            ]);
            let out =
                run_command_with_timeout(cmd, TRUST_CMD_TIMEOUT).map_err(|e| format!("无法执行 security: {e}"))?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                return Err(format!("移除 macOS 根证书失败: {stderr}"));
            }
            Ok("已从 macOS 登录钥匙串移除".to_string())
        }
        #[cfg(all(not(windows), not(target_os = "macos")))]
        {
            let _ = (sha1_thumbprint, cert_path);
            if let Some(nss) = linux_nss_db_dir() {
                let mut cmd = Command::new("certutil");
                cmd.args(["-D", "-d", &format!("sql:{}", nss.display()), "-n", CA_COMMON_NAME]);
                if let Ok(out) = run_command_with_timeout(cmd, TRUST_CMD_TIMEOUT) {
                    if out.status.success() {
                        return Ok("已从用户 NSS 证书库移除".to_string());
                    }
                }
            }
            Ok("未检测到用户 NSS 证书条目".to_string())
        }
    }

    fn system_roots_pem(&self) -> Option<String> {
        let _guard = TRUST_CMD_LOCK.lock();
        #[cfg(windows)]
        {
            let script = r#"
$seen = @{}
$sb = New-Object System.Text.StringBuilder
foreach ($loc in @('LocalMachine', 'CurrentUser')) {
  $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', $loc)
  try {
    $store.Open('ReadOnly')
    foreach ($c in $store.Certificates) {
      if ($c.Subject -like '*Hide-Go Local Privacy CA*') { continue }
      if (-not $seen.ContainsKey($c.Thumbprint)) {
        $seen[$c.Thumbprint] = $true
        [void]$sb.AppendLine('-----BEGIN CERTIFICATE-----')
        [void]$sb.AppendLine([Convert]::ToBase64String($c.RawData, 'InsertLineBreaks'))
        [void]$sb.AppendLine('-----END CERTIFICATE-----')
      }
    }
  } finally {
    $store.Close()
  }
}
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::Write($sb.ToString())
"#;
            let mut cmd = hidden_system_command(r"WindowsPowerShell\v1.0\powershell.exe");
            cmd.args(["-NoProfile", "-NonInteractive", "-Command", script]);
            let out = run_command_with_timeout(cmd, SYSTEM_ROOTS_TIMEOUT).ok()?;
            if out.status.success() {
                let pem = String::from_utf8_lossy(&out.stdout).into_owned();
                if pem.contains("BEGIN CERTIFICATE") {
                    return Some(pem);
                }
            }
            None
        }
        #[cfg(target_os = "macos")]
        {
            std::fs::read_to_string("/etc/ssl/cert.pem").ok()
        }
        #[cfg(all(not(windows), not(target_os = "macos")))]
        {
            for p in [
                "/etc/ssl/certs/ca-certificates.crt",
                "/etc/pki/tls/certs/ca-bundle.crt",
                "/etc/ssl/ca-bundle.pem",
                "/etc/ssl/cert.pem",
            ] {
                if let Ok(text) = std::fs::read_to_string(p) {
                    if text.contains("BEGIN CERTIFICATE") {
                        return Some(text);
                    }
                }
            }
            None
        }
    }
}

#[cfg(target_os = "macos")]
fn macos_login_keychain() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| "cannot resolve HOME".to_string())?;
    Ok(home.join("Library/Keychains/login.keychain-db"))
}

#[cfg(all(not(windows), not(target_os = "macos")))]
fn linux_nss_db_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").filter(|v| !v.is_empty()).map(PathBuf::from)?;
    let db = home.join(".pki/nssdb");
    db.is_dir().then_some(db)
}

/// In-memory `CaTrustAdapter` for isolated automated tests (never mutates OS trust stores).
#[derive(Default)]
pub struct MockCaTrustAdapter {
    trusted: Mutex<HashSet<String>>,
    extra_roots_pem: Mutex<Option<String>>,
}

impl MockCaTrustAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_system_roots(pem: impl Into<String>) -> Self {
        Self {
            trusted: Mutex::new(HashSet::new()),
            extra_roots_pem: Mutex::new(Some(pem.into())),
        }
    }
}

impl CaTrustAdapter for MockCaTrustAdapter {
    fn platform_supported(&self) -> bool {
        true
    }

    fn is_trusted(&self, sha1_thumbprint: &str, _cert_path: &Path) -> Result<bool, String> {
        Ok(self.trusted.lock().contains(sha1_thumbprint))
    }

    fn install_trust(&self, sha1_thumbprint: &str, _cert_path: &Path) -> Result<String, String> {
        self.trusted.lock().insert(sha1_thumbprint.to_string());
        Ok("mock trust installed".to_string())
    }

    fn remove_trust(&self, sha1_thumbprint: &str, _cert_path: &Path) -> Result<String, String> {
        self.trusted.lock().remove(sha1_thumbprint);
        Ok("mock trust removed".to_string())
    }

    fn system_roots_pem(&self) -> Option<String> {
        self.extra_roots_pem.lock().clone()
    }
}

struct CachedLeaf {
    server_config: Arc<ServerConfig>,
    created_at: Instant,
}

/// Local Root CA & dynamic leaf-certificate manager.
pub struct CaManager {
    ca_dir: Option<PathBuf>,
    ca_cert_der: Vec<u8>,
    ca_cert_pem: String,
    ca_subject_der: Vec<u8>,
    ca_ski: [u8; 20],
    ca_key: EcdsaKeyPair,
    not_after: DateTime<Utc>,
    fingerprint_sha1: String,
    fingerprint_sha256: String,
    trust_adapter: Arc<dyn CaTrustAdapter>,
    leaf_cache: RwLock<HashMap<String, CachedLeaf>>,
    mint_semaphore: Arc<Semaphore>,
    rng: SystemRandom,
    tls_provider: Arc<rustls::crypto::CryptoProvider>,
}

impl CaManager {
    /// Resolve the default CA directory next to `HideConfig::default_path()`.
    pub fn default_ca_dir() -> Option<PathBuf> {
        crate::config::HideConfig::default_path().and_then(|p| p.parent().map(|d| d.join("ca")))
    }

    /// Load existing CA keypair/cert from `ca_dir`, or generate and persist a new one.
    pub fn load_or_create(ca_dir: PathBuf, trust_adapter: Arc<dyn CaTrustAdapter>) -> Result<Self, String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&ca_dir)
                .map_err(|e| format!("failed to create CA directory {}: {e}", ca_dir.display()))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(&ca_dir)
                .map_err(|e| format!("failed to create CA directory {}: {e}", ca_dir.display()))?;
        }
        harden_private_dir_permissions(&ca_dir)?;
        let cert_path = ca_dir.join(CA_CERT_FILENAME);
        let key_path = ca_dir.join(CA_KEY_FILENAME);

        let rng = SystemRandom::new();
        if cert_path.exists() || key_path.exists() {
            if !cert_path.is_file() || !key_path.is_file() {
                return Err(format!(
                    "incomplete CA files in {}; refusing to overwrite existing CA state",
                    ca_dir.display()
                ));
            }
            return Self::try_load_existing(&ca_dir, &cert_path, &key_path, &rng, trust_adapter);
        }

        Self::generate_and_persist(Some(ca_dir), &rng, trust_adapter)
    }

    /// Create an in-memory ephemeral CA (fallback when config dir is unavailable or for isolated tests).
    pub fn ephemeral(trust_adapter: Arc<dyn CaTrustAdapter>) -> Result<Self, String> {
        let rng = SystemRandom::new();
        Self::generate_and_persist(None, &rng, trust_adapter)
    }

    fn try_load_existing(
        ca_dir: &Path,
        cert_path: &Path,
        key_path: &Path,
        rng: &SystemRandom,
        trust_adapter: Arc<dyn CaTrustAdapter>,
    ) -> Result<Self, String> {
        let _ = harden_private_file_permissions(key_path);
        let cert_pem = std::fs::read_to_string(cert_path).map_err(|e| e.to_string())?;
        let mut key_pem = std::fs::read_to_string(key_path).map_err(|e| e.to_string())?;
        let cert_der = decode_pem(&cert_pem, "CERTIFICATE")?;
        let mut key_der = decode_pem(&key_pem, "PRIVATE KEY")?;
        zeroize_string(&mut key_pem);
        let key_res = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &key_der, rng)
            .map_err(|e| format!("invalid CA private key: {e:?}"));
        zeroize_bytes(&mut key_der);
        let ca_key = key_res?;

        let expected_spki = build_ec_p256_spki(ca_key.public_key().as_ref());
        let meta = parse_x509_tbs(&cert_der)?;
        if meta.spki_der != expected_spki {
            return Err("CA certificate public key does not match private key".to_string());
        }
        if Utc::now() > meta.not_after {
            return Err("CA certificate has expired".to_string());
        }

        let ca_ski = compute_ski(&expected_spki);
        let fingerprint_sha1 = sha1_hex(&cert_der);
        let fingerprint_sha256 = sha256_colon_hex(&cert_der);

        let mgr = Self {
            ca_dir: Some(ca_dir.to_path_buf()),
            ca_cert_der: cert_der,
            ca_cert_pem: cert_pem,
            ca_subject_der: meta.subject_der,
            ca_ski,
            ca_key,
            not_after: meta.not_after,
            fingerprint_sha1,
            fingerprint_sha256,
            trust_adapter,
            leaf_cache: RwLock::new(HashMap::new()),
            mint_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_LEAF_MINTS)),
            rng: SystemRandom::new(),
            tls_provider: Arc::new(rustls::crypto::ring::default_provider()),
        };
        mgr.ensure_bundle_file();
        Ok(mgr)
    }

    fn generate_and_persist(
        ca_dir: Option<PathBuf>,
        rng: &SystemRandom,
        trust_adapter: Arc<dyn CaTrustAdapter>,
    ) -> Result<Self, String> {
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, rng)
            .map_err(|_| "failed to generate CA ECDSA P-256 keypair".to_string())?;
        let ca_key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), rng)
            .map_err(|e| format!("failed to parse generated CA keypair: {e:?}"))?;

        let now_raw = Utc::now();
        let now = DateTime::from_timestamp(now_raw.timestamp(), 0).unwrap_or(now_raw);
        let not_before = now - ChronoDuration::days(1);
        let not_after = now + ChronoDuration::days(3650);
        let serial = random_serial(rng)?;
        let ca_subject_der = build_name_der(CA_COMMON_NAME, Some(CA_ORG_NAME));
        let spki = build_ec_p256_spki(ca_key.public_key().as_ref());
        let ca_ski = compute_ski(&spki);

        let ca_cert_der = build_signed_x509(
            &serial,
            &ca_subject_der,
            &ca_subject_der,
            not_before,
            not_after,
            &spki,
            &[
                ext_basic_constraints_ca(),
                ext_key_usage_ca(),
                ext_subject_key_identifier(&ca_ski),
            ],
            &ca_key,
            rng,
        )?;

        let ca_cert_pem = encode_pem("CERTIFICATE", &ca_cert_der);
        let mut ca_key_pem = encode_pem("PRIVATE KEY", pkcs8.as_ref());

        if let Some(dir) = &ca_dir {
            let cert_path = dir.join(CA_CERT_FILENAME);
            let key_path = dir.join(CA_KEY_FILENAME);
            let write_key_res = atomic_write_private_file(&key_path, ca_key_pem.as_bytes());
            zeroize_string(&mut ca_key_pem);
            write_key_res?;
            atomic_write_text_file(&cert_path, &ca_cert_pem)?;
        } else {
            zeroize_string(&mut ca_key_pem);
        }

        let fingerprint_sha1 = sha1_hex(&ca_cert_der);
        let fingerprint_sha256 = sha256_colon_hex(&ca_cert_der);
        let mgr = Self {
            ca_dir,
            ca_cert_der,
            ca_cert_pem,
            ca_subject_der,
            ca_ski,
            ca_key,
            not_after,
            fingerprint_sha1,
            fingerprint_sha256,
            trust_adapter,
            leaf_cache: RwLock::new(HashMap::new()),
            mint_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_LEAF_MINTS)),
            rng: SystemRandom::new(),
            tls_provider: Arc::new(rustls::crypto::ring::default_provider()),
        };
        mgr.ensure_bundle_file();
        Ok(mgr)
    }

    fn ensure_bundle_file(&self) {
        let Some(dir) = &self.ca_dir else { return };
        let bundle_path = dir.join(CA_BUNDLE_FILENAME);
        if bundle_path.is_file() {
            if let Ok(existing) = std::fs::read_to_string(&bundle_path) {
                if existing.contains(self.ca_cert_pem.trim()) {
                    return;
                }
            }
        }
        self.rebuild_bundle_file();
    }

    fn rebuild_bundle_file(&self) {
        let Some(dir) = &self.ca_dir else { return };
        let bundle_path = dir.join(CA_BUNDLE_FILENAME);
        let mut content = self.trust_adapter.system_roots_pem().unwrap_or_default();
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        content.push_str(&self.ca_cert_pem);
        if let Err(err) = atomic_write_text_file(&bundle_path, &content) {
            tracing::warn!("failed to write CA bundle {}: {err}", bundle_path.display());
        }
    }

    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    pub fn ca_cert_der(&self) -> &[u8] {
        &self.ca_cert_der
    }

    pub fn ca_cert_path(&self) -> Option<PathBuf> {
        self.ca_dir.as_ref().map(|d| d.join(CA_CERT_FILENAME))
    }

    pub fn ca_bundle_path(&self) -> Option<PathBuf> {
        self.ca_dir.as_ref().map(|d| d.join(CA_BUNDLE_FILENAME))
    }

    pub fn status(&self) -> CaStatus {
        let cert_path = self.ca_cert_path().unwrap_or_default();
        let bundle_path = self.ca_bundle_path().unwrap_or_default();
        let supported = self.trust_adapter.platform_supported();
        let (trusted, detail) = if supported {
            match self.trust_adapter.is_trusted(&self.fingerprint_sha1, &cert_path) {
                Ok(true) => (true, "已在当前用户受信任根证书存储中".to_string()),
                Ok(false) => (false, "尚未导入系统受信任根证书存储".to_string()),
                Err(err) => (false, format!("检测信任状态失败: {err}")),
            }
        } else {
            (false, "当前平台不支持自动根证书导入".to_string())
        };

        CaStatus {
            ready: true,
            ca_cert_path: cert_path.to_string_lossy().into_owned(),
            ca_bundle_path: bundle_path.to_string_lossy().into_owned(),
            fingerprint_sha1: self.fingerprint_sha1.clone(),
            fingerprint_sha256: self.fingerprint_sha256.clone(),
            subject: format!("CN={CA_COMMON_NAME}, O={CA_ORG_NAME}"),
            not_after: self.not_after.to_rfc3339(),
            installed_in_os_store: trusted,
            os_trust_supported: supported,
            os_trust_detail: detail,
        }
    }

    pub fn install_trust(&self) -> Result<CaStatus, String> {
        let Some(cert_path) = self.ca_cert_path() else {
            return Err("临时内存 CA 无法导入系统存储".to_string());
        };
        let msg = self.trust_adapter.install_trust(&self.fingerprint_sha1, &cert_path)?;
        self.rebuild_bundle_file();
        let mut st = self.status();
        st.os_trust_detail = msg;
        Ok(st)
    }

    pub fn remove_trust(&self) -> Result<CaStatus, String> {
        let Some(cert_path) = self.ca_cert_path() else {
            return Err("临时内存 CA 无需移除".to_string());
        };
        let msg = self.trust_adapter.remove_trust(&self.fingerprint_sha1, &cert_path)?;
        let mut st = self.status();
        st.os_trust_detail = msg;
        Ok(st)
    }

    /// Return a cached `rustls::ServerConfig` for `host` (mints a leaf certificate on demand).
    pub fn server_config_for_host(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        let normalized = validate_leaf_host(host)?;
        if let Some(cfg) = self.cached_leaf(&normalized) {
            return Ok(cfg);
        }

        let cfg = self.mint_server_config(&normalized)?;
        self.insert_cached_leaf(normalized, cfg.clone());
        Ok(cfg)
    }

    /// Async version that offloads ECDSA leaf keygen/signing to `spawn_blocking`
    /// under a bounded concurrency semaphore to protect the Tokio runtime and CPU.
    pub async fn server_config_for_host_async(self: &Arc<Self>, host: &str) -> Result<Arc<ServerConfig>, String> {
        let normalized = validate_leaf_host(host)?;
        if let Some(cfg) = self.cached_leaf(&normalized) {
            return Ok(cfg);
        }

        let _permit = self
            .mint_semaphore
            .acquire()
            .await
            .map_err(|_| "CA mint semaphore closed".to_string())?;
        if let Some(cfg) = self.cached_leaf(&normalized) {
            return Ok(cfg);
        }

        let this = self.clone();
        let host_owned = normalized.clone();
        let cfg = tokio::task::spawn_blocking(move || this.mint_server_config(&host_owned))
            .await
            .map_err(|_| "leaf certificate minting task panicked".to_string())??;
        self.insert_cached_leaf(normalized, cfg.clone());
        Ok(cfg)
    }

    fn cached_leaf(&self, normalized: &str) -> Option<Arc<ServerConfig>> {
        let cache = self.leaf_cache.read();
        cache
            .get(normalized)
            .filter(|entry| entry.created_at.elapsed() < Duration::from_secs(LEAF_CACHE_REFRESH_SECS))
            .map(|entry| entry.server_config.clone())
    }

    fn insert_cached_leaf(&self, normalized: String, cfg: Arc<ServerConfig>) {
        let mut cache = self.leaf_cache.write();
        if cache.len() >= LEAF_CACHE_MAX_ENTRIES && !cache.contains_key(&normalized) {
            let oldest_key = cache.iter().min_by_key(|(_, v)| v.created_at).map(|(k, _)| k.clone());
            if let Some(k) = oldest_key {
                cache.remove(&k);
            }
        }
        cache.insert(
            normalized,
            CachedLeaf {
                server_config: cfg,
                created_at: Instant::now(),
            },
        );
    }

    fn mint_server_config(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        let leaf_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &self.rng)
            .map_err(|_| "failed to generate leaf ECDSA P-256 key".to_string())?;
        let leaf_key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, leaf_pkcs8.as_ref(), &self.rng)
            .map_err(|e| format!("failed to parse leaf key: {e:?}"))?;

        let now = Utc::now();
        let not_before = now - ChronoDuration::days(1);
        let not_after = now + ChronoDuration::days(LEAF_TTL_DAYS);
        let serial = random_serial(&self.rng)?;
        let cn = if host.len() > 64 {
            "Hide-Go Intercepted Host"
        } else {
            host
        };
        let subject_der = build_name_der(cn, Some("Hide-Go Leaf"));
        let spki = build_ec_p256_spki(leaf_key.public_key().as_ref());
        let leaf_ski = compute_ski(&spki);

        let leaf_der = build_signed_x509(
            &serial,
            &self.ca_subject_der,
            &subject_der,
            not_before,
            not_after,
            &spki,
            &[
                ext_basic_constraints_leaf(),
                ext_key_usage_leaf(),
                ext_eku_server_auth(),
                ext_san_host(host),
                ext_subject_key_identifier(&leaf_ski),
                ext_authority_key_identifier(&self.ca_ski),
            ],
            &self.ca_key,
            &self.rng,
        )?;

        let cert_chain = vec![
            CertificateDer::from(leaf_der),
            CertificateDer::from(self.ca_cert_der.clone()),
        ];
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_pkcs8.as_ref().to_vec()));

        let mut server_config = ServerConfig::builder_with_provider(self.tls_provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("rustls protocol versions failed: {e}"))?
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| format!("rustls server cert config failed: {e}"))?;
        // Advertise both HTTP/2 and HTTP/1.1 so gRPC / HTTP/2 harnesses negotiate seamlessly inside CONNECT tunnels.
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(Arc::new(server_config))
    }
}

fn normalize_host(host: &str) -> String {
    let trimmed = host.trim();
    let unbracketed = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);
    unbracketed.trim_end_matches('.').to_ascii_lowercase()
}

pub(crate) fn validate_leaf_host(host: &str) -> Result<String, String> {
    let norm = normalize_host(host);
    if norm.is_empty() || norm.len() > 253 {
        return Err("invalid target host length".to_string());
    }
    if norm.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("target host contains forbidden control or whitespace characters".to_string());
    }
    if let Ok(ip) = norm.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    if norm.contains('*') || !norm.is_ascii() {
        return Err("wildcard or non-ASCII DNS hostnames are not permitted for leaf minting".to_string());
    }
    for label in norm.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("invalid DNS label in target host".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("invalid DNS label hyphen placement".to_string());
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return Err("target host contains invalid DNS characters".to_string());
        }
    }
    Ok(norm)
}

fn atomic_write_text_file(path: &Path, text: &str) -> Result<(), String> {
    let dir = path
        .parent()
        .ok_or_else(|| format!("missing parent directory for {}", path.display()))?;
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file.tmp");
    let tmp_path = dir.join(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4().simple()));
    let write_res: Result<(), String> = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .map_err(|e| format!("failed to create {}: {e}", tmp_path.display()))?;
        f.write_all(text.as_bytes())
            .map_err(|e| format!("failed to write {}: {e}", tmp_path.display()))?;
        f.sync_all()
            .map_err(|e| format!("failed to sync {}: {e}", tmp_path.display()))?;
        drop(f);
        std::fs::rename(&tmp_path, path).map_err(|e| format!("failed to replace {}: {e}", path.display()))?;
        Ok(())
    })();
    if write_res.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_res
}

fn encode_pem(label: &str, der: &[u8]) -> String {
    let encoded = B64.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn decode_pem(pem: &str, expected_label: &str) -> Result<Vec<u8>, String> {
    let begin = format!("-----BEGIN {expected_label}-----");
    let end = format!("-----END {expected_label}-----");
    let start_idx = pem.find(&begin).ok_or_else(|| format!("missing PEM header {begin}"))? + begin.len();
    let rest = &pem[start_idx..];
    let end_idx = rest.find(&end).ok_or_else(|| format!("missing PEM footer {end}"))?;
    let body: String = rest[..end_idx].chars().filter(|c| !c.is_whitespace()).collect();
    B64.decode(body)
        .map_err(|e| format!("invalid PEM base64 for {expected_label}: {e}"))
}

fn sha1_hex(data: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data);
    d.as_ref().iter().map(|b| format!("{b:02X}")).collect()
}

fn sha256_colon_hex(data: &[u8]) -> String {
    let d = Sha256::digest(data);
    d.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

fn random_serial(rng: &SystemRandom) -> Result<Vec<u8>, String> {
    let mut buf = [0u8; 16];
    ring::rand::SecureRandom::fill(rng, &mut buf).map_err(|_| "RNG failure".to_string())?;
    buf[0] &= 0x7F;
    if buf[0] == 0 {
        buf[0] = 0x01;
    }
    Ok(buf.to_vec())
}

fn compute_ski(spki_der: &[u8]) -> [u8; 20] {
    let d = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, spki_der);
    let mut out = [0u8; 20];
    out.copy_from_slice(d.as_ref());
    out
}

// ===== Minimal RFC 5280 ASN.1 DER X.509 v3 Encoder =====

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 4 + content.len());
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else if len <= 0xFF_FFFF {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x84);
        out.push((len >> 24) as u8);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
    out.extend_from_slice(content);
    out
}

fn der_sequence(parts: &[&[u8]]) -> Vec<u8> {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let mut inner = Vec::with_capacity(total);
    for p in parts {
        inner.extend_from_slice(p);
    }
    der_tlv(0x30, &inner)
}

fn der_set(parts: &[&[u8]]) -> Vec<u8> {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let mut inner = Vec::with_capacity(total);
    for p in parts {
        inner.extend_from_slice(p);
    }
    der_tlv(0x31, &inner)
}

fn der_integer_u8(v: u8) -> Vec<u8> {
    der_tlv(0x02, &[v])
}

fn der_integer_unsigned_bytes(bytes: &[u8]) -> Vec<u8> {
    let trimmed = bytes.iter().position(|&b| b != 0).map(|i| &bytes[i..]).unwrap_or(&[0]);
    if trimmed[0] & 0x80 != 0 {
        let mut prefixed = Vec::with_capacity(trimmed.len() + 1);
        prefixed.push(0x00);
        prefixed.extend_from_slice(trimmed);
        der_tlv(0x02, &prefixed)
    } else {
        der_tlv(0x02, trimmed)
    }
}

fn der_bit_string(unused_bits: u8, data: &[u8]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(1 + data.len());
    inner.push(unused_bits);
    inner.extend_from_slice(data);
    der_tlv(0x03, &inner)
}

fn der_octet_string(data: &[u8]) -> Vec<u8> {
    der_tlv(0x04, data)
}

fn der_boolean(val: bool) -> Vec<u8> {
    der_tlv(0x01, &[if val { 0xFF } else { 0x00 }])
}

fn der_utf8_string(s: &str) -> Vec<u8> {
    der_tlv(0x0C, s.as_bytes())
}

fn der_oid(arcs: &[u32]) -> Vec<u8> {
    let mut body = Vec::new();
    if arcs.len() >= 2 {
        body.push((arcs[0] * 40 + arcs[1]) as u8);
        for &arc in &arcs[2..] {
            encode_base128(arc, &mut body);
        }
    }
    der_tlv(0x06, &body)
}

fn encode_base128(mut v: u32, out: &mut Vec<u8>) {
    let mut buf = [0u8; 5];
    let mut idx = buf.len();
    buf[idx - 1] = (v & 0x7F) as u8;
    idx -= 1;
    v >>= 7;
    while v > 0 {
        idx -= 1;
        buf[idx] = ((v & 0x7F) as u8) | 0x80;
        v >>= 7;
    }
    out.extend_from_slice(&buf[idx..]);
}

fn der_explicit(tag_num: u8, inner: &[u8]) -> Vec<u8> {
    der_tlv(0xA0 | (tag_num & 0x1F), inner)
}

fn der_x509_time(dt: DateTime<Utc>) -> Vec<u8> {
    let year = dt.year();
    if (1950..=2049).contains(&year) {
        let s = format!(
            "{:02}{:02}{:02}{:02}{:02}{:02}Z",
            year.rem_euclid(100),
            dt.month(),
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        );
        der_tlv(0x17, s.as_bytes())
    } else {
        let s = format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}Z",
            year,
            dt.month(),
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        );
        der_tlv(0x18, s.as_bytes())
    }
}

struct ParsedCertTbs {
    not_after: DateTime<Utc>,
    subject_der: Vec<u8>,
    spki_der: Vec<u8>,
}

type DerTlv<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

fn read_der_tlv(input: &[u8]) -> Result<DerTlv<'_>, String> {
    if input.len() < 2 {
        return Err("truncated DER TLV".to_string());
    }
    let tag = input[0];
    let len_byte = input[1];
    let (header_len, len) = if len_byte < 0x80 {
        (2usize, len_byte as usize)
    } else {
        let num_octets = (len_byte & 0x7F) as usize;
        if num_octets == 0 || num_octets > 4 || input.len() < 2 + num_octets {
            return Err("invalid DER length".to_string());
        }
        let mut len = 0usize;
        for &b in &input[2..2 + num_octets] {
            len = (len << 8) | (b as usize);
        }
        (2 + num_octets, len)
    };
    let end = header_len
        .checked_add(len)
        .filter(|&e| e <= input.len())
        .ok_or_else(|| "DER length exceeds buffer".to_string())?;
    Ok((tag, &input[..end], &input[header_len..end], &input[end..]))
}

fn parse_der_x509_time(tag: u8, bytes: &[u8]) -> Result<DateTime<Utc>, String> {
    let s = std::str::from_utf8(bytes).map_err(|_| "non-UTF8 X.509 time".to_string())?;
    let s = s
        .strip_suffix('Z')
        .ok_or_else(|| "X.509 time missing Z suffix".to_string())?;
    let (year, rest) = match tag {
        0x17 => {
            if s.len() != 12 {
                return Err("invalid UTCTime length".to_string());
            }
            let yy: i32 = s[..2].parse().map_err(|_| "invalid UTCTime year".to_string())?;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            (year, &s[2..])
        }
        0x18 => {
            if s.len() != 14 {
                return Err("invalid GeneralizedTime length".to_string());
            }
            let yyyy: i32 = s[..4].parse().map_err(|_| "invalid GeneralizedTime year".to_string())?;
            (yyyy, &s[4..])
        }
        _ => return Err("unexpected X.509 time tag".to_string()),
    };
    let month: u32 = rest[0..2].parse().map_err(|_| "invalid month".to_string())?;
    let day: u32 = rest[2..4].parse().map_err(|_| "invalid day".to_string())?;
    let hour: u32 = rest[4..6].parse().map_err(|_| "invalid hour".to_string())?;
    let min: u32 = rest[6..8].parse().map_err(|_| "invalid minute".to_string())?;
    let sec: u32 = rest[8..10].parse().map_err(|_| "invalid second".to_string())?;
    let date = NaiveDate::from_ymd_opt(year, month, day).ok_or_else(|| "invalid X.509 date".to_string())?;
    let dt = NaiveDateTime::new(
        date,
        chrono::NaiveTime::from_hms_opt(hour, min, sec).ok_or_else(|| "invalid X.509 hms".to_string())?,
    );
    Ok(Utc.from_utc_datetime(&dt))
}

fn parse_x509_tbs(cert_der: &[u8]) -> Result<ParsedCertTbs, String> {
    let (tag, _, cert_inner, trailing) = read_der_tlv(cert_der)?;
    if tag != 0x30 || !trailing.is_empty() {
        return Err("invalid X.509 Certificate outer SEQUENCE".to_string());
    }
    let (tbs_tag, _, mut tbs_inner, _) = read_der_tlv(cert_inner)?;
    if tbs_tag != 0x30 {
        return Err("invalid X.509 TBSCertificate SEQUENCE".to_string());
    }
    // Optional explicit [0] version
    if tbs_inner.first().copied() == Some(0xA0) {
        let (_, _, _, rest) = read_der_tlv(tbs_inner)?;
        tbs_inner = rest;
    }
    // serialNumber (0x02)
    let (t, _, _, rest) = read_der_tlv(tbs_inner)?;
    if t != 0x02 {
        return Err("missing X.509 serialNumber".to_string());
    }
    // signature (0x30)
    let (t, _, _, rest) = read_der_tlv(rest)?;
    if t != 0x30 {
        return Err("missing X.509 signature algorithm".to_string());
    }
    // issuer (0x30)
    let (t, _, _, rest) = read_der_tlv(rest)?;
    if t != 0x30 {
        return Err("missing X.509 issuer".to_string());
    }
    // validity (0x30)
    let (t, _, validity_inner, rest) = read_der_tlv(rest)?;
    if t != 0x30 {
        return Err("missing X.509 validity".to_string());
    }
    let (nb_tag, _, nb_bytes, val_rest) = read_der_tlv(validity_inner)?;
    let _not_before = parse_der_x509_time(nb_tag, nb_bytes)?;
    let (na_tag, _, na_bytes, val_trailing) = read_der_tlv(val_rest)?;
    if !val_trailing.is_empty() {
        return Err("unexpected trailing bytes in X.509 validity".to_string());
    }
    let not_after = parse_der_x509_time(na_tag, na_bytes)?;
    // subject (0x30)
    let (t, subject_tlv, _, rest) = read_der_tlv(rest)?;
    if t != 0x30 {
        return Err("missing X.509 subject".to_string());
    }
    // subjectPublicKeyInfo (0x30)
    let (t, spki_tlv, _, _) = read_der_tlv(rest)?;
    if t != 0x30 {
        return Err("missing X.509 subjectPublicKeyInfo".to_string());
    }
    Ok(ParsedCertTbs {
        not_after,
        subject_der: subject_tlv.to_vec(),
        spki_der: spki_tlv.to_vec(),
    })
}

fn build_name_der(common_name: &str, org: Option<&str>) -> Vec<u8> {
    let mut rdns: Vec<Vec<u8>> = Vec::new();
    if let Some(o) = org {
        // OID 2.5.4.10 organizationName
        let oid = der_oid(&[2, 5, 4, 10]);
        let val = der_utf8_string(o);
        let atv = der_sequence(&[&oid, &val]);
        rdns.push(der_set(&[&atv]));
    }
    // OID 2.5.4.3 commonName
    let oid = der_oid(&[2, 5, 4, 3]);
    let val = der_utf8_string(common_name);
    let atv = der_sequence(&[&oid, &val]);
    rdns.push(der_set(&[&atv]));

    let refs: Vec<&[u8]> = rdns.iter().map(Vec::as_slice).collect();
    der_sequence(&refs)
}

fn build_ec_p256_spki(pub_key_uncompressed: &[u8]) -> Vec<u8> {
    // 1.2.840.10045.2.1 (id-ecPublicKey), 1.2.840.10045.3.1.7 (prime256v1)
    let ec_oid = der_oid(&[1, 2, 840, 10045, 2, 1]);
    let p256_oid = der_oid(&[1, 2, 840, 10045, 3, 1, 7]);
    let alg = der_sequence(&[&ec_oid, &p256_oid]);
    let bits = der_bit_string(0, pub_key_uncompressed);
    der_sequence(&[&alg, &bits])
}

fn build_ecdsa_sha256_alg() -> Vec<u8> {
    // 1.2.840.10045.4.3.2 (ecdsa-with-SHA256)
    let oid = der_oid(&[1, 2, 840, 10045, 4, 3, 2]);
    der_sequence(&[&oid])
}

fn der_extension(oid_arcs: &[u32], critical: bool, value_der: &[u8]) -> Vec<u8> {
    let oid = der_oid(oid_arcs);
    let octets = der_octet_string(value_der);
    if critical {
        let crit = der_boolean(true);
        der_sequence(&[&oid, &crit, &octets])
    } else {
        der_sequence(&[&oid, &octets])
    }
}

fn ext_basic_constraints_ca() -> Vec<u8> {
    let is_ca = der_boolean(true);
    let inner = der_sequence(&[&is_ca]);
    der_extension(&[2, 5, 29, 19], true, &inner)
}

fn ext_basic_constraints_leaf() -> Vec<u8> {
    let inner = der_sequence(&[]);
    der_extension(&[2, 5, 29, 19], true, &inner)
}

fn ext_key_usage_ca() -> Vec<u8> {
    // keyCertSign (bit 5 = 0x04) | cRLSign (bit 6 = 0x02) -> 0x06, 1 unused trailing bit
    let bits = der_bit_string(1, &[0x06]);
    der_extension(&[2, 5, 29, 15], true, &bits)
}

fn ext_key_usage_leaf() -> Vec<u8> {
    // digitalSignature (bit 0 = 0x80) | keyEncipherment (bit 2 = 0x20) -> 0xA0, 5 unused trailing bits
    let bits = der_bit_string(5, &[0xA0]);
    der_extension(&[2, 5, 29, 15], true, &bits)
}

fn ext_eku_server_auth() -> Vec<u8> {
    // id-kp-serverAuth: 1.3.6.1.5.5.7.3.1
    let oid = der_oid(&[1, 3, 6, 1, 5, 5, 7, 3, 1]);
    let seq = der_sequence(&[&oid]);
    der_extension(&[2, 5, 29, 37], false, &seq)
}

fn ext_subject_key_identifier(ski: &[u8; 20]) -> Vec<u8> {
    let oct = der_octet_string(ski);
    der_extension(&[2, 5, 29, 14], false, &oct)
}

fn ext_authority_key_identifier(aki: &[u8; 20]) -> Vec<u8> {
    // [0] IMPLICIT KeyIdentifier
    let key_id = der_tlv(0x80, aki);
    let seq = der_sequence(&[&key_id]);
    der_extension(&[2, 5, 29, 35], false, &seq)
}

fn ext_san_host(host: &str) -> Vec<u8> {
    let gn = match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => der_tlv(0x87, &v4.octets()),
        Ok(IpAddr::V6(v6)) => der_tlv(0x87, &v6.octets()),
        Err(_) => der_tlv(0x82, host.as_bytes()),
    };
    let seq = der_sequence(&[&gn]);
    der_extension(&[2, 5, 29, 17], false, &seq)
}

#[allow(clippy::too_many_arguments)]
fn build_signed_x509(
    serial: &[u8],
    issuer_der: &[u8],
    subject_der: &[u8],
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    spki_der: &[u8],
    extensions: &[Vec<u8>],
    signing_key: &EcdsaKeyPair,
    rng: &SystemRandom,
) -> Result<Vec<u8>, String> {
    let version = der_explicit(0, &der_integer_u8(2));
    let serial_der = der_integer_unsigned_bytes(serial);
    let sig_alg = build_ecdsa_sha256_alg();
    let nb = der_x509_time(not_before);
    let na = der_x509_time(not_after);
    let validity = der_sequence(&[&nb, &na]);

    let ext_refs: Vec<&[u8]> = extensions.iter().map(Vec::as_slice).collect();
    let ext_seq = der_sequence(&ext_refs);
    let ext_explicit = der_explicit(3, &ext_seq);

    let tbs = der_sequence(&[
        &version,
        &serial_der,
        &sig_alg,
        issuer_der,
        &validity,
        subject_der,
        spki_der,
        &ext_explicit,
    ]);

    let sig = signing_key
        .sign(rng, &tbs)
        .map_err(|_| "ECDSA signing failed".to_string())?;
    let sig_bits = der_bit_string(0, sig.as_ref());
    Ok(der_sequence(&[&tbs, &sig_alg, &sig_bits]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("hide-go-ca-test-{}", uuid::Uuid::new_v4().simple()));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn ca_persists_reloads_and_tracks_mock_trust() {
        let tmp = TempDir::new();
        let adapter = Arc::new(MockCaTrustAdapter::with_system_roots(
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        ));

        let mgr1 = CaManager::load_or_create(tmp.0.clone(), adapter.clone()).unwrap();
        let st1 = mgr1.status();
        assert!(st1.ready);
        assert!(!st1.installed_in_os_store);
        assert!(Path::new(&st1.ca_cert_path).is_file());
        assert!(Path::new(&st1.ca_bundle_path).is_file());
        let bundle = std::fs::read_to_string(&st1.ca_bundle_path).unwrap();
        assert!(bundle.contains("AAAA"));
        assert!(bundle.contains(mgr1.ca_cert_pem().trim()));

        // Reload from disk preserves exact same Root CA fingerprint
        let mgr2 = CaManager::load_or_create(tmp.0.clone(), adapter.clone()).unwrap();
        assert_eq!(mgr2.status().fingerprint_sha256, st1.fingerprint_sha256);
        assert_eq!(mgr2.status().fingerprint_sha1, st1.fingerprint_sha1);

        // Trust / untrust via mock adapter
        let trusted = mgr2.install_trust().unwrap();
        assert!(trusted.installed_in_os_store);
        let untrusted = mgr2.remove_trust().unwrap();
        assert!(!untrusted.installed_in_os_store);
    }

    #[tokio::test]
    async fn minted_leaf_cert_completes_real_rustls_handshake_for_dns_and_ip() {
        let mgr = CaManager::ephemeral(Arc::new(MockCaTrustAdapter::new())).unwrap();

        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(CertificateDer::from(mgr.ca_cert_der().to_vec()))
            .unwrap();
        let client_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        );

        for (host, sni_str) in [("api.openai.com", "api.openai.com"), ("127.0.0.1", "127.0.0.1")] {
            let server_cfg = mgr.server_config_for_host(host).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let acceptor = TlsAcceptor::from(server_cfg);
            let server_task = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut tls = acceptor.accept(tcp).await.unwrap();
                let mut buf = [0u8; 4];
                tls.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"ping");
                tls.write_all(b"pong").await.unwrap();
                tls.shutdown().await.unwrap();
            });

            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let connector = TlsConnector::from(client_cfg.clone());
            let server_name = rustls::pki_types::ServerName::try_from(sni_str.to_string()).unwrap();
            let mut tls = connector.connect(server_name, tcp).await.unwrap();
            tls.write_all(b"ping").await.unwrap();
            let mut resp = [0u8; 4];
            tls.read_exact(&mut resp).await.unwrap();
            assert_eq!(&resp, b"pong");
            server_task.await.unwrap();
        }
    }

    #[test]
    fn ca_rejects_wildcard_and_invalid_leaf_hosts_and_refuses_corrupt_overwrite() {
        let tmp = TempDir::new();
        let adapter = Arc::new(MockCaTrustAdapter::new());
        let mgr = CaManager::load_or_create(tmp.0.clone(), adapter.clone()).unwrap();
        let original_not_after = mgr.status().not_after;

        // Reload parses exact not_after from DER instead of fabricating now+3650d
        let reloaded = CaManager::load_or_create(tmp.0.clone(), adapter.clone()).unwrap();
        assert_eq!(reloaded.status().not_after, original_not_after);

        for bad in ["", "*.qoder.sh", "bad host", "evil\0.com", "café.com", "-bad.com"] {
            assert!(
                mgr.server_config_for_host(bad).is_err(),
                "expected rejection for {bad:?}"
            );
        }

        // Replace cert with a different CA's cert -> load_or_create must fail without overwriting key
        let other = CaManager::ephemeral(adapter.clone()).unwrap();
        let orig_key = std::fs::read_to_string(tmp.0.join(CA_KEY_FILENAME)).unwrap();
        std::fs::write(tmp.0.join(CA_CERT_FILENAME), other.ca_cert_pem()).unwrap();
        assert!(CaManager::load_or_create(tmp.0.clone(), adapter).is_err());
        assert_eq!(std::fs::read_to_string(tmp.0.join(CA_KEY_FILENAME)).unwrap(), orig_key);
    }

    #[test]
    fn run_command_with_timeout_handles_large_stdout_without_pipe_deadlock() {
        #[cfg(windows)]
        let cmd = {
            let mut c = hidden_system_command(r"WindowsPowerShell\v1.0\powershell.exe");
            c.args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[Console]::Write('A' * 300000)",
            ]);
            c
        };
        #[cfg(not(windows))]
        let cmd = {
            let mut c = Command::new("sh");
            c.args(["-c", "head -c 300000 /dev/zero | tr '\\0' 'A'"]);
            c
        };
        let out = run_command_with_timeout(cmd, Duration::from_secs(10)).unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout.len(), 300_000);
    }
}
