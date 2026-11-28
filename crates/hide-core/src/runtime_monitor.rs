//! Local process-tree inspection, TCP socket-to-PID attribution, companion discovery,
//! and restart detection for running AI coding harnesses.
//!
//! Uses native OS APIs (`CreateToolhelp32Snapshot` + `GetExtendedTcpTable` on Windows,
//! `/proc` on Linux) with short-lived caching so hot-path proxy attribution runs in
//! sub-millisecond time without spawning shell subprocesses.

use crate::config::HarnessKind;
use crate::harness::HarnessProfile;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PROCESS_CACHE_TTL: Duration = Duration::from_secs(4);
const TCP_OWNER_CACHE_TTL: Duration = Duration::from_secs(30);
const MAX_TCP_OWNER_CACHE: usize = 512;

/// Snapshot of a single running OS process.
#[derive(Debug, Clone)]
pub struct ProcessEntry {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe_path: Option<String>,
    /// Unix epoch seconds when the process started, if available from the OS.
    pub started_epoch_secs: Option<u64>,
}

/// Resolved local client process behind an incoming proxy TCP connection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClientAttribution {
    pub pid: u32,
    pub process_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<HarnessKind>,
    pub is_companion: bool,
}

impl ClientAttribution {
    /// Concise display label stored on audit records (e.g. `"node.exe (via Pi)"`).
    pub fn display_label(&self) -> String {
        match (self.is_companion, self.harness) {
            (true, Some(h)) => format!("{} (via {})", self.process_name, h.display_name()),
            _ => self.process_name.clone(),
        }
    }
}

/// Companion or child process running alongside a detected AI harness.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompanionProcessInfo {
    pub pid: u32,
    pub name: String,
    /// `"child"` (descendant in process tree) or `"sibling"` (same install directory).
    pub relation: String,
}

/// Live runtime status for a harness that is currently executing on this machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RunningHarnessNotice {
    pub kind: HarnessKind,
    pub running_pids: Vec<u32>,
    pub primary_process: String,
    pub started_before_gateway: bool,
    pub configured: bool,
    pub has_live_traffic: bool,
    pub needs_restart: bool,
    #[serde(default)]
    pub companions: Vec<CompanionProcessInfo>,
}

/// Listening local TCP loopback endpoint owned by another local process.
#[derive(Debug, Clone)]
pub struct LocalListener {
    pub port: u16,
    pub pid: u32,
}

/// Cached process-tree snapshot with fast PID lookup and parent/child traversal.
#[derive(Debug, Clone, Default)]
pub struct ProcessSnapshot {
    pub by_pid: HashMap<u32, ProcessEntry>,
    pub children: HashMap<u32, Vec<u32>>,
}

impl ProcessSnapshot {
    pub fn from_entries(entries: Vec<ProcessEntry>) -> Self {
        let mut by_pid = HashMap::with_capacity(entries.len());
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        for e in entries {
            if e.ppid != 0 && e.ppid != e.pid {
                children.entry(e.ppid).or_default().push(e.pid);
            }
            by_pid.insert(e.pid, e);
        }
        Self { by_pid, children }
    }

    /// Walk up the parent chain from `pid` (bounded depth to guard against PID reuse cycles).
    pub fn ancestors(&self, pid: u32) -> Vec<&ProcessEntry> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut cur = pid;
        for _ in 0..16 {
            let Some(entry) = self.by_pid.get(&cur) else {
                break;
            };
            if !seen.insert(cur) {
                break;
            }
            out.push(entry);
            if entry.ppid == 0 || entry.ppid == cur {
                break;
            }
            cur = entry.ppid;
        }
        out
    }

    /// Collect all descendant PIDs below `root_pid` (breadth-first, cycle-safe).
    pub fn descendants(&self, root_pid: u32) -> Vec<&ProcessEntry> {
        let mut out = Vec::new();
        let mut visited = HashSet::new();
        visited.insert(root_pid);
        let mut queue = VecDeque::new();
        queue.push_back(root_pid);
        while let Some(pid) = queue.pop_front() {
            if let Some(kids) = self.children.get(&pid) {
                for &kid in kids {
                    if visited.insert(kid) {
                        if let Some(entry) = self.by_pid.get(&kid) {
                            out.push(entry);
                        }
                        queue.push_back(kid);
                    }
                }
            }
            if out.len() >= 64 {
                break;
            }
        }
        out
    }
}

type PeerAttributionCache = HashMap<(u16, u16), (Instant, Option<ClientAttribution>)>;

/// Shared runtime monitor cached inside `GatewayState`.
pub struct RuntimeMonitor {
    gateway_started_epoch: u64,
    connect_epochs: RwLock<HashMap<HarnessKind, u64>>,
    proc_cache: RwLock<Option<(Instant, ProcessSnapshot)>>,
    profile_cache: RwLock<Option<(Instant, Vec<HarnessProfile>)>>,
    peer_cache: RwLock<PeerAttributionCache>,
}

impl Default for RuntimeMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeMonitor {
    pub fn new() -> Self {
        Self {
            gateway_started_epoch: now_epoch_secs(),
            connect_epochs: RwLock::new(HashMap::new()),
            proc_cache: RwLock::new(None),
            profile_cache: RwLock::new(None),
            peer_cache: RwLock::new(HashMap::new()),
        }
    }

    pub fn update_cached_profiles(&self, profiles: Vec<HarnessProfile>) {
        *self.profile_cache.write() = Some((Instant::now(), profiles));
    }

    pub fn cached_profiles_or_static(&self, proxy_port: u16) -> Vec<HarnessProfile> {
        if let Some((at, profiles)) = self.profile_cache.read().as_ref() {
            if at.elapsed() < Duration::from_secs(60) {
                return profiles.clone();
            }
        }
        crate::harness::get_all_harness_profiles(proxy_port)
    }

    pub fn gateway_started_epoch(&self) -> u64 {
        self.gateway_started_epoch
    }

    /// Record when a harness was just connected via Hide-Go so already-running processes
    /// started before that instant are flagged as needing a restart until live traffic arrives.
    pub fn mark_harness_connected(&self, kind: HarnessKind) {
        self.connect_epochs.write().insert(kind, now_epoch_secs());
    }

    pub fn snapshot(&self) -> ProcessSnapshot {
        if let Some((at, snap)) = self.proc_cache.read().as_ref() {
            if at.elapsed() < PROCESS_CACHE_TTL {
                return snap.clone();
            }
        }
        let fresh = capture_os_process_snapshot();
        *self.proc_cache.write() = Some((Instant::now(), fresh.clone()));
        fresh
    }

    /// Attribute an incoming loopback proxy connection (`peer_addr -> server_port`) to its
    /// originating local process and (via process tree / install dir affinity) parent harness.
    pub fn attribute_connection(
        &self,
        peer_addr: Option<SocketAddr>,
        server_port: u16,
        profiles: &[HarnessProfile],
    ) -> Option<ClientAttribution> {
        let addr = peer_addr?;
        if !addr.ip().is_loopback() || server_port == 0 {
            return None;
        }
        let key = (addr.port(), server_port);
        if let Some((at, cached)) = self.peer_cache.read().get(&key) {
            if at.elapsed() < TCP_OWNER_CACHE_TTL {
                return cached.clone();
            }
        }
        let pid = lookup_local_tcp_owner_pid(addr, server_port);
        let attr = pid.and_then(|p| {
            let snap = self.snapshot();
            resolve_pid_attribution(&snap, p, profiles)
        });
        let mut cache = self.peer_cache.write();
        if cache.len() >= MAX_TCP_OWNER_CACHE {
            cache.retain(|_, (at, _)| at.elapsed() < TCP_OWNER_CACHE_TTL);
            if cache.len() >= MAX_TCP_OWNER_CACHE {
                cache.clear();
            }
        }
        cache.insert(key, (Instant::now(), attr.clone()));
        attr
    }

    /// Inspect all running harnesses, their companion/child processes, and restart reminders.
    pub fn inspect_running_harnesses(&self, profiles: &[HarnessProfile]) -> Vec<RunningHarnessNotice> {
        let snap = self.snapshot();
        let connect_epochs = self.connect_epochs.read().clone();
        evaluate_running_harnesses(&snap, profiles, self.gateway_started_epoch, &connect_epochs)
    }
}

pub fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn normalized_stem(name: &str) -> String {
    let lower = name.trim().to_ascii_lowercase();
    lower
        .strip_suffix(".exe")
        .or_else(|| lower.strip_suffix(".cmd"))
        .or_else(|| lower.strip_suffix(".bat"))
        .unwrap_or(&lower)
        .to_string()
}

fn normalized_path_lower(p: &str) -> String {
    p.trim().replace('\\', "/").to_ascii_lowercase()
}

/// Match a single process to a `HarnessKind` using binary stem and install-directory affinity.
pub fn match_process_harness(entry: &ProcessEntry, profiles: &[HarnessProfile]) -> Option<HarnessKind> {
    let stem = normalized_stem(&entry.name);
    let exe_norm = entry.exe_path.as_deref().map(normalized_path_lower);

    // 1. Direct executable-name / install-root affinity against discovered harness paths.
    for profile in profiles {
        if let Some(ref exe) = exe_norm {
            for install_path in &profile.install_paths {
                let ip = normalized_path_lower(install_path);
                if ip.is_empty() {
                    continue;
                }
                // Match either exact binary or an executable living inside the app's install tree
                // (ignoring generic shared directories like `~/.config` or `.../npm`).
                if *exe == ip {
                    return Some(profile.kind);
                }
                if !ip.ends_with("/npm")
                    && !ip.ends_with("/.local/bin")
                    && !ip.ends_with(".json")
                    && !ip.ends_with(".toml")
                    && !ip.ends_with(".cmd")
                {
                    let dir_prefix = if ip.ends_with('/') { ip } else { format!("{ip}/") };
                    if exe.starts_with(&dir_prefix) {
                        return Some(profile.kind);
                    }
                }
            }
        }
    }

    // 2. Canonical binary stem matching for CLI / desktop harnesses.
    match stem.as_str() {
        "claude" | "claude-code" => Some(HarnessKind::ClaudeCode),
        "codex" => Some(HarnessKind::Codex),
        "antigravity" | "agy" => Some(HarnessKind::Antigravity),
        "zcode" => Some(HarnessKind::Zcode),
        "qoder" | "qodercn" => Some(HarnessKind::Qoder),
        "cursor" => Some(HarnessKind::Cursor),
        "grok" | "grok-build" | "grok bot" => Some(HarnessKind::GrokBuild),
        "pi" => Some(HarnessKind::Pi),
        _ => {
            // Check path components for bundled helpers (e.g. `.../antigravity/.../language_server...`)
            if let Some(ref exe) = exe_norm {
                if exe.contains("/antigravity/") || exe.contains("/.gemini/antigravity/") {
                    return Some(HarnessKind::Antigravity);
                }
                if exe.contains("/cursor/") {
                    return Some(HarnessKind::Cursor);
                }
                if exe.contains("/qoder/") || exe.contains("/qodercn/") {
                    return Some(HarnessKind::Qoder);
                }
                if exe.contains("/zcode/") {
                    return Some(HarnessKind::Zcode);
                }
                if exe.contains("/@earendil-works/pi-coding-agent/") || exe.contains("/.pi/agent/") {
                    return Some(HarnessKind::Pi);
                }
            }
            None
        }
    }
}

fn is_primary_harness_binary(kind: HarnessKind, stem: &str) -> bool {
    match kind {
        HarnessKind::ClaudeCode => matches!(stem, "claude" | "claude-code"),
        HarnessKind::Codex => stem == "codex",
        HarnessKind::Antigravity => matches!(stem, "antigravity" | "agy"),
        HarnessKind::Zcode => stem == "zcode",
        HarnessKind::Qoder => matches!(stem, "qoder" | "qodercn"),
        HarnessKind::Cursor => stem == "cursor",
        HarnessKind::GrokBuild => matches!(stem, "grok" | "grok-build" | "grok bot"),
        HarnessKind::Pi => stem == "pi",
        HarnessKind::Generic => false,
    }
}

/// Resolve a local PID to its `ClientAttribution`, walking ancestors to attribute child/companion
/// processes (MCP servers, language servers, crash handlers, shell helpers) back to their harness.
pub fn resolve_pid_attribution(
    snap: &ProcessSnapshot,
    pid: u32,
    profiles: &[HarnessProfile],
) -> Option<ClientAttribution> {
    let entry = snap.by_pid.get(&pid)?;
    let self_stem = normalized_stem(&entry.name);
    if let Some(kind) = match_process_harness(entry, profiles) {
        let is_companion = !is_primary_harness_binary(kind, &self_stem);
        return Some(ClientAttribution {
            pid,
            process_name: entry.name.clone(),
            exe_path: entry.exe_path.clone(),
            harness: Some(kind),
            is_companion,
        });
    }
    for ancestor in snap.ancestors(pid).into_iter().skip(1) {
        if let Some(kind) = match_process_harness(ancestor, profiles) {
            return Some(ClientAttribution {
                pid,
                process_name: entry.name.clone(),
                exe_path: entry.exe_path.clone(),
                harness: Some(kind),
                is_companion: true,
            });
        }
    }
    Some(ClientAttribution {
        pid,
        process_name: entry.name.clone(),
        exe_path: entry.exe_path.clone(),
        harness: None,
        is_companion: false,
    })
}

fn exe_install_dir(exe: &str) -> Option<String> {
    let parent = Path::new(exe).parent()?;
    let norm = normalized_path_lower(&parent.to_string_lossy());
    if norm.len() < 8
        || norm.ends_with("/system32")
        || norm.ends_with("/bin")
        || norm.ends_with("/usr/bin")
        || norm.ends_with("/npm")
    {
        return None;
    }
    Some(norm)
}

/// Evaluate all running harnesses, their companion/child processes, and whether a restart
/// reminder should be shown because the process predates Hide-Go/connect with zero live traffic.
pub fn evaluate_running_harnesses(
    snap: &ProcessSnapshot,
    profiles: &[HarnessProfile],
    gateway_started_epoch: u64,
    connect_epochs: &HashMap<HarnessKind, u64>,
) -> Vec<RunningHarnessNotice> {
    let own_pid = std::process::id();
    let mut grouped: HashMap<HarnessKind, Vec<&ProcessEntry>> = HashMap::new();
    for entry in snap.by_pid.values() {
        if entry.pid == own_pid {
            continue;
        }
        let stem = normalized_stem(&entry.name);
        if stem.starts_with("hide-go") {
            continue;
        }
        if let Some(kind) = match_process_harness(entry, profiles) {
            grouped.entry(kind).or_default().push(entry);
        }
    }

    let mut out = Vec::new();
    for profile in profiles {
        let Some(entries) = grouped.get(&profile.kind) else {
            continue;
        };
        if entries.is_empty() {
            continue;
        }
        let primary_entries: Vec<&ProcessEntry> = entries
            .iter()
            .copied()
            .filter(|e| is_primary_harness_binary(profile.kind, &normalized_stem(&e.name)))
            .collect();
        let roots = if primary_entries.is_empty() {
            entries.as_slice()
        } else {
            primary_entries.as_slice()
        };

        let mut running_pids: Vec<u32> = roots.iter().map(|e| e.pid).collect();
        running_pids.sort_unstable();
        let primary_process = roots.first().map(|e| e.name.clone()).unwrap_or_default();

        let reference_epoch = connect_epochs
            .get(&profile.kind)
            .copied()
            .unwrap_or(gateway_started_epoch)
            .max(gateway_started_epoch);

        let started_before_gateway = roots
            .iter()
            .any(|e| e.started_epoch_secs.is_some_and(|s| s + 2 < reference_epoch));

        // Discover child + sibling companion processes running alongside this harness.
        let root_pid_set: HashSet<u32> = running_pids.iter().copied().collect();
        let root_dirs: HashSet<String> = roots
            .iter()
            .filter_map(|e| e.exe_path.as_deref().and_then(exe_install_dir))
            .collect();
        let mut seen_comp: HashSet<u32> = root_pid_set.clone();
        let mut companions: Vec<CompanionProcessInfo> = Vec::new();

        for &root_pid in &running_pids {
            for desc in snap.descendants(root_pid) {
                if desc.pid == own_pid || !seen_comp.insert(desc.pid) {
                    continue;
                }
                let stem = normalized_stem(&desc.name);
                if stem.starts_with("hide-go") || is_primary_harness_binary(profile.kind, &stem) {
                    continue;
                }
                companions.push(CompanionProcessInfo {
                    pid: desc.pid,
                    name: desc.name.clone(),
                    relation: "child".to_string(),
                });
            }
        }
        for entry in snap.by_pid.values() {
            if entry.pid == own_pid || !seen_comp.insert(entry.pid) {
                continue;
            }
            let stem = normalized_stem(&entry.name);
            if stem.starts_with("hide-go") || is_primary_harness_binary(profile.kind, &stem) {
                continue;
            }
            let same_dir = entry
                .exe_path
                .as_deref()
                .and_then(exe_install_dir)
                .is_some_and(|d| root_dirs.contains(&d));
            let same_harness_helper = !same_dir && match_process_harness(entry, profiles) == Some(profile.kind);
            if same_dir || same_harness_helper {
                companions.push(CompanionProcessInfo {
                    pid: entry.pid,
                    name: entry.name.clone(),
                    relation: "sibling".to_string(),
                });
            }
            if companions.len() >= 16 {
                break;
            }
        }
        companions.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.pid.cmp(&b.pid)));
        companions.truncate(12);

        let has_live_traffic = profile.traffic_count > 0;
        let needs_restart = profile.configured && !has_live_traffic && started_before_gateway;

        out.push(RunningHarnessNotice {
            kind: profile.kind,
            running_pids,
            primary_process,
            started_before_gateway,
            configured: profile.configured,
            has_live_traffic,
            needs_restart,
            companions,
        });
    }
    out
}

/// Enumerate local loopback TCP listeners (`127.0.0.1:<port>`) and their owning PIDs.
pub fn list_local_loopback_listeners() -> Vec<LocalListener> {
    #[cfg(windows)]
    {
        win32::list_loopback_tcp_listeners()
    }
    #[cfg(target_os = "linux")]
    {
        linux::list_loopback_tcp_listeners()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Vec::new()
    }
}

/// Look up the owning PID for an established loopback TCP connection `(peer_addr -> 127.0.0.1:server_port)`.
pub fn lookup_local_tcp_owner_pid(peer_addr: SocketAddr, server_port: u16) -> Option<u32> {
    #[cfg(windows)]
    {
        win32::lookup_tcp_owner_pid(peer_addr, server_port)
    }
    #[cfg(target_os = "linux")]
    {
        linux::lookup_tcp_owner_pid(peer_addr, server_port)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = (peer_addr, server_port);
        None
    }
}

fn capture_os_process_snapshot() -> ProcessSnapshot {
    #[cfg(windows)]
    {
        ProcessSnapshot::from_entries(win32::capture_processes())
    }
    #[cfg(target_os = "linux")]
    {
        ProcessSnapshot::from_entries(linux::capture_processes())
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        ProcessSnapshot::default()
    }
}

/// Terminate a verified user-owned local peer process cleanly (used only when the user
/// explicitly chooses "Stop conflicting proxy" inside the conflict resolution modal).
pub fn terminate_local_process(pid: u32) -> Result<(), String> {
    if pid <= 4 || pid == std::process::id() {
        return Err("refusing to terminate protected or self process".to_string());
    }
    #[cfg(windows)]
    {
        win32::terminate_pid(pid)
    }
    #[cfg(unix)]
    {
        let status = std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .map_err(|e| format!("failed to signal process {pid}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("process {pid} could not be terminated"))
        }
    }
}

#[cfg(windows)]
mod win32 {
    use super::{LocalListener, ProcessEntry, SocketAddr};
    use std::ffi::c_void;
    use std::net::IpAddr;

    const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
    const INVALID_HANDLE_VALUE: *mut c_void = (-1isize) as *mut c_void;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const PROCESS_TERMINATE: u32 = 0x0001;
    const MAX_PATH: usize = 260;

    const AF_INET: u32 = 2;
    const TCP_TABLE_OWNER_PID_LISTENER: u32 = 3;
    const TCP_TABLE_OWNER_PID_CONNECTIONS: u32 = 4;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const NO_ERROR: u32 = 0;

    #[repr(C)]
    struct PROCESSENTRY32W {
        dw_size: u32,
        cnt_usage: u32,
        th32_process_id: u32,
        th32_default_heap_id: usize,
        th32_module_id: u32,
        cnt_threads: u32,
        th32_parent_process_id: u32,
        pc_pri_class_base: i32,
        dw_flags: u32,
        sz_exe_file: [u16; MAX_PATH],
    }

    #[repr(C)]
    #[derive(Default)]
    #[allow(clippy::upper_case_acronyms)]
    struct FILETIME {
        dw_low_date_time: u32,
        dw_high_date_time: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct MibTcpRowOwnerPid {
        state: u32,
        local_addr: u32,
        local_port: u32,
        remote_addr: u32,
        remote_port: u32,
        owning_pid: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateToolhelp32Snapshot(dw_flags: u32, th32_process_id: u32) -> *mut c_void;
        fn Process32FirstW(h_snapshot: *mut c_void, lppe: *mut PROCESSENTRY32W) -> i32;
        fn Process32NextW(h_snapshot: *mut c_void, lppe: *mut PROCESSENTRY32W) -> i32;
        fn OpenProcess(dw_desired_access: u32, b_inherit_handle: i32, dw_process_id: u32) -> *mut c_void;
        fn QueryFullProcessImageNameW(
            h_process: *mut c_void,
            dw_flags: u32,
            lp_exe_name: *mut u16,
            lpdw_size: *mut u32,
        ) -> i32;
        fn GetProcessTimes(
            h_process: *mut c_void,
            lp_creation_time: *mut FILETIME,
            lp_exit_time: *mut FILETIME,
            lp_kernel_time: *mut FILETIME,
            lp_user_time: *mut FILETIME,
        ) -> i32;
        fn TerminateProcess(h_process: *mut c_void, u_exit_code: u32) -> i32;
        fn CloseHandle(h_object: *mut c_void) -> i32;
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetExtendedTcpTable(
            p_tcp_table: *mut c_void,
            pdw_size: *mut u32,
            b_order: i32,
            ul_af: u32,
            table_class: u32,
            reserved: u32,
        ) -> u32;
    }

    struct SafeHandle(*mut c_void);
    impl SafeHandle {
        fn new(raw: *mut c_void) -> Option<Self> {
            if raw.is_null() || raw == INVALID_HANDLE_VALUE {
                None
            } else {
                Some(Self(raw))
            }
        }
    }
    impl Drop for SafeHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    fn filetime_to_epoch_secs(ft: &FILETIME) -> Option<u64> {
        const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
        let ticks = ((ft.dw_high_date_time as u64) << 32) | (ft.dw_low_date_time as u64);
        ticks.checked_sub(WINDOWS_TO_UNIX_EPOCH_100NS).map(|d| d / 10_000_000)
    }

    fn query_process_meta(pid: u32) -> (Option<String>, Option<u64>) {
        let Some(handle) = SafeHandle::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) }) else {
            return (None, None);
        };
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let exe_path = if unsafe { QueryFullProcessImageNameW(handle.0, 0, buf.as_mut_ptr(), &mut len) } != 0
            && len > 0
            && (len as usize) <= buf.len()
        {
            Some(String::from_utf16_lossy(&buf[..len as usize]))
        } else {
            None
        };
        let mut created = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        let started = if unsafe { GetProcessTimes(handle.0, &mut created, &mut exit, &mut kernel, &mut user) } != 0 {
            filetime_to_epoch_secs(&created)
        } else {
            None
        };
        (exe_path, started)
    }

    pub fn capture_processes() -> Vec<ProcessEntry> {
        let Some(snap) = SafeHandle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
            return Vec::new();
        };
        let mut entry = PROCESSENTRY32W {
            dw_size: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            cnt_usage: 0,
            th32_process_id: 0,
            th32_default_heap_id: 0,
            th32_module_id: 0,
            cnt_threads: 0,
            th32_parent_process_id: 0,
            pc_pri_class_base: 0,
            dw_flags: 0,
            sz_exe_file: [0u16; MAX_PATH],
        };
        let mut out = Vec::with_capacity(256);
        let mut ok = unsafe { Process32FirstW(snap.0, &mut entry) };
        while ok != 0 {
            let pid = entry.th32_process_id;
            if pid > 4 {
                let nul = entry
                    .sz_exe_file
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.sz_exe_file.len());
                let name = String::from_utf16_lossy(&entry.sz_exe_file[..nul]);
                let (exe_path, started_epoch_secs) = query_process_meta(pid);
                out.push(ProcessEntry {
                    pid,
                    ppid: entry.th32_parent_process_id,
                    name,
                    exe_path,
                    started_epoch_secs,
                });
            }
            ok = unsafe { Process32NextW(snap.0, &mut entry) };
        }
        out
    }

    fn fetch_ipv4_tcp_rows(table_class: u32) -> Vec<MibTcpRowOwnerPid> {
        let mut size: u32 = 0;
        let first = unsafe { GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, AF_INET, table_class, 0) };
        if first != ERROR_INSUFFICIENT_BUFFER || size < 4 {
            return Vec::new();
        }
        let mut buf = vec![0u8; size as usize + 64];
        let mut actual_size = buf.len() as u32;
        let rc = unsafe {
            GetExtendedTcpTable(
                buf.as_mut_ptr() as *mut c_void,
                &mut actual_size,
                0,
                AF_INET,
                table_class,
                0,
            )
        };
        if rc != NO_ERROR || (actual_size as usize) < 4 {
            return Vec::new();
        }
        let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let row_size = std::mem::size_of::<MibTcpRowOwnerPid>();
        let max_rows = (actual_size as usize).saturating_sub(4) / row_size;
        let n = count.min(max_rows);
        let mut rows = Vec::with_capacity(n);
        for i in 0..n {
            let offset = 4 + i * row_size;
            let row = unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const MibTcpRowOwnerPid) };
            rows.push(row);
        }
        rows
    }

    #[inline]
    fn net_port_to_host(raw: u32) -> u16 {
        u16::from_be((raw & 0xFFFF) as u16)
    }

    #[inline]
    fn is_ipv4_loopback_or_any(addr_ne: u32) -> bool {
        let octets = addr_ne.to_ne_bytes();
        octets == [127, 0, 0, 1] || octets == [0, 0, 0, 0]
    }

    pub fn lookup_tcp_owner_pid(peer_addr: SocketAddr, server_port: u16) -> Option<u32> {
        let IpAddr::V4(v4) = peer_addr.ip() else {
            return None;
        };
        let target_ip = u32::from_ne_bytes(v4.octets());
        let client_port = peer_addr.port();
        for row in fetch_ipv4_tcp_rows(TCP_TABLE_OWNER_PID_CONNECTIONS) {
            if row.local_addr == target_ip
                && net_port_to_host(row.local_port) == client_port
                && net_port_to_host(row.remote_port) == server_port
                && row.owning_pid > 4
            {
                return Some(row.owning_pid);
            }
        }
        None
    }

    pub fn list_loopback_tcp_listeners() -> Vec<LocalListener> {
        fetch_ipv4_tcp_rows(TCP_TABLE_OWNER_PID_LISTENER)
            .into_iter()
            .filter(|r| is_ipv4_loopback_or_any(r.local_addr) && r.owning_pid > 4)
            .map(|r| LocalListener {
                port: net_port_to_host(r.local_port),
                pid: r.owning_pid,
            })
            .filter(|l| l.port > 0)
            .collect()
    }

    pub fn terminate_pid(pid: u32) -> Result<(), String> {
        let Some(handle) = SafeHandle::new(unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) }) else {
            return Err(format!(
                "unable to open process {pid} (insufficient permissions or already exited)"
            ));
        };
        if unsafe { TerminateProcess(handle.0, 0) } != 0 {
            Ok(())
        } else {
            Err(format!("failed to terminate process {pid}"))
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{LocalListener, ProcessEntry, SocketAddr};
    use std::collections::HashMap;
    use std::fs;

    pub fn capture_processes() -> Vec<ProcessEntry> {
        let Ok(entries) = fs::read_dir("/proc") else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for ent in entries.flatten() {
            let Ok(pid) = ent.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let base = ent.path();
            let name = fs::read_to_string(base.join("comm"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            let ppid = fs::read_to_string(base.join("stat"))
                .ok()
                .and_then(|s| s.rsplit_once(')').map(|(_, rest)| rest.to_string()))
                .and_then(|rest| rest.split_whitespace().nth(1).and_then(|p| p.parse::<u32>().ok()))
                .unwrap_or(0);
            let exe_path = fs::read_link(base.join("exe"))
                .ok()
                .map(|p| p.to_string_lossy().into_owned());
            out.push(ProcessEntry {
                pid,
                ppid,
                name,
                exe_path,
                started_epoch_secs: None,
            });
        }
        out
    }

    fn parse_proc_net_tcp() -> Vec<(u32, u16, u32, u16, u8, u64)> {
        let Ok(raw) = fs::read_to_string("/proc/net/tcp") else {
            return Vec::new();
        };
        let mut rows = Vec::new();
        for line in raw.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 {
                continue;
            }
            let Some((la, lp)) = cols[1].split_once(':') else {
                continue;
            };
            let Some((ra, rp)) = cols[2].split_once(':') else {
                continue;
            };
            let (Ok(la), Ok(lp), Ok(ra), Ok(rp), Ok(st), Ok(inode)) = (
                u32::from_str_radix(la, 16),
                u16::from_str_radix(lp, 16),
                u32::from_str_radix(ra, 16),
                u16::from_str_radix(rp, 16),
                u8::from_str_radix(cols[3], 16),
                cols[9].parse::<u64>(),
            ) else {
                continue;
            };
            rows.push((la, lp, ra, rp, st, inode));
        }
        rows
    }

    fn map_inodes_to_pids(target_inodes: &std::collections::HashSet<u64>) -> HashMap<u64, u32> {
        let mut map = HashMap::new();
        if target_inodes.is_empty() {
            return map;
        }
        let Ok(entries) = fs::read_dir("/proc") else {
            return map;
        };
        for ent in entries.flatten() {
            let Ok(pid) = ent.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Ok(fds) = fs::read_dir(ent.path().join("fd")) else {
                continue;
            };
            for fd in fds.flatten() {
                let Ok(target) = fs::read_link(fd.path()) else {
                    continue;
                };
                let s = target.to_string_lossy();
                let Some(inner) = s.strip_prefix("socket:[").and_then(|r| r.strip_suffix(']')) else {
                    continue;
                };
                let Ok(inode) = inner.parse::<u64>() else {
                    continue;
                };
                if target_inodes.contains(&inode) {
                    map.insert(inode, pid);
                }
            }
        }
        map
    }

    pub fn lookup_tcp_owner_pid(peer_addr: SocketAddr, server_port: u16) -> Option<u32> {
        let client_port = peer_addr.port();
        let rows = parse_proc_net_tcp();
        let inode = rows
            .into_iter()
            .find(|&(_, lp, _, rp, st, inode)| st == 0x01 && lp == client_port && rp == server_port && inode > 0)
            .map(|r| r.5)?;
        let mut set = std::collections::HashSet::new();
        set.insert(inode);
        map_inodes_to_pids(&set).remove(&inode)
    }

    pub fn list_loopback_tcp_listeners() -> Vec<LocalListener> {
        let rows: Vec<(u16, u64)> = parse_proc_net_tcp()
            .into_iter()
            .filter(|&(la, lp, _, _, st, inode)| st == 0x0A && lp > 0 && inode > 0 && (la == 0x0100_007F || la == 0))
            .map(|(_, lp, _, _, _, inode)| (lp, inode))
            .collect();
        let set: std::collections::HashSet<u64> = rows.iter().map(|r| r.1).collect();
        let owners = map_inodes_to_pids(&set);
        rows.into_iter()
            .filter_map(|(port, inode)| owners.get(&inode).map(|&pid| LocalListener { port, pid }))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::get_all_harness_profiles;

    #[test]
    fn attributes_child_and_sibling_companions_and_flags_restart_until_traffic_arrives() {
        let mut profiles = get_all_harness_profiles(18787);
        for p in &mut profiles {
            if p.kind == HarnessKind::Pi {
                p.installed = true;
                p.configured = true;
                p.install_paths = vec![r"C:\Users\dev\AppData\Roaming\npm\pi.cmd".to_string()];
            }
            if p.kind == HarnessKind::Cursor {
                p.installed = true;
                p.configured = true;
                p.install_paths = vec![r"C:\Users\dev\AppData\Local\Programs\cursor\Cursor.exe".to_string()];
            }
        }

        let snap = ProcessSnapshot::from_entries(vec![
            ProcessEntry {
                pid: 1000,
                ppid: 1,
                name: "pi.exe".to_string(),
                exe_path: Some(r"C:\Users\dev\AppData\Roaming\npm\pi.exe".to_string()),
                started_epoch_secs: Some(1_700_000_000),
            },
            ProcessEntry {
                pid: 1001,
                ppid: 1000,
                name: "node.exe".to_string(),
                exe_path: Some(r"C:\Program Files\nodejs\node.exe".to_string()),
                started_epoch_secs: Some(1_700_000_005),
            },
            ProcessEntry {
                pid: 2000,
                ppid: 1,
                name: "Cursor.exe".to_string(),
                exe_path: Some(r"C:\Users\dev\AppData\Local\Programs\cursor\Cursor.exe".to_string()),
                started_epoch_secs: Some(1_700_000_010),
            },
            ProcessEntry {
                pid: 2001,
                ppid: 1,
                name: "crashpad_handler.exe".to_string(),
                exe_path: Some(r"C:\Users\dev\AppData\Local\Programs\cursor\crashpad_handler.exe".to_string()),
                started_epoch_secs: Some(1_700_000_011),
            },
        ]);

        // Child MCP/node process under Pi attributes back to Pi as companion
        let attr_child = resolve_pid_attribution(&snap, 1001, &profiles).unwrap();
        assert_eq!(attr_child.harness, Some(HarnessKind::Pi));
        assert!(attr_child.is_companion);
        assert_eq!(attr_child.display_label(), "node.exe (via Pi)");

        // Sibling crashpad helper inside Cursor's install dir attributes back to Cursor
        let attr_sib = resolve_pid_attribution(&snap, 2001, &profiles).unwrap();
        assert_eq!(attr_sib.harness, Some(HarnessKind::Cursor));
        assert!(attr_sib.is_companion);

        // Gateway started AFTER both processes, zero live traffic -> both need restart
        let notices = evaluate_running_harnesses(&snap, &profiles, 1_700_000_500, &HashMap::new());
        let pi_notice = notices.iter().find(|n| n.kind == HarnessKind::Pi).unwrap();
        assert!(pi_notice.needs_restart);
        assert!(pi_notice
            .companions
            .iter()
            .any(|c| c.pid == 1001 && c.relation == "child"));

        let cur_notice = notices.iter().find(|n| n.kind == HarnessKind::Cursor).unwrap();
        assert!(cur_notice.needs_restart);
        assert!(cur_notice
            .companions
            .iter()
            .any(|c| c.pid == 2001 && c.relation == "sibling"));

        // Once live traffic arrives for Pi, restart reminder clears immediately
        profiles
            .iter_mut()
            .find(|p| p.kind == HarnessKind::Pi)
            .unwrap()
            .traffic_count = 1;
        let after = evaluate_running_harnesses(&snap, &profiles, 1_700_000_500, &HashMap::new());
        assert!(!after.iter().find(|n| n.kind == HarnessKind::Pi).unwrap().needs_restart);
    }
}
