use std::{
    collections::{BTreeSet, VecDeque},
    env, fs,
    path::{Path, PathBuf},
};

fn mime_for_asset(name: &str) -> &'static str {
    let ext = Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("js" | "mjs") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        _ => "application/octet-stream",
    }
}

fn collect_setup_assets(dist_dir: &Path, setup_html_text: &str) -> Vec<String> {
    let assets_dir = dist_dir.join("assets");
    let all_assets: Vec<String> = fs::read_dir(&assets_dir)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", assets_dir.display()))
        .filter_map(|entry| {
            let entry = entry.ok()?;
            entry.file_type().ok()?.is_file().then_some(())?;
            entry.file_name().into_string().ok()
        })
        .collect();

    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::new();

    for name in &all_assets {
        if setup_html_text.contains(name.as_str()) && visited.insert(name.clone()) {
            queue.push_back(name.clone());
        }
    }

    while let Some(cur) = queue.pop_front() {
        let low = cur.to_ascii_lowercase();
        if !(low.ends_with(".js") || low.ends_with(".mjs") || low.ends_with(".css")) {
            continue;
        }
        let Ok(content) = fs::read_to_string(assets_dir.join(&cur)) else {
            continue;
        };
        for candidate in &all_assets {
            if !visited.contains(candidate) && content.contains(candidate.as_str()) {
                visited.insert(candidate.clone());
                queue.push_back(candidate.clone());
            }
        }
    }

    visited.into_iter().collect()
}

fn generate_embedded_setup(manifest_dir: &Path) {
    let repo_root =
        fs::canonicalize(manifest_dir.join("../..")).unwrap_or_else(|e| panic!("failed to locate workspace root: {e}"));
    let dist_dir = repo_root.join("dist");
    let setup_html_path = dist_dir.join("setup.html");
    let locales_dir = repo_root.join("src/locales");
    let zh_locale_path = locales_dir.join("zh-CN.json");
    let en_locale_path = locales_dir.join("en.json");

    println!("cargo:rerun-if-changed={}", setup_html_path.display());
    println!("cargo:rerun-if-changed={}", dist_dir.join("assets").display());
    println!("cargo:rerun-if-changed={}", zh_locale_path.display());
    println!("cargo:rerun-if-changed={}", en_locale_path.display());
    println!("cargo:rerun-if-env-changed=HIDE_GO_EMBED_PAYLOAD_ARCHIVE");

    let setup_html = fs::read_to_string(&setup_html_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", setup_html_path.display()));
    let assets = collect_setup_assets(&dist_dir, &setup_html);

    let mut out = String::new();
    out.push_str(&format!(
        "pub const EMBEDDED_SETUP_HTML: &str = include_str!({:?});\n",
        setup_html_path.to_string_lossy()
    ));
    out.push_str(&format!(
        "pub const EMBEDDED_LOCALE_ZH_CN: &str = include_str!({:?});\n",
        zh_locale_path.to_string_lossy()
    ));
    out.push_str(&format!(
        "pub const EMBEDDED_LOCALE_EN: &str = include_str!({:?});\n",
        en_locale_path.to_string_lossy()
    ));
    out.push_str("pub const EMBEDDED_SETUP_ASSETS: &[(&str, &str, &[u8])] = &[\n");
    for name in &assets {
        let asset_path = dist_dir.join("assets").join(name);
        println!("cargo:rerun-if-changed={}", asset_path.display());
        let url = format!("/assets/{name}");
        let mime = mime_for_asset(name);
        out.push_str(&format!(
            "    ({:?}, {:?}, include_bytes!({:?})),\n",
            url,
            mime,
            asset_path.to_string_lossy()
        ));
    }
    out.push_str("];\n");

    let payload_env = env::var("HIDE_GO_EMBED_PAYLOAD_ARCHIVE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    if let Some(raw_path) = payload_env {
        let candidate = PathBuf::from(&raw_path);
        let abs_path = if candidate.is_absolute() {
            candidate
        } else {
            repo_root.join(candidate)
        };
        let bytes = fs::read(&abs_path).unwrap_or_else(|e| {
            panic!(
                "HIDE_GO_EMBED_PAYLOAD_ARCHIVE points to missing file {}: {e}",
                abs_path.display()
            )
        });
        println!("cargo:rerun-if-changed={}", abs_path.display());
        let digest = ring::digest::digest(&ring::digest::SHA256, &bytes);
        let sha256: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        out.push_str(&format!(
            "pub const EMBEDDED_PAYLOAD_ARCHIVE: Option<(&[u8], &str)> = Some((include_bytes!({:?}), {:?}));\n",
            abs_path.to_string_lossy(),
            sha256
        ));
    } else {
        out.push_str("pub const EMBEDDED_PAYLOAD_ARCHIVE: Option<(&[u8], &str)> = None;\n");
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"));
    fs::write(out_dir.join("embedded_setup.rs"), out).expect("failed to write embedded_setup.rs");
}

#[cfg(windows)]
fn four_part_version(raw: &str) -> String {
    let core = raw.split(['-', '+']).next().unwrap_or("0.1.0");
    let mut parts = core.split('.');
    let parse_num = |s: Option<&str>| -> u16 { s.and_then(|v| v.trim().parse::<u16>().ok()).unwrap_or(0) };
    format!(
        "{}.{}.{}.0",
        parse_num(parts.next()),
        parse_num(parts.next()),
        parse_num(parts.next())
    )
}

#[cfg(windows)]
fn build_windows_manifest(assembly_ver: &str, identity_name: &str, desc: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="{assembly_ver}" processorArchitecture="*" name="{identity_name}" type="win32"/>
  <description>{desc}</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}}"/>
      <supportedOS Id="{{1f676c76-80e1-4239-95bb-83d0f6d0da78}}"/>
      <supportedOS Id="{{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}}"/>
      <supportedOS Id="{{35138b9a-5d96-4fbd-8e2d-a2440225f93a}}"/>
      <supportedOS Id="{{e2011457-1546-43c5-a5fe-008deee3d3f0}}"/>
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </windowsSettings>
  </application>
</assembly>
"#
    )
}

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let icon_ico = manifest_dir.join("../../desktop/icons/icon.ico");
    println!("cargo:rerun-if-changed={}", icon_ico.display());

    generate_embedded_setup(&manifest_dir);

    #[cfg(windows)]
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let pkg_ver = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.1.0".into());
        let assembly_ver = four_part_version(&pkg_ver);
        let manifest = build_windows_manifest(&assembly_ver, "HideGo.Setup", "Hide-Go Setup");

        let mut res = winresource::WindowsResource::new();
        res.set_icon(icon_ico.to_str().expect("desktop/icons/icon.ico path must be UTF-8"));
        res.set_manifest(&manifest);
        res.set("CompanyName", "Hide-Go");
        res.set("ProductName", "Hide-Go");
        res.set("LegalCopyright", "Copyright (c) Hide-Go Contributors");
        res.set("FileDescription", "Hide-Go Setup");
        res.set("OriginalFilename", "Hide-Go-Setup.exe");
        res.set("InternalName", "hide-go-setup");
        res.compile()
            .expect("failed to compile Windows icon resource for hide-go-setup");
    }
}
