use std::{env, path::PathBuf};

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

    #[cfg(windows)]
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let pkg_ver = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.1.0".into());
        let assembly_ver = four_part_version(&pkg_ver);
        let manifest = build_windows_manifest(&assembly_ver, "HideGo.Daemon", "Hide-Go Background Gateway Daemon");

        let mut res = winresource::WindowsResource::new();
        res.set_icon(icon_ico.to_str().expect("desktop/icons/icon.ico path must be UTF-8"));
        res.set_manifest(&manifest);
        res.set("CompanyName", "Hide-Go");
        res.set("ProductName", "Hide-Go");
        res.set("LegalCopyright", "Copyright (c) Hide-Go Contributors");
        res.set("FileDescription", "Hide-Go Background Gateway Daemon");
        res.set("OriginalFilename", "hide-go-daemon.exe");
        res.set("InternalName", "hide-go-daemon");
        res.compile()
            .expect("failed to compile Windows icon resource for hide-go-daemon");
    }
}
