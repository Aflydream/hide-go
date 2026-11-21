use std::{env, path::PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let icon_ico = manifest_dir.join("../../desktop/icons/icon.ico");
    println!("cargo:rerun-if-changed={}", icon_ico.display());

    #[cfg(windows)]
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon(icon_ico.to_str().expect("desktop/icons/icon.ico path must be UTF-8"));
        res.set("ProductName", "Hide-Go");
        res.set("FileDescription", "Hide-Go Setup");
        res.compile()
            .expect("failed to compile Windows icon resource for hide-go-setup");
    }
}
