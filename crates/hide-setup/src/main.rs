#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use hide_engine::{
    chrome_bridge::{ChromeHost, NativeWindowOptions},
    installer::EmbeddedPayloadArchive,
    setup::{localized_setup_message, run_setup_standalone, EmbeddedSetupAssets},
    web_assets::UiBundle,
};
use std::path::Path;
use std::sync::Arc;

mod embedded_setup {
    include!(concat!(env!("OUT_DIR"), "/embedded_setup.rs"));
}

struct NativeChromeHost;

impl ChromeHost for NativeChromeHost {
    fn can_open_gui(&self) -> bool {
        hide_chrome::can_open_gui()
    }

    fn run_frameless_window(&self, opts: NativeWindowOptions) -> Result<(), String> {
        hide_chrome::run_frameless_window(hide_chrome::NativeWindowOptions {
            title: opts.title,
            url: opts.url,
            width: opts.width,
            height: opts.height,
            min_width: opts.min_width,
            min_height: opts.min_height,
            resizable: opts.resizable,
            cleanup_on_close: opts.cleanup_on_close,
            user_data_dir: opts.user_data_dir,
        })
    }

    fn show_error_dialog(&self, title: &str, message: &str) {
        hide_chrome::show_error_dialog(title, message);
    }

    fn pick_folder(&self, title: &str, initial_dir: Option<&Path>) -> Option<std::path::PathBuf> {
        hide_chrome::pick_folder(title, initial_dir)
    }

    fn detect_system_locale(&self) -> &'static str {
        hide_chrome::detect_system_locale()
    }

    fn terminate_other_processes(&self) -> usize {
        hide_chrome::terminate_other_hide_go_processes()
    }
}

fn main() {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));
    let chrome: Arc<dyn ChromeHost> = Arc::new(NativeChromeHost);

    let ui = match UiBundle::from_embedded(
        embedded_setup::EMBEDDED_SETUP_HTML,
        embedded_setup::EMBEDDED_SETUP_ASSETS,
    ) {
        Ok(bundle) => bundle,
        Err(err) => {
            let locale = chrome.detect_system_locale();
            let title = localized_setup_message(
                locale,
                embedded_setup::EMBEDDED_LOCALE_ZH_CN,
                embedded_setup::EMBEDDED_LOCALE_EN,
                "setup.launchErrorTitle",
            );
            let title = if title.is_empty() { "Hide-Go Setup" } else { &title };
            chrome.show_error_dialog(title, &err);
            std::process::exit(1);
        }
    };

    let payload_archive =
        embedded_setup::EMBEDDED_PAYLOAD_ARCHIVE.map(|(bytes, sha256)| EmbeddedPayloadArchive { bytes, sha256 });

    let code = run_setup_standalone(
        exe_dir.as_deref(),
        chrome,
        EmbeddedSetupAssets {
            ui,
            zh_cn_json: embedded_setup::EMBEDDED_LOCALE_ZH_CN,
            en_json: embedded_setup::EMBEDDED_LOCALE_EN,
            payload_archive,
        },
    );
    std::process::exit(code);
}
