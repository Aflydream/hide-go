#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    std::process::exit(hide_launcher::launch_gui_entry(b"hide_engine_run_desktop\0"));
}
