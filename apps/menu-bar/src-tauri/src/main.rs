// macOS: hide the dock icon — this is a menu-bar-only app.
// (Setting NSUIElement = true in Info.plist; for `cargo run` we use the
// activation-policy hack below to also work outside a bundled app.)
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::Deserialize;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{
    AppHandle,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    tray::{TrayIcon, TrayIconBuilder},
};
use tokio::time::interval;

#[derive(Debug, Clone, Default, Deserialize)]
struct Summary {
    total: u64,
    last_24h: u64,
    last_7d: u64,
    last_30d: u64,
}

struct StatsState {
    last_summary: Mutex<Summary>,
}

const POLL_INTERVAL_SECS: u64 = 2;

fn read_proxy_stats_port() -> Option<u16> {
    std::fs::read_to_string("/tmp/bleep-stats.port")
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

async fn fetch_summary(port: u16) -> Option<Summary> {
    let url = format!("http://127.0.0.1:{port}/stats");
    let resp = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .ok()?
        .get(&url)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<Summary>().await.ok()
}

fn format_tray_title(s: &Summary, connected: bool) -> String {
    if !connected {
        // dim, no count, indicates not connected
        "Bleep •".to_string()
    } else {
        format!("Bleep · {}", s.last_24h)
    }
}

fn format_menu_summary(s: &Summary) -> String {
    format!(
        "Today: {}   ·   7d: {}   ·   30d: {}   ·   total: {}",
        s.last_24h, s.last_7d, s.last_30d, s.total
    )
}

fn build_menu(app: &AppHandle, summary_text: &str, connected: bool) -> tauri::Result<Menu<tauri::Wry>> {
    let header = MenuItem::with_id(app, "header", summary_text, false, None::<&str>)?;
    let status_label = if connected {
        "● Connected to bleep-gateway"
    } else {
        "○ Waiting for bleep-gateway…"
    };
    let status = MenuItem::with_id(app, "status", status_label, false, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let dashboard = MenuItem::with_id(app, "open_dashboard", "Open Dashboard…", true, None::<&str>)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Bleep", true, Some("Cmd+Q"))?;
    Menu::with_items(app, &[&header, &status, &sep, &dashboard, &sep2, &quit])
}

fn handle_menu_event(_app: &AppHandle, event: MenuEvent) {
    match event.id().as_ref() {
        "quit" => std::process::exit(0),
        "open_dashboard" => {
            // commit 4 will wire this to a real dashboard window
            eprintln!("[menu-bar] dashboard window not yet implemented");
        }
        _ => {}
    }
}

fn spawn_poller(app: AppHandle, tray: TrayIcon, state: Arc<StatsState>) {
    tauri::async_runtime::spawn(async move {
        let mut tick = interval(Duration::from_secs(POLL_INTERVAL_SECS));
        loop {
            tick.tick().await;
            let port = read_proxy_stats_port();
            let summary = match port {
                Some(p) => fetch_summary(p).await,
                None => None,
            };
            let connected = summary.is_some();
            let s = summary.unwrap_or_default();
            // update cached state
            if let Ok(mut guard) = state.last_summary.lock() {
                *guard = s.clone();
            }
            // update tray title
            let _ = tray.set_title(Some(format_tray_title(&s, connected)));
            // rebuild menu with fresh numbers
            if let Ok(menu) = build_menu(&app, &format_menu_summary(&s), connected) {
                let _ = tray.set_menu(Some(menu));
            }
        }
    });
}

fn run() {
    let state = Arc::new(StatsState {
        last_summary: Mutex::new(Summary::default()),
    });

    tauri::Builder::default()
        .setup({
            let state = state.clone();
            move |app| {
                #[cfg(target_os = "macos")]
                {
                    use tauri::ActivationPolicy;
                    app.set_activation_policy(ActivationPolicy::Accessory);
                }

                let initial_menu = build_menu(
                    app.handle(),
                    "Today: 0   ·   7d: 0   ·   30d: 0   ·   total: 0",
                    false,
                )?;
                let tray = TrayIconBuilder::with_id("main")
                    .icon(app.default_window_icon().cloned().ok_or("no default icon")?)
                    .icon_as_template(true)
                    .title("Bleep •")
                    .menu(&initial_menu)
                    .on_menu_event(handle_menu_event)
                    .build(app)?;

                spawn_poller(app.handle().clone(), tray, state);
                Ok(())
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn main() {
    run();
}
