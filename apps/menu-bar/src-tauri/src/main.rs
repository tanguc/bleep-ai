// macOS: hide the dock icon — this is a menu-bar-only app.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{
    AppHandle, Emitter, Manager, WebviewUrl, WebviewWindowBuilder,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    tray::{TrayIcon, TrayIconBuilder},
};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::interval;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct Summary {
    total: u64,
    last_24h: u64,
    last_7d: u64,
    last_30d: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RedactedEntry {
    rule_id: String,
    category: String,
    subcategory: Option<String>,
    severity: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
enum ProxyEvent {
    Request {
        id: String,
        ts: String,
        method: String,
        uri: String,
        redacted: Vec<RedactedEntry>,
    },
    Response {
        id: String,
        ts: String,
        uri: String,
        status: u16,
    },
}

struct StatsState {
    last_summary: Mutex<Summary>,
}

const POLL_INTERVAL_SECS: u64 = 2;
const DASHBOARD_LABEL: &str = "dashboard";

fn read_port_file(path: &str) -> Option<u16> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

fn read_proxy_stats_port() -> Option<u16> {
    read_port_file("/tmp/bleep-stats.port")
}

fn read_proxy_events_port() -> Option<u16> {
    read_port_file("/tmp/bleep-events.port")
}

#[tauri::command]
fn get_stats_port() -> Option<u16> {
    read_proxy_stats_port()
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

fn build_menu(
    app: &AppHandle,
    summary_text: &str,
    connected: bool,
) -> tauri::Result<Menu<tauri::Wry>> {
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

fn open_dashboard(app: &AppHandle) {
    if let Some(existing) = app.get_webview_window(DASHBOARD_LABEL) {
        let _ = existing.show();
        let _ = existing.set_focus();
        return;
    }
    let builder = WebviewWindowBuilder::new(app, DASHBOARD_LABEL, WebviewUrl::App("index.html".into()))
        .title("Bleep Dashboard")
        .inner_size(900.0, 640.0)
        .min_inner_size(720.0, 520.0)
        .resizable(true)
        .visible(true);
    if let Err(e) = builder.build() {
        eprintln!("[menu-bar] failed to create dashboard window: {e}");
    }
}

fn handle_menu_event(app: &AppHandle, event: MenuEvent) {
    match event.id().as_ref() {
        "quit" => app.exit(0),
        "open_dashboard" => open_dashboard(app),
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
            if let Ok(mut guard) = state.last_summary.lock() {
                *guard = s.clone();
            }
            let _ = tray.set_title(Some(format_tray_title(&s, connected)));
            if let Ok(menu) = build_menu(&app, &format_menu_summary(&s), connected) {
                let _ = tray.set_menu(Some(menu));
            }
        }
    });
}

/// Connect to the gateway's event_bus TCP stream and forward each Request
/// event (with at least one redaction) to the webview as a "redaction" event.
/// Reconnects with backoff if the connection drops or never establishes.
fn spawn_event_forwarder(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut backoff = Duration::from_secs(1);
        loop {
            let port = match read_proxy_events_port() {
                Some(p) => p,
                None => {
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(15));
                    continue;
                }
            };
            match TcpStream::connect(("127.0.0.1", port)).await {
                Ok(stream) => {
                    backoff = Duration::from_secs(1);
                    let mut reader = BufReader::new(stream);
                    let mut line = String::new();
                    loop {
                        line.clear();
                        match reader.read_line(&mut line).await {
                            Ok(0) => break, // EOF
                            Ok(_) => {
                                let trimmed = line.trim();
                                if trimmed.is_empty() {
                                    continue;
                                }
                                if let Ok(ev) = serde_json::from_str::<ProxyEvent>(trimmed) {
                                    if let ProxyEvent::Request { redacted, .. } = &ev {
                                        if redacted.is_empty() {
                                            continue;
                                        }
                                    } else {
                                        continue;
                                    }
                                    let _ = app.emit("redaction", &ev);
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
                Err(_) => {
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(15));
                }
            }
        }
    });
}

fn run() {
    let state = Arc::new(StatsState {
        last_summary: Mutex::new(Summary::default()),
    });

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_stats_port])
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
                spawn_event_forwarder(app.handle().clone());
                Ok(())
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn main() {
    run();
}
