// macOS: hide the windows-console banner in release; we use the macOS run loop.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{
    AppHandle, Emitter, Manager, RunEvent, WebviewUrl, WebviewWindowBuilder, WindowEvent,
    menu::{Menu, MenuBuilder, MenuEvent, MenuItem, PredefinedMenuItem, SubmenuBuilder},
    tray::{TrayIcon, TrayIconBuilder},
};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
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
    /// Cached last-rendered title + connection state. We only push tray
    /// updates when these change — otherwise repeatedly calling set_menu()
    /// while the user has the menu open causes macOS to close it.
    last_title: Mutex<String>,
    last_connected: Mutex<bool>,
}

#[derive(Default)]
struct GatewayProcess {
    child: Mutex<Option<Child>>,
}

const POLL_INTERVAL_SECS: u64 = 2;
const MAIN_WINDOW: &str = "main";

// ── port file discovery ───────────────────────────────────────────────────────

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

// ── window management ─────────────────────────────────────────────────────────

fn show_main_window(app: &AppHandle) {
    show_main_window_at(app, None);
}

fn show_main_window_at(app: &AppHandle, route: Option<&str>) {
    if let Some(existing) = app.get_webview_window(MAIN_WINDOW) {
        let _ = existing.show();
        let _ = existing.unminimize();
        let _ = existing.set_focus();
        if let Some(r) = route {
            let _ = existing.eval(&format!("window.location.hash = '#{r}'"));
        }
    } else {
        let url = match route {
            Some(r) => WebviewUrl::App(format!("index.html#{r}").into()),
            None => WebviewUrl::App("index.html".into()),
        };
        let win = WebviewWindowBuilder::new(app, MAIN_WINDOW, url)
            .title("Bleep")
            .inner_size(1080.0, 720.0)
            .min_inner_size(880.0, 560.0)
            .resizable(true)
            .visible(true)
            .build();
        if let Err(e) = win {
            eprintln!("[menu-bar] failed to create main window: {e}");
        }
    }
    refresh_activation_policy(app);
}

/// Hide instead of close — closing the red traffic light should leave the
/// tray running (mac convention for tray-based apps).
fn handle_close_request(window: &tauri::Window) {
    let _ = window.hide();
    refresh_activation_policy(&window.app_handle().clone());
}

/// macOS: show the dock icon when at least one window is visible; revert to
/// Accessory (tray-only, no dock icon, no app-switcher entry) otherwise.
fn refresh_activation_policy(_app: &AppHandle) {
    #[cfg(target_os = "macos")]
    {
        use tauri::ActivationPolicy;
        let any_visible = _app
            .webview_windows()
            .values()
            .any(|w| w.is_visible().unwrap_or(false));
        let policy = if any_visible {
            ActivationPolicy::Regular
        } else {
            ActivationPolicy::Accessory
        };
        let _ = _app.set_activation_policy(policy);
    }
}

// ── tray ──────────────────────────────────────────────────────────────────────

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

fn build_tray_menu(
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
    let show = MenuItem::with_id(app, "show_main", "Show Bleep…", true, None::<&str>)?;
    let dashboard = MenuItem::with_id(app, "show_dashboard", "Open Dashboard", true, None::<&str>)?;
    let rules = MenuItem::with_id(app, "show_rules", "Rules", true, None::<&str>)?;
    let settings = MenuItem::with_id(app, "show_settings", "Settings", true, None::<&str>)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Bleep", true, Some("Cmd+Q"))?;
    Menu::with_items(
        app,
        &[
            &header, &status, &sep, &show, &dashboard, &rules, &settings, &sep2, &quit,
        ],
    )
}

fn handle_tray_event(app: &AppHandle, event: MenuEvent) {
    match event.id().as_ref() {
        "quit" => app.exit(0),
        "show_main" => show_main_window(app),
        "show_dashboard" => show_main_window_at(app, Some("dashboard")),
        "show_rules" => show_main_window_at(app, Some("rules")),
        "show_settings" => show_main_window_at(app, Some("settings")),
        _ => {}
    }
}

// ── app menu (mac menu bar across the top of the screen) ──────────────────────

fn build_app_menu(app: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let app_submenu = SubmenuBuilder::new(app, "Bleep")
        .text("about", "About Bleep")
        .separator()
        .text("hide", "Hide Bleep")
        .text("hide_others", "Hide Others")
        .separator()
        .text("quit_app", "Quit Bleep")
        .build()?;

    let edit_submenu = SubmenuBuilder::new(app, "Edit")
        .undo()
        .redo()
        .separator()
        .cut()
        .copy()
        .paste()
        .select_all()
        .build()?;

    let view_submenu = SubmenuBuilder::new(app, "View")
        .text("nav_dashboard", "Dashboard")
        .text("nav_rules", "Rules")
        .text("nav_settings", "Settings")
        .separator()
        .text("reload", "Reload")
        .build()?;

    let window_submenu = SubmenuBuilder::new(app, "Window")
        .minimize()
        .text("close_window", "Close Window")
        .separator()
        .text("show_main_menu", "Bring to Front")
        .build()?;

    MenuBuilder::new(app)
        .items(&[&app_submenu, &edit_submenu, &view_submenu, &window_submenu])
        .build()
}

fn handle_app_menu_event(app: &AppHandle, event: MenuEvent) {
    match event.id().as_ref() {
        "quit_app" => app.exit(0),
        "hide" => {
            for w in app.webview_windows().values() {
                let _ = w.hide();
            }
            refresh_activation_policy(app);
        }
        "hide_others" => {
            // Tauri doesn't expose hideOtherApplications directly; closest is to
            // do nothing here (the standard PredefinedMenuItem::hide_others would
            // be ideal but for simplicity we no-op).
        }
        "about" => show_main_window_at(app, Some("about")),
        "nav_dashboard" => show_main_window_at(app, Some("dashboard")),
        "nav_rules" => show_main_window_at(app, Some("rules")),
        "nav_settings" => show_main_window_at(app, Some("settings")),
        "reload" => {
            if let Some(w) = app.get_webview_window(MAIN_WINDOW) {
                let _ = w.eval("window.location.reload()");
            }
        }
        "close_window" => {
            if let Some(w) = app.get_webview_window(MAIN_WINDOW) {
                let _ = w.hide();
                refresh_activation_policy(app);
            }
        }
        "show_main_menu" => show_main_window(app),
        _ => {}
    }
}

// ── stats poller (updates tray title + menu) ──────────────────────────────────

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

            // only push tray updates when values actually changed.
            // calling set_menu() while the user has the menu open causes
            // macOS to close it, which feels like the click "loses focus"
            let new_title = format_tray_title(&s, connected);
            let title_changed = match state.last_title.lock() {
                Ok(mut g) if *g != new_title => {
                    *g = new_title.clone();
                    true
                }
                _ => false,
            };
            let connected_changed = match state.last_connected.lock() {
                Ok(mut g) if *g != connected => {
                    *g = connected;
                    true
                }
                _ => false,
            };
            if title_changed {
                let _ = tray.set_title(Some(new_title));
            }
            // rebuild the menu only when the values it shows have changed:
            // either the connection state flipped, or the summary text differs
            if title_changed || connected_changed {
                if let Ok(menu) = build_tray_menu(&app, &format_menu_summary(&s), connected) {
                    let _ = tray.set_menu(Some(menu));
                }
            }
        }
    });
}

// ── embedded gateway lifecycle ────────────────────────────────────────────────

fn resolve_gateway_binary(app: &AppHandle) -> Option<PathBuf> {
    if let Ok(p) = std::env::var("BLEEP_GATEWAY_BIN") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Some(path);
        }
    }
    if let Ok(resource_dir) = app.path().resource_dir() {
        let path = resource_dir.join("bleep-gateway");
        if path.is_file() {
            return Some(path);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let path = dir.join("bleep-gateway");
            if path.is_file() {
                return Some(path);
            }
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        let mut p = exe.as_path();
        for _ in 0..6 {
            match p.parent() {
                Some(parent) => p = parent,
                None => return None,
            }
        }
        let release = p.join("target/release/bleep-gateway");
        if release.is_file() {
            return Some(release);
        }
        let debug = p.join("target/debug/bleep-gateway");
        if debug.is_file() {
            return Some(debug);
        }
    }
    None
}

async fn gateway_already_running() -> bool {
    let Some(port) = read_proxy_stats_port() else {
        return false;
    };
    let url = format!("http://127.0.0.1:{port}/health");
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    matches!(client.get(&url).send().await, Ok(r) if r.status().is_success())
}

fn spawn_gateway(app: AppHandle, gateway: Arc<GatewayProcess>) {
    tauri::async_runtime::spawn(async move {
        if gateway_already_running().await {
            println!("[menu-bar] gateway already running — not spawning a second copy");
            return;
        }
        let Some(bin) = resolve_gateway_binary(&app) else {
            eprintln!(
                "[menu-bar] could not locate bleep-gateway binary. Set BLEEP_GATEWAY_BIN \
                 or run the gateway manually."
            );
            return;
        };
        let our_pid = std::process::id();
        println!(
            "[menu-bar] spawning gateway: {} (BLEEP_PARENT_PID={})",
            bin.display(),
            our_pid
        );
        let child = Command::new(&bin)
            .env("BLEEP_PARENT_PID", our_pid.to_string())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn();
        match child {
            Ok(c) => {
                if let Ok(mut guard) = gateway.child.lock() {
                    *guard = Some(c);
                }
            }
            Err(e) => eprintln!("[menu-bar] failed to spawn gateway: {e}"),
        }
    });
}

fn shutdown_gateway(gateway: &GatewayProcess) {
    if let Ok(mut guard) = gateway.child.lock() {
        if let Some(mut child) = guard.take() {
            let _ = child.start_kill();
        }
    }
}

#[cfg(unix)]
fn spawn_signal_handler(gateway: Arc<GatewayProcess>) {
    tauri::async_runtime::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        let term = signal(SignalKind::terminate());
        let int = signal(SignalKind::interrupt());
        let (mut term, mut int) = match (term, int) {
            (Ok(t), Ok(i)) => (t, i),
            _ => return,
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
        eprintln!("[menu-bar] caught signal, shutting down gateway");
        shutdown_gateway(&gateway);
        std::process::exit(0);
    });
}

#[cfg(not(unix))]
fn spawn_signal_handler(_gateway: Arc<GatewayProcess>) {}

// ── live event forwarding ─────────────────────────────────────────────────────

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
                            Ok(0) => break,
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

// ── entry point ───────────────────────────────────────────────────────────────

fn run() {
    let state = Arc::new(StatsState {
        last_summary: Mutex::new(Summary::default()),
        last_title: Mutex::new(String::new()),
        last_connected: Mutex::new(false),
    });
    let gateway = Arc::new(GatewayProcess::default());

    // when a user double-clicks the .app or launches it from Spotlight (no
    // --tray flag), the main window should appear. Otherwise we stay tray-only.
    let start_in_tray = std::env::args().any(|a| a == "--tray");

    let app = tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_stats_port])
        .menu(|app| build_app_menu(app))
        .on_menu_event(handle_app_menu_event)
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                handle_close_request(window);
            }
        })
        .setup({
            let state = state.clone();
            let gateway = gateway.clone();
            move |app| {
                #[cfg(target_os = "macos")]
                {
                    use tauri::ActivationPolicy;
                    let initial = if start_in_tray {
                        ActivationPolicy::Accessory
                    } else {
                        ActivationPolicy::Regular
                    };
                    let _ = app.set_activation_policy(initial);
                }

                let initial_menu = build_tray_menu(
                    app.handle(),
                    "Today: 0   ·   7d: 0   ·   30d: 0   ·   total: 0",
                    false,
                )?;
                let tray = TrayIconBuilder::with_id("main")
                    .title("Bleep •")
                    .menu(&initial_menu)
                    .on_menu_event(handle_tray_event)
                    .build(app)?;

                spawn_gateway(app.handle().clone(), gateway.clone());
                spawn_signal_handler(gateway.clone());
                spawn_poller(app.handle().clone(), tray, state);
                spawn_event_forwarder(app.handle().clone());

                if !start_in_tray {
                    show_main_window(app.handle());
                }
                Ok(())
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    let gw_for_exit = gateway.clone();
    app.run(move |app, event| match event {
        RunEvent::Exit => {
            shutdown_gateway(&gw_for_exit);
        }
        // macOS: clicking the dock icon when no windows are visible should reopen.
        RunEvent::Reopen { has_visible_windows, .. } if !has_visible_windows => {
            show_main_window(app);
        }
        _ => {}
    });
}

fn main() {
    run();
}
