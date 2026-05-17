// macOS: hide the windows-console banner in release; we use the macOS run loop.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{
    menu::{Menu, MenuBuilder, MenuEvent, MenuItem, PredefinedMenuItem, SubmenuBuilder},
    tray::{TrayIcon, TrayIconBuilder},
    AppHandle, Emitter, Manager, RunEvent, WebviewUrl, WebviewWindowBuilder, WindowEvent,
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

// Wire types from the shared crate — same definitions the gateway and TUI
// use. Previously this file maintained its own RedactedEntry / ProxyEvent
// copies that had drifted (missing fake_value, subcategory typed as Option).
use bleep_events::ProxyEvent;

struct StatsState {
    last_summary: Mutex<Summary>,
    /// Cached last-rendered tray title — only push set_title() when it
    /// changes (avoids unnecessary writes; not strictly required for
    /// open-menu stability, but keeps the chrome quieter).
    last_title: Mutex<String>,
    /// Live-updatable references to the dynamic items in the tray menu.
    /// We mutate these in place every poll instead of rebuilding the
    /// whole Menu — rebuilding swaps the underlying NSMenu, which closes
    /// any open dropdown on macOS.
    header_item: Mutex<Option<MenuItem<tauri::Wry>>>,
    status_item: Mutex<Option<MenuItem<tauri::Wry>>>,
}

#[derive(Default)]
struct GatewayProcess {
    child: Mutex<Option<Child>>,
}

const POLL_INTERVAL_SECS: u64 = 2;
const MAIN_WINDOW: &str = "main";

// ── port file discovery ───────────────────────────────────────────────────────
//
// Mirrors src/devmode.rs in the gateway crate. Kept in sync by hand because
// the menu-bar app intentionally doesn't depend on the gateway crate (would
// drag in the entire detection pipeline + rules). If you change paths in one
// place, change them here too.

fn is_dev() -> bool {
    matches!(
        std::env::var("BLEEP_DEV").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE")
    )
}

fn stats_port_file() -> &'static str {
    if is_dev() { "/tmp/bleep-stats-dev.port" } else { "/tmp/bleep-stats.port" }
}

fn events_port_file() -> &'static str {
    if is_dev() { "/tmp/bleep-events-dev.port" } else { "/tmp/bleep-events.port" }
}

fn stats_port_range() -> std::ops::RangeInclusive<u16> {
    if is_dev() { 9490..=9499 } else { 9290..=9299 }
}

fn read_port_file(path: &str) -> Option<u16> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

fn read_proxy_stats_port() -> Option<u16> {
    read_port_file(stats_port_file())
}

fn read_proxy_events_port() -> Option<u16> {
    read_port_file(events_port_file())
}

#[tauri::command]
async fn get_stats_port() -> Option<u16> {
    // 1) fast path — port file written by the running gateway
    if let Some(port) = read_proxy_stats_port() {
        return Some(port);
    }
    // 2) recovery path — file is gone but the gateway may still be alive.
    //    Probe the well-known stats range; if anything responds, rewrite the
    //    port file so future calls hit the fast path again. This is the bug
    //    that surfaced when `task gateway:stop` rm'd /tmp/bleep-*.port out
    //    from under a still-running gateway (Bleep.app showed "disconnected"
    //    while the gateway was healthy).
    for port in stats_port_range() {
        if probe_health(port).await {
            let path = stats_port_file();
            if let Err(e) = std::fs::write(path, port.to_string()) {
                eprintln!("[menu-bar] failed to rewrite {path}: {e}");
            } else {
                eprintln!("[menu-bar] recovered stats port {port} → {path}");
            }
            return Some(port);
        }
    }
    None
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

fn status_label(connected: bool) -> &'static str {
    if connected {
        "● Connected to bleep-gateway"
    } else {
        "○ Waiting for bleep-gateway…"
    }
}

/// Build the tray menu ONCE at startup. Returns the assembled Menu plus
/// references to the two dynamic items (header line, status line) so the
/// poller can mutate them in place without ever calling set_menu() again.
fn build_tray_menu(
    app: &AppHandle,
    summary_text: &str,
    connected: bool,
) -> tauri::Result<(Menu<tauri::Wry>, MenuItem<tauri::Wry>, MenuItem<tauri::Wry>)> {
    let header = MenuItem::with_id(app, "header", summary_text, false, None::<&str>)?;
    let status = MenuItem::with_id(app, "status", status_label(connected), false, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let show = MenuItem::with_id(app, "show_main", "Show Bleep…", true, None::<&str>)?;
    let dashboard = MenuItem::with_id(app, "show_dashboard", "Open Dashboard", true, None::<&str>)?;
    let rules = MenuItem::with_id(app, "show_rules", "Rules", true, None::<&str>)?;
    let settings = MenuItem::with_id(app, "show_settings", "Settings", true, None::<&str>)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Bleep", true, Some("Cmd+Q"))?;
    let menu = Menu::with_items(
        app,
        &[
            &header, &status, &sep, &show, &dashboard, &rules, &settings, &sep2, &quit,
        ],
    )?;
    Ok((menu, header, status))
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

fn spawn_poller(_app: AppHandle, tray: TrayIcon, state: Arc<StatsState>) {
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

            // tray title — only set when actually different (cheap dedup)
            let new_title = format_tray_title(&s, connected);
            let title_changed = match state.last_title.lock() {
                Ok(mut g) if *g != new_title => {
                    *g = new_title.clone();
                    true
                }
                _ => false,
            };
            if title_changed {
                let _ = tray.set_title(Some(new_title));
            }

            // tray menu — mutate the two dynamic items IN PLACE rather than
            // rebuilding the menu. Rebuilding swaps the underlying NSMenu and
            // macOS dismisses any open dropdown attached to it.
            if let Ok(g) = state.header_item.lock() {
                if let Some(item) = g.as_ref() {
                    let _ = item.set_text(format_menu_summary(&s));
                }
            }
            if let Ok(g) = state.status_item.lock() {
                if let Some(item) = g.as_ref() {
                    let _ = item.set_text(status_label(connected));
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
    // 1) preferred path: stats port file written by the running gateway.
    if let Some(port) = read_proxy_stats_port() {
        if probe_health(port).await {
            return true;
        }
    }
    // 2) fallback: the port file may have been removed out from under a still-
    //    running gateway (e.g. by an over-eager cleanup task). Probe the
    //    well-known default range directly so we don't spawn a duplicate
    //    that will fail to bind the proxy port and look like a "crash". Range
    //    mirrors stats_server::bind_first_available — prod 9290..=9299, dev 9490..=9499.
    for port in stats_port_range() {
        if probe_health(port).await {
            return true;
        }
    }
    false
}

async fn probe_health(port: u16) -> bool {
    let url = format!("http://127.0.0.1:{port}/health");
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(250))
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
        println!("[menu-bar] spawning gateway: {} (detached)", bin.display());
        // Detach the gateway so it survives the menu-bar:
        //   - own process group → terminal Ctrl+C / SIGINT to the menu-bar's
        //     pgrp doesn't propagate.
        //   - no kill_on_drop / no BLEEP_PARENT_PID watchdog → menu-bar exit
        //     leaves the gateway running.
        //   - stdio redirected to /tmp/bleep-gateway.{out,err}.log INSTEAD of
        //     piping back to the menu-bar. With Stdio::piped() the menu-bar
        //     holds the read end; on menu-bar exit that end closes and the
        //     gateway's next stderr write (TLS chatter is constant) hits
        //     SIGPIPE → process dies. Routing to a file decouples lifetimes
        //     AND keeps logs greppable via `task menu-bar:logs` /
        //     /tmp/bleep-gateway.err.log.
        // Use `task menu-bar:stop` to take everything down explicitly.
        let mut cmd = Command::new(&bin);
        // stdin must also be null — by default Command inherits the parent's
        // stdin which keeps the child tied to the menu-bar's controlling
        // terminal (terminal close → SIGHUP propagates).
        cmd.stdin(std::process::Stdio::null());
        let log_dir = std::path::Path::new("/tmp");
        let stdout_log = log_dir.join("bleep-gateway.out.log");
        let stderr_log = log_dir.join("bleep-gateway.err.log");
        match (
            std::fs::OpenOptions::new().create(true).append(true).open(&stdout_log),
            std::fs::OpenOptions::new().create(true).append(true).open(&stderr_log),
        ) {
            (Ok(o), Ok(e)) => {
                cmd.stdout(std::process::Stdio::from(o))
                    .stderr(std::process::Stdio::from(e));
            }
            _ => {
                // fall back to /dev/null rather than pipe — pipes are the bug
                // we're avoiding. Losing logs is better than killing the
                // gateway.
                eprintln!(
                    "[menu-bar] could not open gateway log files at {}; \
                     redirecting gateway stdio to /dev/null",
                    log_dir.display()
                );
                cmd.stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
            }
        }
        #[cfg(unix)]
        {
            // setsid() starts a brand-new session — fully detaches from the
            // menu-bar's controlling terminal. Without this, SIGHUP propagates
            // session-wide when the terminal (or the parent task) goes away
            // and takes the gateway with it. process_group(0) alone only
            // makes a new pgrp inside the same session — not enough.
            //
            // SAFETY: pre_exec runs between fork() and exec() in the child,
            // before any Rust state is shared. setsid is async-signal-safe.
            unsafe {
                cmd.pre_exec(|| {
                    // ignore EPERM (already a session leader after fork in
                    // some configurations) — falling back to setpgid is fine.
                    let _ = libc::setsid();
                    Ok(())
                });
            }
            cmd.process_group(0);
        }
        let child = cmd.spawn();
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

#[cfg(unix)]
fn spawn_signal_handler(_gateway: Arc<GatewayProcess>) {
    // We deliberately do NOT kill the gateway on signal: the gateway is
    // detached (own process group) and outlives the menu-bar by design.
    // Use `task menu-bar:stop` to take down both explicitly.
    tauri::async_runtime::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
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
        eprintln!("[menu-bar] caught signal, exiting (gateway left running)");
        std::process::exit(0);
    });
}

#[cfg(not(unix))]
fn spawn_signal_handler(_gateway: Arc<GatewayProcess>) {}

// ── live event forwarding ─────────────────────────────────────────────────────

fn spawn_event_forwarder(app: AppHandle) {
    // Reconnect schedule for the same-host event bus. The original 1s→15s
    // exponential backoff dropped 7s+ of events on every gateway restart
    // (events emitted with no subscriber are silently discarded by
    // broadcast::Sender::send). For a loopback TCP connection a fast retry
    // is fine — the gateway only takes ~1s to come back up.
    let initial_backoff = Duration::from_millis(100);
    let max_backoff = Duration::from_secs(1);
    tauri::async_runtime::spawn(async move {
        let mut backoff = initial_backoff;
        loop {
            let port = match read_proxy_events_port() {
                Some(p) => p,
                None => {
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(max_backoff);
                    continue;
                }
            };
            match TcpStream::connect(("127.0.0.1", port)).await {
                Ok(stream) => {
                    backoff = initial_backoff;
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
                    backoff = (backoff * 2).min(max_backoff);
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
        header_item: Mutex::new(None),
        status_item: Mutex::new(None),
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

                let (initial_menu, header_item, status_item) = build_tray_menu(
                    app.handle(),
                    "Today: 0   ·   7d: 0   ·   30d: 0   ·   total: 0",
                    false,
                )?;
                if let Ok(mut g) = state.header_item.lock() {
                    *g = Some(header_item);
                }
                if let Ok(mut g) = state.status_item.lock() {
                    *g = Some(status_item);
                }
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

    app.run(move |app, event| match event {
        // gateway is intentionally not torn down here — it runs detached and
        // is meant to outlive the menu-bar. Stop it via `task menu-bar:stop`.
        // macOS: clicking the dock icon when no windows are visible should reopen.
        RunEvent::Reopen {
            has_visible_windows,
            ..
        } if !has_visible_windows => {
            show_main_window(app);
        }
        _ => {}
    });
}

fn main() {
    run();
}
