use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};
use std::io::{self, BufRead, BufReader};
use std::net::TcpStream;
use tracing::{debug, info, warn};

// Wire types from the shared crate — single source of truth across
// gateway/TUI/GUI. Previously this file mirrored RedactedEntry by hand
// using `matched_text` instead of `fake_value`, so the TUI had been
// silently failing to parse events ever since the gateway field was
// renamed.
use bleep_events::{ProxyEvent, RedactedEntry};

// flat display entry used by the UI
struct DisplayEntry {
    id: String,
    ts: String,
    method: String,
    uri: String,
    redacted: Vec<RedactedEntry>,
}

#[derive(PartialEq)]
enum ViewMode {
    List,
    Detail,
}

struct App {
    events: Vec<DisplayEntry>,
    list_state: ListState,
    detail_state: ListState,
    mode: ViewMode,
    reader: Option<BufReader<TcpStream>>,
    connected: bool,
    last_reconnect: std::time::Instant,
}

impl App {
    fn new() -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));

        let (reader, connected) = match connect_to_bus() {
            Ok(stream) => (Some(BufReader::new(stream)), true),
            Err(_) => (None, false),
        };

        Self {
            events: Vec::new(),
            list_state,
            detail_state: ListState::default(),
            mode: ViewMode::List,
            reader,
            connected,
            last_reconnect: std::time::Instant::now(),
        }
    }

    fn try_reconnect(&mut self) {
        // only attempt every 2 seconds
        if self.last_reconnect.elapsed().as_secs() < 1 {
            return;
        }
        self.last_reconnect = std::time::Instant::now();

        if let Ok(stream) = connect_to_bus() {
            self.reader = Some(BufReader::new(stream));
            self.connected = true;
        }
    }

    fn poll_events(&mut self) {
        if !self.connected {
            self.try_reconnect();
            return;
        }

        let Some(reader) = self.reader.as_mut() else {
            return;
        };

        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    // server closed connection
                    warn!("server closed connection");
                    self.connected = false;
                    self.reader = None;
                    break;
                }
                Ok(_) => {
                    let line = line.trim_end();
                    if line.is_empty() {
                        continue;
                    }
                    if let Ok(ev) = serde_json::from_str::<ProxyEvent>(line) {
                        // only display requests, skip responses for now
                        if let Some(entry) = proxy_event_to_display(ev) {
                            self.events.push(entry);
                            let last = self.events.len().saturating_sub(1);
                            if self.list_state.selected().is_none() {
                                self.list_state.select(Some(last));
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    // connection lost
                    warn!("connection lost: {e}");
                    self.connected = false;
                    self.reader = None;
                    break;
                }
            }
        }
    }

    fn selected_event(&self) -> Option<&DisplayEntry> {
        self.list_state.selected().and_then(|i| self.events.get(i))
    }

    fn selected_redacted_count(&self) -> usize {
        self.selected_event().map_or(0, |e| e.redacted.len())
    }

    fn list_next(&mut self) {
        let i = self
            .list_state
            .selected()
            .map(|i| {
                if i >= self.events.len().saturating_sub(1) {
                    i
                } else {
                    i + 1
                }
            })
            .unwrap_or(0);
        self.list_state.select(Some(i));
    }

    fn list_prev(&mut self) {
        let i = self
            .list_state
            .selected()
            .map(|i| i.saturating_sub(1))
            .unwrap_or(0);
        self.list_state.select(Some(i));
    }

    fn detail_next(&mut self) {
        let max = self.selected_redacted_count().saturating_sub(1);
        let i = self
            .detail_state
            .selected()
            .map(|i| if i >= max { i } else { i + 1 })
            .unwrap_or(0);
        self.detail_state.select(Some(i));
    }

    fn detail_prev(&mut self) {
        let i = self
            .detail_state
            .selected()
            .map(|i| i.saturating_sub(1))
            .unwrap_or(0);
        self.detail_state.select(Some(i));
    }

    fn enter_detail(&mut self) {
        if self.selected_redacted_count() > 0 {
            self.detail_state.select(Some(0));
            self.mode = ViewMode::Detail;
        }
    }

    fn exit_detail(&mut self) {
        self.mode = ViewMode::List;
    }
}

fn connect_to_bus() -> io::Result<TcpStream> {
    let port_str = std::fs::read_to_string(bleep_gateway::devmode::events_port_file())?;
    let port: u16 = port_str
        .trim()
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid port"))?;
    debug!("connecting to 127.0.0.1:{port}");
    let stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_nonblocking(true)?;
    info!("connected to 127.0.0.1:{port}");
    Ok(stream)
}

// returns None for Response events (filtered out)
fn proxy_event_to_display(ev: ProxyEvent) -> Option<DisplayEntry> {
    match ev {
        ProxyEvent::Request { id, ts, method, uri, redacted } => Some(DisplayEntry {
            id,
            ts,
            method,
            uri,
            redacted,
        }),
        // responses disabled for now
        ProxyEvent::Response { .. } => None,
    }
}

fn init_logging() {
    let file_appender = tracing_appender::rolling::never("/tmp", "bleep-tui.log");
    tracing_subscriber::fmt()
        .with_writer(file_appender)
        .with_ansi(false)
        .with_target(false)
        .init();
}

fn main() -> io::Result<()> {
    init_logging();
    info!("tui starting");

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let app = App::new();
    let result = run(&mut terminal, app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, mut app: App) -> io::Result<()> {
    loop {
        app.poll_events();
        terminal.draw(|f| ui(f, &mut app))?;

        if event::poll(std::time::Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                debug!("key event: code={:?} kind={:?}", key.code, key.kind);

                // handle Esc regardless of key kind (some terminals report it differently)
                if key.code == KeyCode::Esc {
                    match app.mode {
                        ViewMode::List => return Ok(()),
                        ViewMode::Detail => { app.exit_detail(); continue; }
                    }
                }

                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match app.mode {
                    ViewMode::List => match key.code {
                        KeyCode::Char('q') => return Ok(()),
                        KeyCode::Down | KeyCode::Char('j') => app.list_next(),
                        KeyCode::Up | KeyCode::Char('k') => app.list_prev(),
                        KeyCode::Enter => app.enter_detail(),
                        _ => {}
                    },
                    ViewMode::Detail => match key.code {
                        KeyCode::Backspace | KeyCode::Left | KeyCode::Enter => app.exit_detail(),
                        KeyCode::Down | KeyCode::Char('j') => app.detail_next(),
                        KeyCode::Up | KeyCode::Char('k') => app.detail_prev(),
                        KeyCode::Char('q') => return Ok(()),
                        _ => {}
                    },
                }
            }
        }
    }
}

fn ui(f: &mut ratatui::Frame, app: &mut App) {
    match app.mode {
        ViewMode::List => ui_list(f, app),
        ViewMode::Detail => ui_detail(f, app),
    }
}

fn ui_list(f: &mut ratatui::Frame, app: &mut App) {
    let has_preview = app
        .selected_event()
        .is_some_and(|e| !e.redacted.is_empty());

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(if has_preview {
            vec![
                Constraint::Length(3),  // header
                Constraint::Min(8),     // traffic list
                Constraint::Length(8),  // preview panel
                Constraint::Length(3),  // status bar
            ]
        } else {
            vec![
                Constraint::Length(3), // header
                Constraint::Min(8),    // traffic list
                Constraint::Length(0), // no preview
                Constraint::Length(3), // status bar
            ]
        })
        .split(f.area());

    render_header(f, chunks[0]);

    // -- traffic list --
    let items: Vec<ListItem> = app
        .events
        .iter()
        .map(|e| {
            let redact_count = if e.redacted.is_empty() {
                String::new()
            } else {
                format!("  [{} redacted]", e.redacted.len())
            };

            let style = if !e.redacted.is_empty() {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::Green)
            };

            ListItem::new(Line::from(Span::styled(
                format!(" {} {} >>> {} {}{}", &e.id[..8], e.ts, e.method, e.uri, redact_count),
                style,
            )))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().title(" Traffic ").borders(Borders::ALL))
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .bg(Color::DarkGray),
        )
        .highlight_symbol("► ");

    f.render_stateful_widget(list, chunks[1], &mut app.list_state);

    // -- preview panel (shows when selected row has redactions) --
    if has_preview {
        let event = app.selected_event().unwrap();
        let mut lines: Vec<Line> = Vec::new();

        for entry in &event.redacted {
            let severity_color = match entry.severity.as_str() {
                "high" => Color::Red,
                "medium" => Color::Yellow,
                _ => Color::White,
            };

            lines.push(Line::from(vec![
                Span::styled("  Rule: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    &entry.rule_id,
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                ),
                Span::styled("    Severity: ", Style::default().fg(Color::DarkGray)),
                Span::styled(&entry.severity, Style::default().fg(severity_color)),
                Span::styled("    Fake: ", Style::default().fg(Color::DarkGray)),
                Span::styled(&entry.fake_value, Style::default().fg(Color::Red)),
            ]));
        }

        let preview = Paragraph::new(lines)
            .block(Block::default().title(" Preview ").borders(Borders::ALL));
        f.render_widget(preview, chunks[2]);
    }

    render_status_bar(f, app, chunks[3], " q: quit  up/down: scroll  enter: details");
}

fn ui_detail(f: &mut ratatui::Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header
            Constraint::Length(3),  // request summary
            Constraint::Min(6),    // matched rules list (scrollable)
            Constraint::Length(3), // status bar
        ])
        .split(f.area());

    render_header(f, chunks[0]);

    // grab selected index to avoid borrowing app through selected_event()
    let sel_idx = match app.list_state.selected() {
        Some(i) if i < app.events.len() => i,
        _ => {
            app.mode = ViewMode::List;
            return;
        }
    };

    // -- request summary --
    let event = &app.events[sel_idx];
    let summary = Paragraph::new(Line::from(vec![
        Span::styled(" ", Style::default()),
        Span::styled(&event.ts, Style::default().fg(Color::DarkGray)),
        Span::styled("  >>>  ", Style::default().fg(Color::White)),
        Span::styled(
            format!("{} {}", event.method, event.uri),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  ({} redacted)", event.redacted.len()),
            Style::default().fg(Color::Red),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(summary, chunks[1]);

    // -- matched rules as scrollable list via ListState --
    let rule_items: Vec<ListItem> = app.events[sel_idx]
        .redacted
        .iter()
        .map(|entry| {
            let severity_color = match entry.severity.as_str() {
                "high" => Color::Red,
                "medium" => Color::Yellow,
                _ => Color::White,
            };

            ListItem::new(vec![
                Line::from(vec![
                    Span::styled("  Rule: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        &entry.rule_id,
                        Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("    Severity: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&entry.severity, Style::default().fg(severity_color)),
                    Span::styled("    Category: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&entry.category, Style::default().fg(Color::Cyan)),
                ]),
                Line::from(vec![
                    Span::styled("  Fake: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&entry.fake_value, Style::default().fg(Color::Red)),
                ]),
                Line::raw(""),
            ])
        })
        .collect();

    let rules_list = List::new(rule_items)
        .block(Block::default().title(" Matched Rules ").borders(Borders::ALL))
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .bg(Color::DarkGray),
        )
        .highlight_symbol("► ");

    f.render_stateful_widget(rules_list, chunks[2], &mut app.detail_state);

    render_status_bar(f, app, chunks[3], " esc: back  up/down: scroll rules  q: quit");
}

fn render_header(f: &mut ratatui::Frame, area: ratatui::layout::Rect) {
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " bleep ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  proxy monitor"),
    ]))
    .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(header, area);
}

fn render_status_bar(f: &mut ratatui::Frame, app: &App, area: ratatui::layout::Rect, keys: &str) {
    let total_requests = app.events.len();
    let total_redacted: usize = app.events.iter().map(|e| e.redacted.len()).sum();

    let (proxy_label, proxy_color) = if app.connected {
        ("connected", Color::Green)
    } else {
        ("reconnecting...", Color::Yellow)
    };

    let status = Paragraph::new(Line::from(vec![
        Span::styled(" proxy: ", Style::default().fg(Color::DarkGray)),
        Span::styled(proxy_label, Style::default().fg(proxy_color)),
        Span::styled("  |  requests: ", Style::default().fg(Color::DarkGray)),
        Span::styled(total_requests.to_string(), Style::default().fg(Color::White)),
        Span::styled("  |  redactions: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            total_redacted.to_string(),
            Style::default().fg(if total_redacted > 0 {
                Color::Red
            } else {
                Color::Green
            }),
        ),
        Span::styled(
            format!("  |{keys}"),
            Style::default().fg(Color::DarkGray),
        ),
    ]))
    .block(Block::default().borders(Borders::TOP));
    f.render_widget(status, area);
}
