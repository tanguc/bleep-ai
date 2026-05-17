use std::sync::OnceLock;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::broadcast;

// Wire types come from the shared crate so the TUI and the GUI can
// pull from the same definitions and not silently drift.
pub use bleep_events::{ProxyEvent, RedactedEntry};

static BUS: OnceLock<broadcast::Sender<ProxyEvent>> = OnceLock::new();

pub fn init() {
    let (tx, _rx) = broadcast::channel(1000);
    // if already initialized, ignore
    let _ = BUS.set(tx);
}

pub fn emit(event: ProxyEvent) {
    if let Some(tx) = BUS.get() {
        let _ = tx.send(event);
    }
}

pub fn subscribe() -> broadcast::Receiver<ProxyEvent> {
    BUS.get()
        .expect("event_bus::init() must be called before subscribe()")
        .subscribe()
}

pub fn start_tcp_server() {
    tokio::spawn(async move {
        let listener = bind_first_available().await;
        let local_addr = listener.local_addr().expect("failed to get local addr");
        let port = local_addr.port();

        // use std::fs (sync) to ensure file is written before anything else runs
        if let Err(e) = std::fs::write(crate::devmode::events_port_file(), port.to_string()) {
            eprintln!("event_bus: failed to write port file: {e}");
        }
        eprintln!("event_bus: listening on 127.0.0.1:{port}");

        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let rx = subscribe();
                    tokio::spawn(handle_client(stream, rx, peer.to_string()));
                }
                Err(e) => {
                    eprintln!("event_bus: accept error: {e}");
                }
            }
        }
    });
}

async fn bind_first_available() -> TcpListener {
    let range = crate::devmode::events_port_range();
    let (start, end) = (*range.start(), *range.end());
    for port in range {
        match TcpListener::bind(("127.0.0.1", port)).await {
            Ok(l) => return l,
            Err(_) => continue,
        }
    }
    panic!("event_bus: no available port in range {start}-{end}");
}

async fn handle_client(
    mut stream: tokio::net::TcpStream,
    mut rx: broadcast::Receiver<ProxyEvent>,
    peer: String,
) {
    loop {
        match rx.recv().await {
            Ok(event) => {
                let mut line = match serde_json::to_string(&event) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("event_bus: serialize error for {peer}: {e}");
                        continue;
                    }
                };
                line.push('\n');
                if stream.write_all(line.as_bytes()).await.is_err() {
                    // client disconnected
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                eprintln!("event_bus: client {peer} lagged, dropped {n} events");
            }
            Err(broadcast::error::RecvError::Closed) => {
                break;
            }
        }
    }
}
