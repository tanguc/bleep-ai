use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactedEntry {
    pub rule_id: String,
    pub category: String,
    pub subcategory: String,
    pub severity: String,
    /// substituted fake value — safe for TUI and event bus; original NOT sent here
    pub fake_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProxyEvent {
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
        if let Err(e) = std::fs::write("/tmp/bleep-events.port", port.to_string()) {
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
    for port in 9191u16..=9200 {
        match TcpListener::bind(("127.0.0.1", port)).await {
            Ok(l) => return l,
            Err(_) => continue,
        }
    }
    panic!("event_bus: no available port in range 9191-9200");
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
