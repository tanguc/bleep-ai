mod content_router;
mod detection;
mod devmode;
mod event_bus;
mod hudsucker;
mod logging;
mod patterns;
mod perf;
mod proxy;
mod replacement;
mod request_logger;
mod stats;
mod stats_server;
mod types;

use clap::Parser;

use crate::hudsucker::run_hudsucker;

#[derive(Parser)]
#[command(
    name = "bleep-gateway",
    version,
    about = "Bleep AI gateway - day-1 pass-through proxy"
)]
struct Cli {
    /// port to listen on (0 = ephemeral). default flips to 9390 when BLEEP_DEV=1.
    #[arg(short, long, default_value_t = devmode::default_proxy_port())]
    port: u16,

    /// path for JSONL log output (default: ~/.bleep/bleep.jsonl)
    #[arg(long, default_value_t = default_log_file())]
    log_file: String,

    /// minimum confidence level for detections: low | medium | high (default: low)
    #[arg(long, default_value = "low", value_name = "LEVEL")]
    min_confidence: String,

    /// print open source license attributions and exit
    #[arg(long)]
    licenses: bool,
}

fn default_log_file() -> String {
    match std::env::var_os("HOME") {
        Some(home) => std::path::PathBuf::from(home)
            .join(".bleep")
            .join("bleep.jsonl")
            .to_string_lossy()
            .into_owned(),
        None => "bleep.jsonl".to_string(),
    }
}

#[tokio::main]
async fn main() {
    let _cli = Cli::parse();

    if _cli.licenses {
        println!("{}", crate::patterns::ATTRIBUTION);
        let rule_count = crate::patterns::get_normalized_rules().len();
        println!("\nLoaded {} detection rules.", rule_count);
        return;
    }

    // mute rustls/hyper/hudsucker TLS handshake chatter by default — those crates
    // emit a flood of DEBUG lines per request that drown out our own logs.
    // override with RUST_LOG (e.g. RUST_LOG=rustls=debug) when actually
    // debugging TLS. NOTE: crate name in tracing targets is `bleep_gateway`
    // (hyphens become underscores).
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(
            "info,\
             bleep_gateway=debug,\
             rustls=off,\
             hyper=warn,\
             hyper_util=warn,\
             hudsucker=warn,\
             h2=warn,\
             tower_http=warn,\
             tokio_util=warn"
        ));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // log panics without aborting the process. Tokio already isolates panics
    // per-task (a panic in one request handler doesn't kill the runtime), but
    // the default panic hook prints to stderr in a format that's easy to miss
    // in mixed log output. This makes them grep-able and confirms which
    // task/thread panicked so a hung request can be traced back.
    std::panic::set_hook(Box::new(|info| {
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "<unknown>".into());
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
            .unwrap_or("<non-string panic payload>");
        let thread = std::thread::current()
            .name()
            .unwrap_or("<unnamed>")
            .to_string();
        eprintln!("[bleep] PANIC at {loc} on thread '{thread}': {msg} — request task isolated, gateway continues");
    }));

    run_hudsucker(_cli.port, _cli.log_file.clone(), _cli.min_confidence.clone()).await;

    // let app_state = types::AppState {
    //     client: reqwest::Client::new(),
    //     log_file: _cli.log_file,
    // };

    // let app = axum::Router::new()
    //     .route("/{*path}", axum::routing::any(proxy::proxy_handler))
    //     .with_state(app_state);

    // // TODO: build shared app state (api_key, log writer, http client)
    // // TODO: build axum router with routes
    // // TODO: bind listener and print actual port
    // // TODO: serve

    // info!("Starting bleep-gateway on port {}", _cli.port);

    // let listener = tokio::net::TcpListener::bind(("0.0.0.0", _cli.port))
    //     .await
    //     .unwrap();
    // axum::serve(listener, app).await.unwrap();

    // axum::serve::
}
