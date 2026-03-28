mod content_router;
mod detection;
mod event_bus;
mod hudsucker;
mod logging;
mod patterns;
mod proxy;
mod replacement;
mod request_logger;
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
    /// port to listen on (0 = ephemeral)
    #[arg(short, long, default_value_t = 9190)]
    port: u16,

    /// path for JSONL log output
    #[arg(long, default_value = "bleep.jsonl")]
    log_file: String,

    /// minimum confidence level for detections: low | medium | high (default: low)
    #[arg(long, default_value = "low", value_name = "LEVEL")]
    min_confidence: String,

    /// print open source license attributions and exit
    #[arg(long)]
    licenses: bool,
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

    tracing_subscriber::fmt::init();

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
