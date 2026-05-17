//! `build-rules` — regenerate `rules/combined.yaml` from vendor sources.
//!
//! Replaces the old `build.rs` script. Run explicitly via `cargo run --bin build-rules`.

use bleep_gateway::rule_pipeline::{run, RunOptions};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "build-rules",
    version,
    about = "Regenerate rules/combined.yaml from vendor sources"
)]
struct Cli {
    /// Truncate the final ruleset to N rules (dev iteration — fast startup)
    #[arg(long, value_name = "N")]
    limit: Option<usize>,

    /// Suppress progress output
    #[arg(short, long)]
    quiet: bool,
}

fn main() {
    let cli = Cli::parse();
    let opts = RunOptions {
        max_rules: cli.limit,
        quiet: cli.quiet,
    };

    let result = run(&opts);

    if !cli.quiet {
        println!();
        println!("=== rule_pipeline summary ===");
        println!("  gitleaks rules    : {}", result.gitleaks_rules);
        println!("  spdb rules        : {}", result.spdb_rules);
        println!("  nosey-parker rules: {}", result.np_rules);
        println!("  hand-authored     : {}", result.ha_rules);
        println!("  custom            : {}", result.custom_rules);
        println!("  total (after merge): {}", result.total_rules);
        println!("  output            : {}", result.combined_path);
        println!("  fixtures          : {}", result.fixtures_path);
    }
}
