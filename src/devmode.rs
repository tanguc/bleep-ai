//! Dev-mode port partitioning.
//!
//! Set `BLEEP_DEV=1` to make a gateway (and a menu-bar that spawns it) use a
//! parallel port range and parallel port files. Lets a dev gateway coexist
//! with an installed Bleep.app without colliding on :9190 / /tmp/bleep-*.port.
//!
//! Prod (default):
//!   proxy 9190, events 9191..=9200, stats 9290..=9299,
//!   /tmp/bleep-stats.port, /tmp/bleep-events.port
//!
//! Dev (BLEEP_DEV=1):
//!   proxy 9390, events 9391..=9400, stats 9490..=9499,
//!   /tmp/bleep-stats-dev.port, /tmp/bleep-events-dev.port

use std::ops::RangeInclusive;

pub fn is_dev() -> bool {
    matches!(
        std::env::var("BLEEP_DEV").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE")
    )
}

pub fn default_proxy_port() -> u16 {
    if is_dev() { 9390 } else { 9190 }
}

pub fn events_port_range() -> RangeInclusive<u16> {
    if is_dev() { 9391..=9400 } else { 9191..=9200 }
}

pub fn stats_port_range() -> RangeInclusive<u16> {
    if is_dev() { 9490..=9499 } else { 9290..=9299 }
}

pub fn stats_port_file() -> &'static str {
    if is_dev() {
        "/tmp/bleep-stats-dev.port"
    } else {
        "/tmp/bleep-stats.port"
    }
}

pub fn events_port_file() -> &'static str {
    if is_dev() {
        "/tmp/bleep-events-dev.port"
    } else {
        "/tmp/bleep-events.port"
    }
}
