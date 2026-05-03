// library crate root — exposes modules for integration testing
pub mod content_router;
pub mod detection;
pub mod patterns;
pub mod replacement;
pub mod rule_pipeline;
pub mod stats;
pub mod types;

// internal modules not exposed externally
mod event_bus;
mod hudsucker;
mod logging;
mod proxy;
mod request_logger;
