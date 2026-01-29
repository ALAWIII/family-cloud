//! Development : "family_cloud=debug,warn"
//!
//! Production  : "family_cloud=info,warn"
///
use once_cell::sync::OnceCell;
use tracing::subscriber::set_global_default;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling;
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_log::LogTracer;
use tracing_subscriber::{
    EnvFilter, Registry,
    fmt::{self},
    layer::SubscriberExt,
};

static GUARD: OnceCell<WorkerGuard> = OnceCell::new();

pub fn init_tracing(app_name: &str, env_filter: &str, logs_directory: &str) -> anyhow::Result<()> {
    LogTracer::init()?;

    // RUST_LOG env variable
    let env_filter = EnvFilter::try_from_default_env().unwrap_or(EnvFilter::new(env_filter));

    // ---- file json logger ------ server-logs
    let file_appender = rolling::daily(logs_directory, "server.log");
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
    GUARD.set(guard).expect("Failed to set guard logger.");

    let bunyan_layer = BunyanFormattingLayer::new(app_name.into(), file_writer); // Converts tracing events/spans into structured JSON. Writes JSON to file via file_writer.

    // ---- stdout json logger ----
    let stdout_layer = fmt::layer().json(); // Emits JSON logs to stdout

    // ---- build subscriber ONCE ----
    let subscriber = Registry::default()
        .with(env_filter)
        .with(JsonStorageLayer)
        .with(bunyan_layer) // json → file
        .with(stdout_layer); // json → stdout

    set_global_default(subscriber)?;
    Ok(())
}
