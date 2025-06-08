use std::io::Write;
use anyhow::Result;
use log::{LevelFilter, debug, info};
use env_logger::Builder;
use chrono::Local;

pub fn init() -> Result<()> {
    let mut builder = Builder::new();

    // Get log level from environment
    let log_level = std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
    let level = match log_level.to_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info,
    };

    builder
        .format(|buf, record| {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
            writeln!(
                buf,
                "[{}] [{}] [{}:{}] {}",
                timestamp,
                record.level(),
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                record.args()
            )
        })
        .filter(None, level);

    // Check if we should log to a file
    if let Ok(log_file) = std::env::var("LOG_FILE") {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file.clone())?;

        // Split logging to both the console and the file
        builder.target(env_logger::Target::Pipe(Box::new(file)));
        info!("Logging to file: {}", log_file);
    }

    builder.init();

    debug!("Logger initialized with level: {}", log_level);
    Ok(())
}