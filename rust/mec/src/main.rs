//! Main entry point for the MEC server application

use actix_web::main as actix_main;
use common::Result;
use common::Config;
use crate::discovery::DeviceRegistry;
use std::sync::Arc;
use crate::server::MECServer;
use crate::priority::analyzer::Analyzer;
use crate::encryption::WbAES;
use log::{info, warn, error, LevelFilter};
use env_logger::Builder;
use env_logger::fmt::Color;
use std::io::Write;
use chrono::Local;

mod server;
mod discovery;
mod priority;
mod models;
mod encryption;

const BANNER: &str = r#"
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ███╗   ███╗███████╗ ██████╗                                     ║
║   ████╗ ████║██╔════╝██╔════╝                                     ║
║   ██╔████╔██║█████╗  ██║                                          ║
║   ██║╚██╔╝██║██╔══╝  ██║                                          ║
║   ██║ ╚═╝ ██║███████╗╚██████╗                                     ║
║   ╚═╝     ╚═╝╚══════╝ ╚═════╝                                     ║
║                                                                   ║
║   Mobile Edge Computing Server v1.0.0                             ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
"#;

fn setup_logger() {
    let mut builder = Builder::from_default_env();
    
    builder
        .format(|buf, record| {
            let mut timestamp_style = buf.style();
            let mut level_style = buf.style();
            let mut target_style = buf.style();
            let mut message_style = buf.style();

            let level_color = match record.level() {
                log::Level::Error => Color::Red,
                log::Level::Warn => Color::Yellow,
                log::Level::Info => Color::Green,
                log::Level::Debug => Color::Cyan,
                log::Level::Trace => Color::White,
            };

            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
            writeln!(
                buf,
                "{} {} [{}] {}",
                timestamp_style.set_color(Color::Rgb(100, 100, 100)).value(timestamp),
                level_style.set_color(level_color).value(record.level()),
                target_style.set_color(Color::Blue).value(record.target()),
                message_style.set_color(Color::White).value(record.args())
            )
        })
        .filter(None, LevelFilter::Info)
        .init();
}

#[actix_main]
async fn main() -> Result<()> {
    // Initialize custom logger
    setup_logger();

    // Print banner
    println!("{}", BANNER);
    
    info!("Starting MEC Server...");
    info!("Initializing system components...");

    // Load configuration
    let config = Config::load()?;
    info!("Configuration loaded successfully");
    
    // Create Redis client
    info!("Establishing Redis connection...");
    let redis_client = redis::Client::open(config.redis_url.as_str())
        .map_err(|e| {
            error!("Failed to connect to Redis: {}", e);
            common::DiscoveryError::StorageError(e.to_string())
        })?;
    info!("✓ Redis connection established successfully");
    
    // Create analyzer with Redis client
    info!("Initializing data analyzer...");
    let analyzer = Analyzer::new(
        100,  // history size
        redis_client.clone()
    );
    info!("✓ Data analyzer initialized");
    
    // Create device registry
    info!("Setting up device registry...");
    let device_registry = Arc::new(DeviceRegistry::new(redis_client.clone())?);
    info!("✓ Device registry initialized");
    
    // Create metadata key
    info!("Generating encryption keys...");
    let metadata_key = WbAES::generate_key()?;
    info!("✓ Encryption keys generated successfully");
    
    // Create server instance
    info!("Initializing MEC server instance...");
    let server = MECServer::new(
        analyzer,
        redis_client,
        device_registry,
        metadata_key,
    )?;
    info!("✓ Server instance created successfully");

    // Start server
    info!(" Starting MEC server...");
    server.start().await
}