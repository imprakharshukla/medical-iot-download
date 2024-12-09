use mec_server::benchmark::run_benchmark;
use mec_server::server::MECServer;
use mec_server::priority::analyzer::Analyzer;
use mec_server::discovery::DeviceRegistry;
use mec_server::encryption::WbAES;
use common::{Result, DiscoveryError};
use std::time::Duration;
use redis::Client as RedisClient;
use std::sync::Arc;
use env_logger::Env;
use log::{info, debug, warn, error};
use chrono::Local;
use std::env;

async fn setup_server() -> Result<MECServer> {
    info!("Setting up benchmark server...");
    
    info!("Connecting to Redis...");
    let redis_client = RedisClient::open("redis://127.0.0.1:6379")
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;
    
    info!("Initializing analyzer...");    
    let analyzer = Analyzer::new(100, redis_client.clone());
    
    info!("Setting up device registry...");
    let device_registry = Arc::new(DeviceRegistry::new(redis_client.clone())?);
    
    info!("Generating encryption keys...");
    let metadata_key = WbAES::generate_key()?;

    info!("Creating MEC server instance...");
    let server = MECServer::new(
        analyzer,
        redis_client,
        device_registry,
        metadata_key,
    )?;
    
    info!("Server setup complete!");
    Ok(server)
}

async fn inspect_redis_data(server: &MECServer) -> Result<()> {
    let mut conn = server.redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    // Get all device IDs
    let device_ids: Vec<String> = redis::cmd("SMEMBERS")
        .arg("active_devices")
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    info!("Found {} devices in Redis", device_ids.len());

    for device_id in device_ids {
        // Get device info
        let info_key = format!("device:{}:info", device_id);
        let info: Option<String> = redis::cmd("GET")
            .arg(&info_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

        if let Some(info) = info {
            info!("Device {}: {}", device_id, info);
        }

        // Get latest readings
        let readings_key = format!("readings:{}", device_id);
        let readings: Vec<String> = redis::cmd("LRANGE")
            .arg(&readings_key)
            .arg(0)
            .arg(5)  // Get latest 5 readings
            .query_async(&mut conn)
            .await
            .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

        info!("Latest {} readings for device {}", readings.len(), device_id);
        for reading in readings {
            debug!("Reading: {}", reading);
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logger with timestamp
    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .format(|buf, record| {
            use std::io::Write;
            writeln!(
                buf,
                "{} [{}] {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .init();

    info!("Starting MEC System Benchmarks...");
    
    // Start Redis if not running
    info!("Checking Redis connection...");
    if let Err(e) = RedisClient::open("redis://127.0.0.1:6379")
        .and_then(|client| client.get_connection()) {
        error!("Redis not running: {}. Please start Redis first.", e);
        return Ok(());
    }

    let server = setup_server().await?;
    let sensor_counts = vec![5, 10, 15, 20];
    let duration = match std::env::var("BENCHMARK_DURATION") {
        Ok(secs) => Duration::from_secs(secs.parse().unwrap_or(10)),
        Err(_) => Duration::from_secs(10), // Default to 10 seconds
    };

    let batch_delay = env::var("BATCH_DELAY_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);

    let parallel = env::var("PARALLEL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(true);

    info!("Benchmark Configuration:");
    info!("- Test duration per sensor count: {:?}", duration);
    info!("- Sensor counts to test: {:?}", sensor_counts);
    info!("- Total estimated duration: {:?}", duration.mul_f32(sensor_counts.len() as f32));
    info!("- Batch delay: {}ms", batch_delay);
    info!("- Parallel processing: {}", parallel);

    println!("Starting MEC System Benchmarks...");
    println!("Testing with sensor counts: {:?}", sensor_counts);

    let mut results = Vec::new();
    for &sensor_count in &sensor_counts {
        println!("\nRunning benchmark with {} sensors...", sensor_count);
        match run_benchmark(&server, sensor_count, duration).await {
            Ok(metrics) => {
                results.push(metrics);
                println!("✓ Completed benchmark for {} sensors", sensor_count);
                
                // Inspect Redis data
                if let Err(e) = inspect_redis_data(&server).await {
                    error!("Failed to inspect Redis data: {}", e);
                }
            }
            Err(e) => eprintln!("✗ Benchmark failed for {} sensors: {}", sensor_count, e),
        }
    }

    // Print results in table format
    println!("\nAccuracy Results:");
    println!("Sensors\tAccuracy (%)");
    println!("------------------------");
    for result in &results {
        println!("{}\t{:.2}", result.sensor_count, result.accuracy);
    }

    println!("\nThroughput Results:");
    println!("Sensors\tThroughput (Kbps)");
    println!("------------------------");
    for result in &results {
        println!("{}\t{:.2}", result.sensor_count, result.throughput_kbps);
    }

    Ok(())
} 