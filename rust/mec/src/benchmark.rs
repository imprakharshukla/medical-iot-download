use crate::models::{SensorData, Priority, EncryptedSensorData};
use crate::server::MECServer;
use crate::encryption::WbAES;
use chrono::Utc;
use common::{Result, DiscoveryError};
use log::{info, debug, warn};
use serde_json::json;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct BenchmarkMetrics {
    pub sensor_count: usize,
    pub accuracy: f64,
    pub throughput_kbps: f64,
    pub total_data_processed: usize,
    pub processing_time: Duration,
    pub encryption_time: Duration,
    pub decryption_time: Duration,
}

async fn simulate_sensor_data(
    data: &SensorData,
    encryption_key: &WbAES,
) -> Result<EncryptedSensorData> {
    // Create metadata
    let metadata = json!({
        "timestamp": data.timestamp,
        "type": data.type_,
        "device_id": data.device_id,
        "reading_count": data.readings.len(),
    });

    info!("Encrypting data for device {}", data.device_id);
    debug!("Original metadata: {:?}", metadata);
    debug!("Original readings: {:?}", data.readings);

    // Encrypt metadata and payload
    let encrypted_metadata = encryption_key.encrypt(&serde_json::to_vec(&metadata)?)?;
    let encrypted_payload = encryption_key.encrypt(&serde_json::to_vec(&data.readings)?)?;

    debug!("Encrypted metadata size: {} bytes", encrypted_metadata.len());
    debug!("Encrypted payload size: {} bytes", encrypted_payload.len());

    Ok(EncryptedSensorData {
        device_id: data.device_id.clone(),
        encrypted_metadata,
        encrypted_payload,
    })
}

pub async fn run_benchmark(
    server: &MECServer,
    sensor_count: usize,
    duration: Duration
) -> Result<BenchmarkMetrics> {
    info!("Starting benchmark with {} sensors for {:?}", sensor_count, duration);
    let start = Instant::now();
    let mut total_bytes = 0;
    let mut correct_predictions = 0;
    let mut total_predictions = 0;
    let mut total_encryption_time = Duration::from_secs(0);
    let mut total_decryption_time = Duration::from_secs(0);

    // Get encryption key
    let encryption_key = server.get_metadata_key();
    info!("Got encryption key from server");

    // Generate test data
    info!("Generating test data for {} sensors...", sensor_count);
    let test_data: Vec<SensorData> = generate_test_data(sensor_count);
    
    info!("Beginning benchmark loop...");
    while start.elapsed() < duration {
        for data in &test_data {
            // Encrypt data
            let encryption_start = Instant::now();
            let encrypted_data = simulate_sensor_data(data, encryption_key).await?;
            total_encryption_time += encryption_start.elapsed();
            
            // Process through server
            let decryption_start = Instant::now();
            let actual_priority = server.process_encrypted_data(&encrypted_data).await?;
            total_decryption_time += decryption_start.elapsed();
            
            let expected_priority = calculate_expected_priority(data);
            let data_size = serde_json::to_vec(&encrypted_data)?.len();

            // Store metrics
            if actual_priority == expected_priority {
                correct_predictions += 1;
            }
            total_predictions += 1;
            total_bytes += data_size;

            debug!("Processed device {} - Priority: {:?}, Size: {} bytes", 
                data.device_id, actual_priority, data_size);
        }
    }

    // Log detailed metrics
    let elapsed = start.elapsed();
    let accuracy = (correct_predictions as f64 / total_predictions as f64) * 100.0;
    let throughput = (total_bytes as f64 * 8.0) / (elapsed.as_secs_f64() * 1000.0); // Kbps

    info!("Benchmark completed:");
    info!("- Duration: {:?}", elapsed);
    info!("- Total predictions: {}", total_predictions);
    info!("- Correct predictions: {}", correct_predictions);
    info!("- Accuracy: {:.2}%", accuracy);
    info!("- Throughput: {:.2} Kbps", throughput);
    info!("- Average encryption time: {:?}", total_encryption_time / total_predictions as u32);
    info!("- Average decryption time: {:?}", total_decryption_time / total_predictions as u32);
    info!("- Total data processed: {} bytes", total_bytes);

    Ok(BenchmarkMetrics {
        sensor_count,
        accuracy,
        throughput_kbps: throughput,
        total_data_processed: total_bytes,
        processing_time: elapsed,
        encryption_time: total_encryption_time,
        decryption_time: total_decryption_time,
    })
}

fn generate_test_data(sensor_count: usize) -> Vec<SensorData> {
    let mut data = Vec::with_capacity(sensor_count);
    
    // Generate different types of medical data scenarios
    for i in 0..sensor_count {
        let mut readings = HashMap::new();
        
        // Simulate different medical scenarios based on sensor index
        let (value, priority_level) = match i % 5 {
            0 => (75.0, "normal"),     // Normal heart rate
            1 => (175.0, "critical"),  // Dangerously high heart rate
            2 => (40.0, "critical"),   // Dangerously low heart rate
            3 => (145.0, "high"),      // High but not critical
            4 => (55.0, "high"),       // Low but not critical
            _ => unreachable!()
        };

        // Add more context to readings
        readings.insert("value".to_string(), json!(value));
        readings.insert("timestamp".to_string(), json!(Utc::now().to_rfc3339()));
        readings.insert("priority_level".to_string(), json!(priority_level));
        readings.insert("type".to_string(), json!("heart_rate"));
        readings.insert("unit".to_string(), json!("bpm"));
        readings.insert("normal_range_min".to_string(), json!(60));
        readings.insert("normal_range_max".to_string(), json!(100));
        readings.insert("critical_range_min".to_string(), json!(45));
        readings.insert("critical_range_max".to_string(), json!(165));

        data.push(SensorData {
            device_id: format!("test_device_{}", i),
            type_: "ecg".to_string(),
            readings,
            timestamp: Utc::now().to_rfc3339(),
        });
    }
    
    info!("Generated test data with following scenarios:");
    info!("- Normal readings: {}", data.iter().filter(|d| d.readings.get("priority_level").unwrap().as_str().unwrap() == "normal").count());
    info!("- High priority readings: {}", data.iter().filter(|d| d.readings.get("priority_level").unwrap().as_str().unwrap() == "high").count());
    info!("- Critical readings: {}", data.iter().filter(|d| d.readings.get("priority_level").unwrap().as_str().unwrap() == "critical").count());
    
    data
}

fn calculate_expected_priority(data: &SensorData) -> Priority {
    if let Some(value) = data.readings.get("value").and_then(|v| v.as_f64()) {
        let normal_min = data.readings.get("normal_range_min").and_then(|v| v.as_i64()).unwrap_or(60) as f64;
        let normal_max = data.readings.get("normal_range_max").and_then(|v| v.as_i64()).unwrap_or(100) as f64;
        let critical_min = data.readings.get("critical_range_min").and_then(|v| v.as_i64()).unwrap_or(45) as f64;
        let critical_max = data.readings.get("critical_range_max").and_then(|v| v.as_i64()).unwrap_or(165) as f64;
        
        match value {
            // Critical conditions
            v if v >= critical_max || v <= critical_min => {
                debug!("Value {} is in critical range [{}, {}]", value, critical_min, critical_max);
                Priority::High
            },
            // High priority conditions
            v if v > normal_max || v < normal_min => {
                debug!("Value {} is outside normal range [{}, {}]", value, normal_min, normal_max);
                Priority::High
            },
            // Normal conditions
            _ => {
                debug!("Value {} is in normal range [{}, {}]", value, normal_min, normal_max);
                Priority::Low
            }
        }
    } else {
        warn!("No value found in readings, defaulting to High priority due to potential data issue");
        Priority::High
    }
}

async fn inspect_redis_data(server: &MECServer) -> Result<()> {
    let mut conn = server.redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    let device_ids: Vec<String> = redis::cmd("SMEMBERS")
        .arg("active_devices")
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    info!("Found {} devices in Redis", device_ids.len());

    for device_id in device_ids {
        // Get encrypted data
        let encrypted_key = format!("device:{}:encrypted", device_id);
        let encrypted_data: Vec<String> = redis::cmd("LRANGE")
            .arg(&encrypted_key)
            .arg(0)
            .arg(5)  // Get latest 5 readings
            .query_async(&mut conn)
            .await
            .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

        info!("Latest {} encrypted readings for device {}", encrypted_data.len(), device_id);
        for data in encrypted_data {
            debug!("Encrypted data: {}", data);
        }
    }

    Ok(())
}