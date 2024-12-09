#![allow(unused_imports)]
#![allow(unused_variables)]

use mec_server::priority::analyzer::Analyzer;
use mec_server::models::{Priority, SensorData};
use chrono::Utc;
use redis::Client as RedisClient;
use std::collections::HashMap as StdHashMap;
use tokio;
use log::{info, debug};
use env_logger;
use std::time::Duration;
use rand::Rng;
use std::thread;

#[tokio::test]
async fn test_priority_analysis() -> Result<(), Box<dyn std::error::Error>> {
    let redis_client = RedisClient::open("redis://127.0.0.1:6379").unwrap();
    let analyzer = Analyzer::new(100, redis_client);
    let is_quick_test = std::env::var("QUICK_TEST").is_ok();
    let reduced_devices = std::env::var("REDUCED_DEVICES").is_ok();

    // Test different transmission patterns
    let test_scenarios = if is_quick_test {
        println!("Running in QUICK TEST mode");
        vec![
            // Quick scenarios with shorter intervals and fewer transmissions
            ("dev1", "ecg", 1000, Some(250), Duration::from_millis(100), 2, Priority::Critical),
            ("dev2", "ecg", 200, Some(250), Duration::from_millis(500), 2, Priority::High),
            ("dev3", "ecg", 200, Some(250), Duration::from_secs(1), 2, Priority::High),
            ("dev4", "ecg", 100, Some(250), Duration::from_secs(2), 2, Priority::Medium),
            ("dev5", "ecg", 50, Some(250), Duration::from_secs(3), 2, Priority::Low),
        ]
    } else {
        let full_scenarios = vec![
            // Full test scenarios with longer intervals and more transmissions
            ("dev1", "ecg", 1000, Some(250), Duration::from_millis(100), 5, Priority::Critical),
            ("dev2", "ecg", 200, Some(250), Duration::from_secs(2), 5, Priority::High),
            ("dev3", "ecg", 200, Some(250), Duration::from_secs(5), 5, Priority::High),
            ("dev4", "ecg", 100, Some(250), Duration::from_secs(20), 5, Priority::Medium),
            ("dev5", "ecg", 50, Some(250), Duration::from_secs(60), 5, Priority::Low),
        ];

        if reduced_devices {
            println!("Running in REDUCED FULL TEST mode (3 devices)");
            // Take only first 3 devices (Critical and High priorities)
            full_scenarios.into_iter().take(3).collect()
        } else {
            println!("Running in FULL TEST mode (all devices)");
            full_scenarios
        }
    };

    let mut results = vec![];

    for (device_id, data_type, reading_count, sampling_rate, interval, transmissions, expected_priority) in test_scenarios {
        println!("\n=== Testing {} device: {} ===", data_type, device_id);
        println!("Base interval: {:?}, Transmissions: {}", interval, transmissions);
        println!("Expected Priority: {:?}", expected_priority);
        
        let mut last_priority = None;
        
        // Send multiple transmissions with the specified pattern
        for i in 0..transmissions {
            let mut data = create_test_data(
                device_id,
                data_type,
                reading_count,
                sampling_rate,
                expected_priority,
            ).0;
            
            // For irregular pattern (dev3), vary the intervals
            if device_id == "dev3" {
                let varying_delays = if is_quick_test {
                    vec![100, 500] // Shorter delays for quick test
                } else {
                    vec![100, 1000, 5000, 100, 30000]
                };
                thread::sleep(std::time::Duration::from_millis(varying_delays[i]));
            } else {
                // Add some random variation to the base interval (±10%)
                let variation = if interval.as_millis() > 0 {
                    let base_ms = interval.as_millis() as f64;
                    let variation = base_ms * 0.1 * (rand::random::<f64>() - 0.5);
                    Duration::from_millis(variation as u64)
                } else {
                    Duration::from_millis(0)
                };
                
                thread::sleep(interval + variation);
            }
            
            // Update timestamp to reflect actual time
            data.timestamp = Utc::now().to_rfc3339();
            
            let priority = analyzer.analyze(&data).await;
            last_priority = Some(priority);
            
            println!("Transmission {}/{}: Priority = {:?}", i + 1, transmissions, priority);
        }
        
        if let Some(final_priority) = last_priority {
            results.push((device_id, final_priority, expected_priority));
        }
    }

    // Verify results
    println!("\n=== Final Results ===");
    let mut correct_predictions = 0;
    let total_results = results.len();

    for (device_id, actual, expected) in results {
        println!("Device: {}", device_id);
        println!("  Expected: {:?}", expected);
        println!("  Actual  : {:?}", actual);
        if actual == expected {
            correct_predictions += 1;
            println!("  ✅ Correct prediction");
        } else {
            println!("  ❌ Incorrect prediction");
        }
    }

    let accuracy = (correct_predictions as f64 / total_results as f64) * 100.0;
    println!("\nOverall accuracy: {:.2}%", accuracy);
    
    assert!(accuracy >= 70.0, "Accuracy {:.2}% below acceptable threshold of 70%", accuracy);
    Ok(())
}

/// Helper function to create test sensor data
fn create_test_data(
    device_id: &str,
    data_type: &str,
    reading_count: usize,
    sampling_rate: Option<u64>,
    severity: Priority,
) -> (SensorData, Priority) {
    let mut readings = StdHashMap::new();
    
    match (data_type, &severity) {
        // ECG readings based on priority
        ("ecg", Priority::Critical) => {
            readings.insert("hr".to_string(), serde_json::json!(180));  // Very high heart rate
            readings.insert("qrs_duration".to_string(), serde_json::json!(140));  // Abnormal QRS
            if let Some(rate) = sampling_rate {
                readings.insert("sampling_rate".to_string(), serde_json::json!(rate));
            }
            // Add more readings to match expected volume
            for i in 0..reading_count.saturating_sub(3) {
                readings.insert(format!("sample_{}", i), serde_json::json!(i));
            }
        },
        ("ecg", Priority::High) => {
            readings.insert("hr".to_string(), serde_json::json!(120));  // Elevated heart rate
            readings.insert("qrs_duration".to_string(), serde_json::json!(110));  // Slightly abnormal QRS
            if let Some(rate) = sampling_rate {
                readings.insert("sampling_rate".to_string(), serde_json::json!(rate));
            }
            // Add moderate number of readings
            for i in 0..(reading_count / 2).saturating_sub(3) {  // Half the readings for High priority
                readings.insert(format!("sample_{}", i), serde_json::json!(i));
            }
        },
        ("ecg", Priority::Medium) => {
            readings.insert("hr".to_string(), serde_json::json!(90));  // Slightly elevated heart rate
            readings.insert("qrs_duration".to_string(), serde_json::json!(95));  // Normal QRS
            if let Some(rate) = sampling_rate {
                readings.insert("sampling_rate".to_string(), serde_json::json!(rate));
            }
            // Add fewer readings
            for i in 0..(reading_count / 4).saturating_sub(3) {  // Quarter the readings for Medium priority
                readings.insert(format!("sample_{}", i), serde_json::json!(i));
            }
        },
        ("ecg", _) => {  // Low priority
            readings.insert("hr".to_string(), serde_json::json!(75));  // Normal heart rate
            readings.insert("qrs_duration".to_string(), serde_json::json!(80));  // Normal QRS
            if let Some(rate) = sampling_rate {
                readings.insert("sampling_rate".to_string(), serde_json::json!(rate));
            }
            // Add minimal readings
            for i in 0..(reading_count / 8).saturating_sub(3).min(5) {  // Minimal readings for Low priority
                readings.insert(format!("sample_{}", i), serde_json::json!(i));
            }
        },
        ("bp", Priority::Critical) => {
            readings.insert("systolic".to_string(), serde_json::json!(180));
            readings.insert("diastolic".to_string(), serde_json::json!(110));
            readings.insert("pulse".to_string(), serde_json::json!(120));
        },
        ("bp", Priority::High) => {
            readings.insert("systolic".to_string(), serde_json::json!(150));
            readings.insert("diastolic".to_string(), serde_json::json!(95));
            readings.insert("pulse".to_string(), serde_json::json!(95));
        },
        ("bp", Priority::Medium) => {
            readings.insert("systolic".to_string(), serde_json::json!(135));
            readings.insert("diastolic".to_string(), serde_json::json!(85));
            readings.insert("pulse".to_string(), serde_json::json!(75));
        },
        ("bp", _) => {
            readings.insert("systolic".to_string(), serde_json::json!(120));
            readings.insert("diastolic".to_string(), serde_json::json!(80));
            readings.insert("pulse".to_string(), serde_json::json!(72));
        },
        // Catch-all for any other data type
        (_, _) => {
            readings.insert("value".to_string(), serde_json::json!(0));
        }
    }

    let data = SensorData {
        device_id: device_id.to_string(),
        type_: data_type.to_string(),
        timestamp: Utc::now().to_rfc3339(),
        readings,
    };

    (data, severity)
} 