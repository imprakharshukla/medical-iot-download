//! Priority analysis module for medical sensor data
//! 
//! Provides functionality for analyzing sensor data and metadata to determine
//! processing priority based on various factors including transmission patterns,
//! data volume, and sampling frequency.

use crate::models::{Priority, SensorData};
use common::encryption::EncryptedMetadata;
use parking_lot::RwLock;
#[cfg(not(test))]
use redis::Client as RedisClient;
#[cfg(not(test))]
use redis::aio::MultiplexedConnection;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
#[cfg(not(test))]
use deadpool_redis::{Config, Pool, Runtime};
use chrono::{DateTime, Utc};
use log::{info, warn, error};
use serde::{Deserialize, Serialize};

#[cfg(test)]
use std::time::Duration;
#[cfg(test)]
use std::collections::HashMap as StdHashMap;

/// Metadata about sensor readings without accessing actual values
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReadingMetadata {
    /// Timestamp when the reading was taken
    timestamp: DateTime<Utc>,
    /// Number of readings in the dataset
    reading_count: usize,
    /// Type of sensor data (e.g., "ecg", "blood_pressure")
    data_type: String,
    /// Sampling frequency in Hz (if applicable)
    sampling_frequency: Option<u32>,
    /// Device ID
    device_id: String,
}

impl ReadingMetadata {
    fn new(
        timestamp: DateTime<Utc>,
        reading_count: usize,
        data_type: String,
        sampling_frequency: Option<u32>,
        device_id: String,
    ) -> Self {
        Self {
            timestamp,
            reading_count,
            data_type,
            sampling_frequency,
            device_id,
        }
    }
}

/// Stores historical data for a device
struct DeviceHistory {
    /// Queue of metadata from previous readings
    metadata: VecDeque<ReadingMetadata>,
    /// Map of transmission patterns and their frequencies
    transmission_patterns: HashMap<String, f64>,
}

/// Analyzes sensor data to determine processing priority
pub struct Analyzer {
    /// Thread-safe map of device histories
    device_history: RwLock<HashMap<String, DeviceHistory>>,
    /// Maximum number of historical entries to keep per device
    history_size: usize,
    /// Redis client for persistence
    redis_client: Option<RedisClient>,
    /// Connection pool for Redis
    redis_pool: Option<Pool>,
}

impl Clone for Analyzer {
    fn clone(&self) -> Self {
        Self {
            device_history: RwLock::new(HashMap::new()),
            history_size: self.history_size,
            redis_client: self.redis_client.clone(),
            redis_pool: self.redis_pool.clone(),
        }
    }
}

impl Analyzer {
    /// Creates a new analyzer instance
    /// 
    /// # Arguments
    /// * `history_size` - Maximum number of historical entries to keep per device
    /// * `redis_client` - Redis client for data persistence
    #[cfg(not(test))]
    pub fn new(history_size: usize, redis_client: RedisClient) -> Self {
        let cfg = Config::from_url("redis://127.0.0.1:6000");
        let pool = cfg
            .create_pool(Some(Runtime::Tokio1))
            .expect("Failed to create redis pool");

        Self {
            device_history: RwLock::new(HashMap::new()),
            history_size,
            redis_client: Some(redis_client),
            redis_pool: Some(pool),
        }
    }

    /// Creates a new analyzer instance for testing
    /// 
    /// # Arguments
    /// * `history_size` - Maximum number of historical entries to keep per device
    #[cfg(test)]
    pub fn new(history_size: usize) -> Self {
        Self {
            device_history: RwLock::new(HashMap::new()),
            history_size,
            redis_client: None,
            redis_pool: None,
        }
    }

    /// Analyzes unencrypted sensor data to determine priority
    /// 
    /// # Arguments
    /// * `data` - Sensor data to analyze
    /// 
    /// # Returns
    /// Priority level determined from the analysis
    pub async fn analyze(&self, data: &SensorData) -> Priority {
        let device_id = &data.device_id;
        info!("Starting analysis for device: {}", device_id);
        let metadata = self.extract_metadata(data);
        info!("Extracted metadata for device {}: {:?}", device_id, metadata);

        // Update device history with metadata only
        let mut history_map = self.device_history.write();
        let history = history_map.entry(device_id.clone()).or_insert_with(|| {
            info!("Creating new history for device: {}", device_id);
            DeviceHistory {
                metadata: VecDeque::with_capacity(self.history_size),
                transmission_patterns: HashMap::new(),
            }
        });

        if history.metadata.len() >= self.history_size {
            info!("History full for device {}, removing oldest entry", device_id);
            history.metadata.pop_front();
        }
        history.metadata.push_back(metadata.clone());

        // Calculate priority based on metadata patterns
        let priority_score = self.calculate_priority_from_metadata(device_id, &metadata, history);
        info!("Calculated priority score for device {}: {}", device_id, priority_score);
        drop(history_map);

        // Persist metadata to Redis
        if let Err(e) = self.persist_metadata(device_id, &metadata).await {
            error!("Failed to persist metadata for device {}: {}", device_id, e);
        } else {
            info!("Successfully persisted metadata for device {}", device_id);
        }

        let priority = self.score_to_priority(priority_score);
        info!("Final priority for device {}: {:?}", device_id, priority);
        priority
    }

    /// Analyzes encrypted metadata to determine priority
    /// 
    /// # Arguments
    /// * `metadata` - Encrypted metadata to analyze
    /// 
    /// # Returns
    /// Priority level determined from the metadata
    pub async fn analyze_metadata(&self, metadata: &EncryptedMetadata) -> ReadingMetadata {
        ReadingMetadata {
            timestamp: DateTime::parse_from_rfc3339(&metadata.timestamp)
                .unwrap_or_else(|_| Utc::now().into())
                .with_timezone(&Utc),
            reading_count: metadata.reading_count,
            data_type: metadata.data_type.clone(),
            sampling_frequency: Some(1),
            device_id: metadata.device_id.clone(),
        }
    }

    /// Extracts metadata from sensor data
    fn extract_metadata(&self, data: &SensorData) -> ReadingMetadata {
        ReadingMetadata {
            timestamp: DateTime::parse_from_rfc3339(&data.timestamp)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            reading_count: data.readings.len(),
            data_type: data.type_.clone(),
            sampling_frequency: data.readings.get("sampling_rate")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            device_id: data.device_id.clone(),
        }
    }

    /// Calculates priority score from metadata
    fn calculate_priority_from_metadata(&self, device_id: &str, current: &ReadingMetadata, history: &DeviceHistory) -> f64 {
        // Adjust weights to give more importance to transmission frequency and patterns
        let transmission_weight = 0.6;  // Increased from 0.5
        let volume_weight = 0.2;        // Decreased from 0.3
        let pattern_weight = 0.2;       // Kept same

        let transmission_frequency = self.calculate_transmission_frequency(history);
        let data_volume_score = self.calculate_data_volume_score(current);
        let pattern_score = self.analyze_transmission_pattern(history);

        // Calculate weighted score
        let score = transmission_weight * transmission_frequency +
                    volume_weight * data_volume_score +
                    pattern_weight * pattern_score;

        // Log breakdown as before...
        score
    }

    /// Calculates transmission frequency score
    fn calculate_transmission_frequency(&self, history: &DeviceHistory) -> f64 {
        if history.metadata.len() < 2 {
            return 0.5;
        }

        let latest = history.metadata.back().unwrap();
        let previous = history.metadata.get(history.metadata.len() - 2).unwrap();
        let time_diff = latest.timestamp - previous.timestamp;
        let seconds = time_diff.num_milliseconds() as f64 / 1000.0;
        
        // Adjusted thresholds for more granular scoring
        if seconds < 0.2 { 
            1.0  // Very frequent (< 200ms)
        } else if seconds < 1.0 {
            0.9  // Frequent (< 1s)
        } else if seconds < 5.0 {
            0.8  // Regular fast (< 5s)
        } else if seconds < 15.0 {
            0.7  // Regular medium (< 15s)
        } else if seconds < 30.0 {
            0.5  // Regular slow (< 30s)
        } else if seconds < 60.0 {
            0.3  // Slow (< 1min)
        } else {
            0.2  // Very slow (>= 1min)
        }
    }

    /// Calculates data volume score based on reading count and type
    fn calculate_data_volume_score(&self, metadata: &ReadingMetadata) -> f64 {
        let expected_count = match metadata.data_type.as_str() {
            "ecg" => metadata.sampling_frequency.unwrap_or(250) as usize / 50, // Even more realistic packet size
            "bp" => 2,  // BP typically has systolic and diastolic only
            _ => 10,
        };

        let ratio = metadata.reading_count as f64 / expected_count as f64;
        
        if ratio > 1.2 {
            1.0  // Much more data than expected
        } else if ratio > 0.9 {
            0.8  // Expected amount of data
        } else if ratio > 0.6 {
            0.6  // Slightly less data
        } else if ratio > 0.4 {
            0.4  // Less data than expected
        } else {
            0.2  // Much less data than expected
        }
    }

    /// Analyzes transmission patterns for regularity
    fn analyze_transmission_pattern(&self, history: &DeviceHistory) -> f64 {
        if history.metadata.len() < 3 {
            info!("Insufficient history for pattern analysis. Using default score 0.5");
            return 0.5;
        }

        let mut intervals = Vec::new();
        let metadata_iter = history.metadata.iter().collect::<Vec<_>>();
        
        for i in 1..metadata_iter.len() {
            let time_diff = metadata_iter[i].timestamp - metadata_iter[i-1].timestamp;
            intervals.push(time_diff.num_milliseconds());
        }

        let mean = intervals.iter().sum::<i64>() as f64 / intervals.len() as f64;
        let variance = intervals.iter()
            .map(|&x| (x as f64 - mean).powi(2))
            .sum::<f64>() / intervals.len() as f64;

        let normalized_variance = variance.sqrt() / mean;
        info!(
            "Pattern analysis: mean interval = {:.2}ms, variance = {:.2}, normalized variance = {:.2}",
            mean,
            variance,
            normalized_variance
        );

        let score = if normalized_variance > 0.5 {
            1.0  // Very irregular pattern
        } else if normalized_variance > 0.3 {
            0.8  // Somewhat irregular pattern
        } else if normalized_variance > 0.2 {
            0.6  // Slightly irregular pattern
        } else if normalized_variance > 0.1 {
            0.4  // Regular pattern
        } else {
            0.2  // Very regular pattern
        };

        info!("Pattern score based on variance: {:.2}", score);
        score
    }

    /// Converts a priority score to a Priority enum value
    fn score_to_priority(&self, score: f64) -> Priority {
        match score {
            s if s >= 0.65 => Priority::Critical,  // Adjusted thresholds
            s if s >= 0.45 => Priority::High,
            s if s >= 0.35 => Priority::Medium,
            _ => Priority::Low,
        }
    }

    /// Persists metadata to Redis
    #[cfg(not(test))]
    async fn persist_metadata(&self, device_id: &str, metadata: &ReadingMetadata) -> Result<(), redis::RedisError> {
        if let Some(ref client) = self.redis_client {
            let mut conn = client
                .get_multiplexed_async_connection()
                .await?;

            redis::cmd("SET")
                .arg(format!("metadata:{}", device_id))
                .arg(serde_json::to_string(metadata).map_err(|e| redis::RedisError::from((
                    redis::ErrorKind::IoError,
                    "Serialization error",
                    e.to_string(),
                )))?)
                .query_async::<MultiplexedConnection, ()>(&mut conn)
                .await?;
        }
        Ok(())
    }

    /// Test version of persist_metadata that does nothing
    #[cfg(test)]
    async fn persist_metadata(&self, _device_id: &str, _metadata: &ReadingMetadata) -> Result<(), redis::RedisError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use chrono::Duration;

    /// Helper function to create test sensor data
    fn create_test_data(
        device_id: &str,
        data_type: &str,
        _reading_count: usize,
        sampling_rate: Option<u64>,
        severity: Priority,
    ) -> (SensorData, Priority) {
        let mut readings = StdHashMap::new();
        
        // Add readings based on severity
        match severity {
            Priority::Critical => {
                if data_type == "ecg" {
                    readings.insert("hr".to_string(), serde_json::json!(150));
                    readings.insert("qrs_duration".to_string(), serde_json::json!(120));
                    if let Some(rate) = sampling_rate {
                        readings.insert("sampling_rate".to_string(), serde_json::json!(rate));
                    }
                }
                if data_type == "bp" {
                    readings.insert("systolic".to_string(), serde_json::json!(180));
                    readings.insert("diastolic".to_string(), serde_json::json!(110));
                }
            },
            Priority::High => {
                if data_type == "ecg" {
                    readings.insert("hr".to_string(), serde_json::json!(100));
                    readings.insert("qrs_duration".to_string(), serde_json::json!(100));
                    if let Some(rate) = sampling_rate {
                        readings.insert("sampling_rate".to_string(), serde_json::json!(rate));
                    }
                }
                if data_type == "bp" {
                    readings.insert("systolic".to_string(), serde_json::json!(150));
                    readings.insert("diastolic".to_string(), serde_json::json!(95));
                }
            },
            _ => {
                if data_type == "ecg" {
                    readings.insert("hr".to_string(), serde_json::json!(75));
                    readings.insert("qrs_duration".to_string(), serde_json::json!(80));
                    if let Some(rate) = sampling_rate {
                        readings.insert("sampling_rate".to_string(), serde_json::json!(rate));
                    }
                }
                if data_type == "bp" {
                    readings.insert("systolic".to_string(), serde_json::json!(120));
                    readings.insert("diastolic".to_string(), serde_json::json!(80));
                }
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

    #[tokio::test]
    async fn test_priority_analysis() -> Result<(), Box<dyn std::error::Error>> {
        let analyzer = Analyzer::new(100);

        // Test different transmission patterns
        let test_scenarios = vec![
            // Scenario 1: Rapid, frequent transmissions (Critical)
            ("dev1", "ecg", 1000, Some(250), Duration::milliseconds(100), 5),
            
            // Scenario 2: Regular but frequent transmissions (High)
            ("dev2", "bp", 3, None, Duration::seconds(5), 5),
            
            // Scenario 3: Irregular pattern with varying intervals (High)
            ("dev3", "ecg", 500, Some(250), Duration::seconds(0), 5), // Will use varying intervals
            
            // Scenario 4: Regular, normal interval transmissions (Medium)
            ("dev4", "bp", 3, None, Duration::seconds(30), 5),
            
            // Scenario 5: Infrequent transmissions (Low)
            ("dev5", "ecg", 250, Some(250), Duration::seconds(60), 5),
        ];

        let mut results = vec![];

        for (device_id, data_type, reading_count, sampling_rate, base_interval, transmissions) in test_scenarios {
            println!("\n=== Testing {} device: {} ===", data_type, device_id);
            println!("Base interval: {:?}, Transmissions: {}", base_interval, transmissions);
            
            let mut last_priority = None;
            
            // Send multiple transmissions with the specified pattern
            for i in 0..transmissions {
                let mut data = create_test_data(
                    device_id,
                    data_type,
                    reading_count,
                    sampling_rate,
                    Priority::Low, // Initial priority doesn't matter for this test
                ).0;
                
                // For irregular pattern (dev3), vary the intervals
                if device_id == "dev3" {
                    let varying_delays = vec![100, 1000, 5000, 100, 30000]; // milliseconds
                    thread::sleep(std::time::Duration::from_millis(varying_delays[i]));
                } else {
                    // Add some random variation to the base interval (±10%)
                    let variation = if base_interval.num_milliseconds() > 0 {
                        let base_ms = base_interval.num_milliseconds() as f64;
                        let variation = base_ms * 0.1 * (rand::random::<f64>() - 0.5);
                        Duration::milliseconds(variation as i64)
                    } else {
                        Duration::milliseconds(0)
                    };
                    
                    thread::sleep(std::time::Duration::from_millis(
                        (base_interval + variation).num_milliseconds() as u64
                    ));
                }
                
                // Update timestamp to reflect actual time
                data.timestamp = Utc::now().to_rfc3339();
                
                let priority = analyzer.analyze(&data).await;
                last_priority = Some(priority);
                
                println!("Transmission {}/{}: Priority = {:?}", i + 1, transmissions, priority);
            }
            
            if let Some(final_priority) = last_priority {
                results.push((device_id, final_priority));
            }
        }

        // Verify results
        println!("\n=== Final Results ===");
        let mut correct_predictions = 0;
        let expected_priorities = vec![
            ("dev1", Priority::Critical),  // Rapid transmissions
            ("dev2", Priority::High),      // Frequent, regular transmissions
            ("dev3", Priority::High),      // Irregular pattern
            ("dev4", Priority::Medium),    // Regular, normal interval
            ("dev5", Priority::Low),       // Infrequent transmissions
        ];

        for ((device_id, actual), (_, expected)) in results.iter().zip(expected_priorities.iter()) {
            println!("Device: {}, Expected: {:?}, Got: {:?}", device_id, expected, actual);
            if actual == expected {
                correct_predictions += 1;
                println!("✅ Correct prediction");
            } else {
                println!("❌ Incorrect prediction");
            }
        }

        let accuracy = (correct_predictions as f64 / results.len() as f64) * 100.0;
        println!("\nOverall accuracy: {:.2}%", accuracy);
        
        assert!(accuracy >= 70.0, "Accuracy {:.2}% below acceptable threshold of 70%", accuracy);
        Ok(())
    }
}