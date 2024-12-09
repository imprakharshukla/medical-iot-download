//! HTTP request handlers for the MEC server
//! 
//! Provides handlers for data ingestion and device management endpoints.

use crate::models::{EncryptedSensorData, Priority, SensorData};
use actix_web::{web, HttpResponse, Result as ActixResult, Responder};
use log::{error, info, debug, warn};
use super::MECServer;
use crate::encryption::error::EncryptionError;
use std::error::Error;
use serde_json::json;
use common::DeviceInfo;
use crate::discovery::DeviceRegistry;
use common::encryption::EncryptedMetadata;
use common::encryption::handshake::{HandshakeRequest, HandshakeResponse};
use ed25519_dalek::{Keypair, Signer};
use rand::{Rng, rngs::OsRng};
use chrono::Utc;
use rand::RngCore;
use std::collections::HashMap;
use chrono::DateTime;
use std::sync::{Arc, RwLock};
use common::{DiscoveryPacket, Result, DiscoveryError};
use actix_web::post;
use redis::RedisError;

/// Handles ingestion of raw (unencrypted) sensor data
/// 
/// # Arguments
/// * `data` - JSON payload containing sensor data
/// * `server` - Shared server instance
pub async fn ingest_data(
    data: web::Json<SensorData>,
    server: web::Data<MECServer>,
) -> ActixResult<HttpResponse> {
    info!("Received raw data from device: {} of type: {}", data.device_id, data.type_);
    info!("Number of readings: {}", data.readings.len());

    match process_data(&server, &data).await {
        Ok(_) => {
            info!("Successfully processed data from device {}. Type: {}", data.device_id, data.type_);
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "status": "success"
            })))
        }
        Err(e) => {
            error!("Error processing data for device {}: {:?}", data.device_id, e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            })))
        }
    }
}

/// Returns a list of currently connected devices
pub async fn get_connected_devices(
    server: web::Data<MECServer>,
) -> Result<HttpResponse> {
    let mut conn = server.redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    // Get all active device IDs
    let device_ids: Vec<String> = redis::cmd("SMEMBERS")
        .arg("active_devices")
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    // Get device info
    let mut device_list = Vec::new();
    for device_id in device_ids {
        let info_key = format!("device:{}:info", device_id);
        let info: Option<String> = redis::cmd("GET")
            .arg(&info_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

        if let Some(info_str) = info {
            if let Ok(info) = serde_json::from_str::<serde_json::Value>(&info_str) {
                device_list.push(info);
            }
        }
    }

    Ok(HttpResponse::Ok().json(device_list))
}

/// Processes incoming sensor data
/// 
/// # Arguments
/// * `server` - Server instance
/// * `data` - Sensor data to process
async fn process_data(
    server: &MECServer,
    data: &SensorData,
) -> Result<()> {
    let priority = server.analyzer.analyze(data).await;

    /* add a log here */
    info!("Processing data for device: {}", data.device_id);
    
    // Create device info JSON
    let device_info = serde_json::json!({
        "type": data.type_,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "priority": priority.as_str(),
        "device_id": data.device_id,
        "capabilities": data.readings.keys().collect::<Vec<_>>(),
        "last_seen": chrono::Utc::now().to_rfc3339(),
        "status": "Online"
    });

    // Create readings JSON
    let readings_data = serde_json::json!({
        "timestamp": data.timestamp.clone(),
        "readings": data.readings,
    });

    let mut conn = server.redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    // Store device info
    let info_key = format!("device:{}:info", data.device_id);
    redis::cmd("SET")
        .arg(&info_key)
        .arg(device_info.to_string())
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    // Store readings in a list with proper key format
    let readings_key = format!("readings:{}", data.device_id);
    
    // Add to the beginning of the list (newest first)
    redis::cmd("LPUSH")
        .arg(&readings_key)
        .arg(readings_data.to_string())
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    // Trim list to keep last 100 readings
    redis::cmd("LTRIM")
        .arg(&readings_key)
        .arg(0)
        .arg(99)
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    // Add to active devices set
    redis::cmd("SADD")
        .arg("active_devices")
        .arg(&data.device_id)
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    // Set expiry on device info (5 minutes)
    redis::cmd("EXPIRE")
        .arg(&info_key)
        .arg(300)
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    // Set expiry on readings (24 hours)
    redis::cmd("EXPIRE")
        .arg(&readings_key)
        .arg(24 * 60 * 60)
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    info!("Stored reading at key: {}", readings_key);
    let length: i64 = redis::cmd("LLEN")
        .arg(&readings_key)
        .query_async(&mut conn)
        .await
        .unwrap_or(-1);
    info!("Current history length: {}", length);

    Ok(())
}

/// Handles ingestion of encrypted sensor data
pub async fn ingest_encrypted_data(
    data: web::Json<EncryptedSensorData>,
    server: web::Data<MECServer>,
) -> Result<HttpResponse> {
    info!("Received encrypted data from device: {}", data.device_id);
    info!("Encrypted payload size: {} bytes", data.encrypted_payload.len());
    info!("Encrypted metadata size: {} bytes", data.encrypted_metadata.len());

    // Decrypt metadata for analysis
    let decrypted_metadata = match server.key_pair.metadata_key.decrypt(&data.encrypted_metadata) {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to decrypt metadata: {}", e);
            return Ok(HttpResponse::InternalServerError().json(json!({
                "error": format!("Metadata decryption error: {}", e)
            })));
        }
    };

    let metadata: EncryptedMetadata = match serde_json::from_slice::<EncryptedMetadata>(&decrypted_metadata) {
        Ok(data) => {
            info!("Decrypted metadata - Count: {}", data.reading_count);
            data
        },
        Err(e) => {
            error!("Failed to parse metadata: {}", e);
            return Ok(HttpResponse::InternalServerError().json(json!({
                "error": format!("Metadata parsing error: {}", e)
            })));
        }
    };

    // Create device info
    let device_info = json!({
        "device_id": data.device_id,
        "type": metadata.data_type,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "capabilities": [
            "heartRate",
            "bloodPressure", 
            "bodyTemperature",
            "spo2",
            "respiratoryRate"
        ],
        "last_seen": chrono::Utc::now().to_rfc3339(),
        "status": "Online"
    });

    // Update in-memory connected devices
    server.connected_devices.write().insert(
        data.device_id.clone(),
        device_info.clone()
    );

    // Store device info in Redis
    let mut conn = server.redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;
    
    // Store in active devices set
    redis::cmd("SADD")
        .arg("active_devices")
        .arg(&data.device_id)
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    // Store device info with expiry
    let device_info_key = format!("device:{}:info", data.device_id);
    redis::cmd("SET")
        .arg(&device_info_key)
        .arg(device_info.to_string())
        .arg("EX")
        .arg(300)
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    // Store encrypted data with a timestamp-based key
    let timestamp = chrono::Utc::now().timestamp_millis();
    let data_key = format!("device:{}:data:{}", data.device_id, timestamp);
    
    info!("Storing encrypted data at key: {}", data_key);
    
    // Store the encrypted data
    redis::cmd("HSET")
        .arg(&data_key)
        .arg("metadata")
        .arg(&data.encrypted_metadata)
        .arg("payload") 
        .arg(&data.encrypted_payload)
        .arg("timestamp")
        .arg(timestamp.to_string())
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    // Add to device-specific timeline
    let device_timeline_key = format!("timeline:{}", data.device_id);
    info!("Adding to device timeline: {}", device_timeline_key);
    
    redis::cmd("ZADD")
        .arg(&device_timeline_key)
        .arg(timestamp as f64)
        .arg(&data_key)
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    // Add to global timeline
    info!("Adding to global timeline");
    redis::cmd("ZADD")
        .arg("timeline:global")
        .arg(timestamp as f64)
        .arg(&data_key)
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    // Set TTL for the data
    redis::cmd("EXPIRE")
        .arg(&data_key)
        .arg(24 * 3600) // 24 hours
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    // Set TTL for the device timeline
    redis::cmd("EXPIRE")
        .arg(&device_timeline_key)
        .arg(24 * 3600) // 24 hours
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    // Verify timeline entry was added
    let timeline_length: i64 = redis::cmd("ZCARD")
        .arg(&device_timeline_key)
        .query_async(&mut conn)
        .await
        .unwrap_or(-1);
    
    info!("Current timeline length for device {}: {}", data.device_id, timeline_length);

    info!("Decrypted metadata - Type: {}, Count: {}", metadata.data_type, metadata.reading_count);

    // For logging only - decrypt payload
    if log::log_enabled!(log::Level::Debug) {
        match server.key_pair.payload_key.decrypt(&data.encrypted_payload) {
            Ok(decrypted_data) => {
                match serde_json::from_slice::<SensorData>(&decrypted_data) {
                    Ok(reading) => {
                        debug!("Decrypted reading: {:?}", reading);
                        // Process the reading
                        let priority = server.analyzer.analyze(&reading).await;
                        info!("Analyzed reading - Priority: {:?}", priority);
                    }
                    Err(e) => warn!("Failed to parse decrypted payload: {}", e),
                }
            }
            Err(e) => warn!("Failed to decrypt payload for logging: {}", e),
        }
    }

    Ok(HttpResponse::Ok().json(json!({
        "status": "success",
        "device_id": data.device_id
    })))
}

/// Stores encrypted data in Redis
async fn store_encrypted_data(
    server: &MECServer,
    data: &EncryptedSensorData,
    priority: Priority,
) -> Result<()> {
    let timestamp = chrono::Utc::now().to_rfc3339();
    
    // Decrypt the payload for storage
    let decrypted_payload = server.key_pair.payload_key.decrypt(&data.encrypted_payload)
        .map_err(|e| DiscoveryError::SecurityError(e.to_string()))?;
    
    let sensor_data: SensorData = serde_json::from_slice(&decrypted_payload)
        .map_err(|e| DiscoveryError::SerializationError(e.to_string()))?;

    // Create readings JSON
    let readings_data = serde_json::json!({
        "timestamp": timestamp,
        "readings": sensor_data.readings,
    });

    let mut conn = server.redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;
    
    // Store device info
    let info_key = format!("device:{}:info", data.device_id);
    let device_info = serde_json::json!({
        "type": sensor_data.type_,
        "timestamp": timestamp,
        "priority": priority.as_str(),
        "device_id": data.device_id,
        "capabilities": sensor_data.readings.keys().collect::<Vec<_>>(),
        "last_seen": timestamp,
        "status": "Online"
    });

    // Store device info
    redis::cmd("SET")
        .arg(&info_key)
        .arg(device_info.to_string())
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    info!("Stored device info for {}", data.device_id);

    // Store readings in a list
    let readings_key = format!("readings:{}", data.device_id);
    
    // Add to the beginning of the list (newest first)
    redis::cmd("LPUSH")
        .arg(&readings_key)
        .arg(readings_data.to_string())
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    // Trim list to keep last 100 readings
    redis::cmd("LTRIM")
        .arg(&readings_key)
        .arg(0)
        .arg(99)
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    info!("Stored readings for {}", data.device_id);

    // Add to active devices set
    redis::cmd("SADD")
        .arg("active_devices")
        .arg(&data.device_id)
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    // Set TTL for device info (5 minutes)
    redis::cmd("EXPIRE")
        .arg(&info_key)
        .arg(300)
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    // Set TTL for readings (24 hours)
    redis::cmd("EXPIRE")
        .arg(&readings_key)
        .arg(24 * 60 * 60)
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    // Log the current history length
    let length: i64 = redis::cmd("LLEN")
        .arg(&readings_key)
        .query_async(&mut conn)
        .await
        .unwrap_or(-1);
    info!("Current history length for device {}: {}", data.device_id, length);

    Ok(())
}

/// Verifies that data was properly stored in Redis
pub async fn verify_redis_storage(server: &MECServer, device_id: &str) -> Result<bool> {
    let mut conn = server.redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;
    
    let info_key = format!("device_info:{}", device_id);
    let payload_key = format!("device_payload:{}", device_id);
    
    // Check if both info and payload exist
    let info_exists: bool = redis::cmd("EXISTS")
        .arg(&info_key)
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;
        
    let payload_exists: bool = redis::cmd("EXISTS")
        .arg(&payload_key)
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    if info_exists && payload_exists {
        // Get the device info
        let info: String = redis::cmd("GET")
            .arg(&info_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

        log::info!("Stored info for device {}: {}", device_id, info);
        Ok(true)
    } else {
        log::info!("Missing data in Redis for device {} (info: {}, payload: {})", 
            device_id, info_exists, payload_exists);
        Ok(false)
    }
}

pub async fn get_status(server: web::Data<MECServer>) -> impl Responder {
    match server.check_redis_connection().await {
        Ok(_) => HttpResponse::Ok().json(json!({
            "status": "ok",
            "timestamp": chrono::Utc::now().timestamp(),
            "services": {
                "redis": "healthy",
                "server": "healthy"
            }
        })),
        Err(_) => HttpResponse::Ok().json(json!({
            "status": "error",
            "timestamp": chrono::Utc::now().timestamp(),
            "services": {
                "redis": "unhealthy",
                "server": "healthy"
            }
        }))
    }
}

pub async fn get_encryption_key(server: web::Data<MECServer>) -> impl Responder {
    match server.key_pair.metadata_key.get_key() {
        Some(key) => HttpResponse::Ok().body(key),
        None => HttpResponse::InternalServerError().body("Key not initialized"),
    }
}

pub async fn get_devices(server: web::Data<MECServer>) -> Result<HttpResponse> {
    let mut conn = server.redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;
    
    let device_ids: Vec<String> = redis::cmd("SMEMBERS")
        .arg("active_devices")
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    let mut device_list = Vec::new();
    let now = Utc::now();

    for device_id in device_ids {
        let info_key = format!("device:{}:info", device_id);
        let info: Option<String> = redis::cmd("GET")
            .arg(&info_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

        if let Some(info_str) = info {
            if let Ok(info) = serde_json::from_str::<serde_json::Value>(&info_str) {
                // Check last_seen timestamp
                if let Some(last_seen) = info.get("last_seen").and_then(|t| t.as_str()) {
                    if let Ok(last_seen_time) = DateTime::parse_from_rfc3339(last_seen) {
                        let duration = now.signed_duration_since(last_seen_time.with_timezone(&Utc));
                        
                        // If device hasn't been seen in last 30 seconds, mark as offline
                        let status = if duration.num_seconds() > 30 {
                            // Remove from active devices set
                            let _: () = redis::cmd("SREM")
                                .arg("active_devices")
                                .arg(&device_id)
                                .query_async(&mut conn)
                                .await
                                .unwrap_or(());
                            "Offline"
                        } else {
                            "Online"
                        };

                        device_list.push(json!({
                            "device_id": device_id,
                            "device_type": info.get("type").and_then(|t| t.as_str()).unwrap_or("unknown"),
                            "status": status,
                            "last_seen": last_seen,
                            "capabilities": info.get("capabilities").and_then(|c| c.as_array())
                                .map(|arr| arr.iter()
                                    .filter_map(|v| v.as_str())
                                    .collect::<Vec<_>>())
                                .unwrap_or_default()
                        }));
                    }
                }
            }
        }
    }

    Ok(HttpResponse::Ok().json(device_list))
}

pub async fn get_device(
    registry: web::Data<DeviceRegistry>,
    device_id: web::Path<String>,
) -> impl Responder {
    match registry.get_device(&device_id).await {
        Ok(Some(device)) => HttpResponse::Ok().json(device),
        Ok(None) => HttpResponse::NotFound().finish(),
        Err(e) => HttpResponse::InternalServerError().json(e.to_string()),
    }
}

pub async fn update_device(
    registry: web::Data<DeviceRegistry>,
    device_id: web::Path<String>,
    device_info: web::Json<DeviceInfo>,
) -> impl Responder {
    match registry.register_device(device_info.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(e.to_string()),
    }
}

pub async fn handle_handshake(
    request: web::Json<HandshakeRequest>,
    server: web::Data<MECServer>,
) -> Result<HttpResponse> {
    // Verify timestamp to prevent replay attacks
    let now = Utc::now().timestamp();
    if (now - request.timestamp).abs() > 300 {
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": "Invalid timestamp"
        })));
    }

    // Generate server random using RngCore trait
    let mut rng = OsRng;
    let mut server_random = vec![0u8; 32];
    rng.fill_bytes(&mut server_random);

    // Get current key version
    let active_key = server.key_pair.get_active_key();

    // Create response message
    let mut message = Vec::new();
    message.extend(&server_random);
    message.extend(&request.client_random);
    message.extend(&active_key.version.to_le_bytes());
    message.extend(&now.to_le_bytes());

    // Sign the message
    let signature = server.signing_key.sign(&message);

    let response = HandshakeResponse {
        server_random,
        selected_version: 1,
        encrypted_key: active_key.key.get_key().unwrap_or_default(),
        key_version: active_key.version,
        signature: signature.to_bytes().to_vec(),
        timestamp: now,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Fetches and decrypts data for a specific device
pub async fn get_device_data(
    device_id: web::Path<String>,
    server: web::Data<MECServer>,
) -> Result<HttpResponse> {
    let mut conn = server.redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;
    
    // Get device timeline entries (last 100 entries)
    let device_timeline_key = format!("timeline:{}", device_id);
    let data_keys: Vec<String> = redis::cmd("ZREVRANGE")
        .arg(&device_timeline_key)
        .arg(0)
        .arg(99)  // Get last 100 readings
        .query_async(&mut conn)
        .await
        .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

    let mut readings = Vec::new();

    for key in data_keys {
        // Get encrypted data from Redis
        let data: HashMap<String, Vec<u8>> = redis::cmd("HGETALL")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

        if let (Some(encrypted_payload), Some(timestamp_bytes)) = (data.get("payload"), data.get("timestamp")) {
            // Decrypt payload
            if let Ok(decrypted_data) = server.key_pair.payload_key.decrypt(encrypted_payload) {
                if let Ok(sensor_data) = serde_json::from_slice::<SensorData>(&decrypted_data) {
                    // Convert timestamp bytes to string
                    let timestamp = String::from_utf8_lossy(timestamp_bytes);
                    
                    // Create reading entry in the format expected by the frontend
                    let reading = json!({
                        "timestamp": chrono::Utc::now().timestamp_millis().to_string(),
                        "readings": sensor_data.readings
                    });
                    
                    readings.push(reading);
                }
            }
        }
    }

    Ok(HttpResponse::Ok().json(json!({
        "device_id": device_id.to_string(),
        "readings": readings
    })))
}


#[post("/api/devices/announce")]
pub async fn announce_device(
    device_registry: web::Data<DeviceRegistry>,
    announcement: web::Json<DiscoveryPacket>,
) -> impl Responder {
    info!("Received device announcement from {}", announcement.device_info.device_id);

    match device_registry.register_device(announcement.device_info.clone()).await {
        Ok(_) => {
            info!("Successfully registered device {}", announcement.device_info.device_id);
            HttpResponse::Ok().finish()
        }
        Err(e) => {
            error!("Failed to register device: {}", e);
            HttpResponse::InternalServerError().json(e.to_string())
        }
    }
}