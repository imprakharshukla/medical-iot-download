use common::types::{DeviceInfo, DeviceStatus};
use common::{DiscoveryError, Result};
use redis::Client as RedisClient;
use redis::aio::MultiplexedConnection;
use std::sync::Arc;
use chrono::Utc;
use log::{info, error};
use serde_json;

pub struct DeviceRegistry {
    redis_client: Arc<RedisClient>,
}

impl DeviceRegistry {
    pub fn new(redis_client: RedisClient) -> Result<Self> {
        Ok(Self {
            redis_client: Arc::new(redis_client),
        })
    }

    pub async fn register_device(&self, device_info: DeviceInfo) -> Result<()> {
        let mut conn = self.redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

        let device_id = device_info.device_id.clone();
        let data = serde_json::to_string(&device_info)
            .map_err(|e| DiscoveryError::SerializationError(e.to_string()))?;

        // Store device info
        redis::cmd("SET")
            .arg(format!("device:{}", device_id))
            .arg(data)
            .query_async::<MultiplexedConnection, ()>(&mut conn)
            .await
            .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

        // Add to active devices set
        redis::cmd("SADD")
            .arg("active_devices")
            .arg(&device_id)
            .query_async::<MultiplexedConnection, ()>(&mut conn)
            .await
            .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

        info!("Registered device {} in Redis", device_id);
        Ok(())
    }

    pub async fn update_device_status(&self, device_id: &str, status: DeviceStatus) -> Result<()> {
        let mut conn = self.redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

        // Get existing device info
        let data: String = redis::cmd("GET")
            .arg(format!("device:{}", device_id))
            .query_async::<MultiplexedConnection, String>(&mut conn)
            .await
            .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

        let mut device_info: DeviceInfo = serde_json::from_str(&data)
            .map_err(|e| DiscoveryError::SerializationError(e.to_string()))?;

        // Update status and last_seen
        device_info.status = status;
        device_info.last_seen = Utc::now();

        // Store updated info
        let updated_data = serde_json::to_string(&device_info)
            .map_err(|e| DiscoveryError::SerializationError(e.to_string()))?;

        redis::cmd("SET")
            .arg(format!("device:{}", device_id))
            .arg(updated_data)
            .query_async::<MultiplexedConnection, ()>(&mut conn)
            .await
            .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_all_devices(&self) -> Result<Vec<DeviceInfo>> {
        let mut conn = self.redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

        // Get all active device IDs
        let device_ids: Vec<String> = redis::cmd("SMEMBERS")
            .arg("active_devices")
            .query_async::<MultiplexedConnection, Vec<String>>(&mut conn)
            .await
            .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

        let mut devices = Vec::new();
        for id in device_ids {
            let data: String = redis::cmd("GET")
                .arg(format!("device:{}", id))
                .query_async::<MultiplexedConnection, String>(&mut conn)
                .await
                .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

            let device: DeviceInfo = serde_json::from_str(&data)
                .map_err(|e| DiscoveryError::SerializationError(e.to_string()))?;
            devices.push(device);
        }

        Ok(devices)
    }

    pub async fn get_device(&self, device_id: &str) -> Result<Option<DeviceInfo>> {
        let mut conn = self.redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

        let data: Option<String> = redis::cmd("GET")
            .arg(format!("device:{}", device_id))
            .query_async::<MultiplexedConnection, Option<String>>(&mut conn)
            .await
            .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

        match data {
            Some(data) => {
                let device = serde_json::from_str(&data)
                    .map_err(|e| DiscoveryError::SerializationError(e.to_string()))?;
                Ok(Some(device))
            }
            None => Ok(None)
        }
    }

    pub async fn cleanup_stale_devices(&self, timeout: chrono::Duration) -> Result<()> {
        let mut conn = self.redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

        let devices = self.get_all_devices().await?;
        let now = Utc::now();

        for device in devices {
            if now.signed_duration_since(device.last_seen) > timeout {
                // Remove from active devices set
                redis::cmd("SREM")
                    .arg("active_devices")
                    .arg(&device.device_id)
                    .query_async::<MultiplexedConnection, ()>(&mut conn)
                    .await
                    .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;

                // Delete device info
                redis::cmd("DEL")
                    .arg(format!("device:{}", device.device_id))
                    .query_async::<MultiplexedConnection, ()>(&mut conn)
                    .await
                    .map_err(|e| DiscoveryError::StorageError(e.to_string()))?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use common::types::NetworkInfo;
    use redis::Client as RedisClient;

    fn create_test_device(id: &str) -> DeviceInfo {
        DeviceInfo {
            device_id: id.to_string(),
            device_type: "sensor".to_string(),
            capabilities: vec!["temperature".to_string()],
            last_seen: Utc::now(),
            status: DeviceStatus::Online,
            network_info: NetworkInfo {
                ip_address: "127.0.0.1".to_string(),
                port: 8080,
                mac_address: "00:11:22:33:44:55".to_string(),
            },
            firmware_version: "1.0.0".to_string(),
            protocol_version: "1.0".to_string(),
        }
    }

    async fn create_test_registry() -> Result<DeviceRegistry> {
        let redis_client = RedisClient::open("redis://127.0.0.1:6379")?;
        DeviceRegistry::new(redis_client)
    }

    #[tokio::test]
    async fn test_register_and_get_device() -> Result<()> {
        let registry = create_test_registry().await?;
        let device = create_test_device("test1");
        
        registry.register_device(device.clone()).await?;
        
        let retrieved = registry.get_device("test1").await?;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().device_id, "test1");
        Ok(())
    }

    #[tokio::test]
    async fn test_update_device_status() -> Result<()> {
        let registry = create_test_registry().await?;
        let device = create_test_device("test1");
        
        registry.register_device(device).await?;
        registry.update_device_status("test1", DeviceStatus::Offline).await?;
        
        let updated = registry.get_device("test1").await?.unwrap();
        assert_eq!(updated.status, DeviceStatus::Offline);
        Ok(())
    }

    #[tokio::test]
    async fn test_cleanup_stale_devices() -> Result<()> {
        let registry = create_test_registry().await?;
        let device = create_test_device("test1");
        
        registry.register_device(device).await?;
        
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        
        registry.cleanup_stale_devices(Duration::seconds(1)).await?;
        
        assert!(registry.get_device("test1").await?.is_none());
        Ok(())
    }
} 