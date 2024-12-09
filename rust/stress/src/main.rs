use clap::Parser;
use common::{
    Result, DeviceInfo, NetworkInfo, DeviceStatus, DiscoveryError,
    types::DiscoveryPacket, DiscoveryConfig,
    encryption::{EncryptedData, EncryptedMetadata, wbaes::WbAES},
};
use tokio::time::{Duration, Instant};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use log::{info, warn, error, debug};
use uuid::Uuid;
use chrono::Utc;
use parking_lot::RwLock;
use std::collections::HashMap;
use serde_json::json;
use rand::Rng;
use serde::{Serialize, Deserialize};
use tokio::net::UdpSocket;
use device::discovery::DeviceAnnouncer;
use reqwest::StatusCode;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "100")]
    device_count: usize,

    #[arg(long, default_value = "10")]
    readings_per_second: u32,

    #[arg(long, default_value = "60")]
    test_duration_seconds: u64,

    #[arg(long, default_value = "http://localhost:8080")]
    server_url: String,

    #[arg(long, default_value = "1")]
    cpu_cores: usize,

    #[arg(long, default_value = "512")]
    memory_mb: usize,
}

struct TestMetrics {
    requests_total: AtomicU64,
    request_latencies: RwLock<Vec<Duration>>,
    active_devices: AtomicUsize,
    errors_total: AtomicU64,
    device_discovery_times: RwLock<Vec<Duration>>,
    mec_discovery_time: RwLock<Option<Duration>>,
    test_start_time: RwLock<Option<Instant>>,
    test_end_time: RwLock<Option<Instant>>,
    security: SecurityMetrics,
    peak_devices: AtomicUsize,
}

struct SecurityMetrics {
    encryption_times: RwLock<Vec<Duration>>,      // Time taken to encrypt each payload
    key_exchange_times: RwLock<Vec<Duration>>,    // Time taken for key exchange
    key_refresh_count: AtomicU64,                 // Number of times keys were refreshed
    encryption_failures: AtomicU64,               // Failed encryption attempts
    invalid_key_errors: AtomicU64,               // Invalid/expired key errors
    unauthorized_requests: AtomicU64,             // 401/403 responses
}

impl TestMetrics {
    fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            request_latencies: RwLock::new(Vec::new()),
            active_devices: AtomicUsize::new(0),
            errors_total: AtomicU64::new(0),
            device_discovery_times: RwLock::new(Vec::new()),
            mec_discovery_time: RwLock::new(None),
            test_start_time: RwLock::new(None),
            test_end_time: RwLock::new(None),
            security: SecurityMetrics {
                encryption_times: RwLock::new(Vec::new()),
                key_exchange_times: RwLock::new(Vec::new()),
                key_refresh_count: AtomicU64::new(0),
                encryption_failures: AtomicU64::new(0),
                invalid_key_errors: AtomicU64::new(0),
                unauthorized_requests: AtomicU64::new(0),
            },
            peak_devices: AtomicUsize::new(0),
        }
    }

    fn add_latency(&self, duration: Duration) {
        let mut latencies = self.request_latencies.write();
        latencies.push(duration);
    }

    fn calculate_stats(&self) -> MetricsStats {
        let latencies = self.request_latencies.read();
        let mut latencies: Vec<f64> = latencies
            .iter()
            .map(|d| d.as_secs_f64() * 1000.0)
            .collect();
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let total_requests = self.requests_total.load(Ordering::Relaxed);
        let total_errors = self.errors_total.load(Ordering::Relaxed);
        
        let test_duration = if let (Some(start), Some(end)) = (
            *self.test_start_time.read(),
            *self.test_end_time.read()
        ) {
            end.duration_since(start)
        } else {
            Duration::from_secs(0)
        };

        let avg_latency = if !latencies.is_empty() {
            latencies.iter().sum::<f64>() / latencies.len() as f64
        } else {
            0.0
        };

        let median_latency = if !latencies.is_empty() {
            latencies[latencies.len() / 2]
        } else {
            0.0
        };

        let p95 = if !latencies.is_empty() {
            let idx = (latencies.len() as f64 * 0.95) as usize;
            latencies[idx]
        } else {
            0.0
        };

        let p99 = if !latencies.is_empty() {
            let idx = (latencies.len() as f64 * 0.99) as usize;
            latencies[idx]
        } else {
            0.0
        };

        let min_latency = latencies.first().copied().unwrap_or(0.0);
        let max_latency = latencies.last().copied().unwrap_or(0.0);

        let requests_per_second = total_requests as f64 / test_duration.as_secs_f64();
        let success_rate = ((total_requests - total_errors) as f64 / total_requests as f64) * 100.0;

        let device_discovery_times = self.device_discovery_times.read();
        let avg_device_discovery_time = if !device_discovery_times.is_empty() {
            device_discovery_times.iter().sum::<Duration>().as_secs_f64() * 1000.0 
            / device_discovery_times.len() as f64
        } else {
            0.0
        };

        // Add security metrics calculations
        let encryption_times = self.security.encryption_times.read();
        let avg_encryption_time = if !encryption_times.is_empty() {
            encryption_times.iter().sum::<Duration>().as_secs_f64() * 1000.0 
            / encryption_times.len() as f64
        } else {
            0.0
        };

        let key_exchange_times = self.security.key_exchange_times.read();
        let avg_key_exchange_time = if !key_exchange_times.is_empty() {
            key_exchange_times.iter().sum::<Duration>().as_secs_f64() * 1000.0 
            / key_exchange_times.len() as f64
        } else {
            0.0
        };

        let key_refresh_rate = self.security.key_refresh_count.load(Ordering::Relaxed) as f64 
            / test_duration.as_secs_f64() * 60.0; // per minute

        let encryption_failures = self.security.encryption_failures.load(Ordering::Relaxed);
        let encryption_failure_rate = if total_requests > 0 {
            (encryption_failures as f64 / total_requests as f64) * 100.0
        } else {
            0.0
        };

        let security_errors = encryption_failures 
            + self.security.invalid_key_errors.load(Ordering::Relaxed)
            + self.security.unauthorized_requests.load(Ordering::Relaxed);
        let security_error_rate = if total_requests > 0 {
            (security_errors as f64 / total_requests as f64) * 100.0
        } else {
            0.0
        };

        MetricsStats {
            total_requests,
            total_errors,
            avg_latency,
            median_latency,
            p95_latency: p95,
            p99_latency: p99,
            min_latency,
            max_latency,
            requests_per_second,
            concurrent_devices: self.active_devices.load(Ordering::Relaxed),
            test_duration,
            avg_device_discovery_time,
            mec_discovery_time: self.mec_discovery_time.read().unwrap_or(Duration::from_secs(0)),
            success_rate,
            avg_encryption_time,
            avg_key_exchange_time,
            key_refresh_rate,
            encryption_failure_rate,
            security_error_rate,
            peak_devices: self.peak_devices.load(Ordering::Relaxed),
        }
    }

    fn print_report(&self) {
        let stats = self.calculate_stats();
        println!("\nTest Results:");
        println!("=============");
        println!("Total Requests:        {}", stats.total_requests);
        println!("Total Errors:          {}", stats.total_errors);
        println!("Success Rate:          {:.2}%", stats.success_rate);
        println!("Requests/second:       {:.2}", stats.requests_per_second);
        println!("Active Devices:        {}", stats.concurrent_devices);
        println!("Peak Devices:          {}", stats.peak_devices);
        println!("\nLatency (ms):");
        println!("  Min:                 {:.2}", stats.min_latency);
        println!("  Avg:                 {:.2}", stats.avg_latency);
        println!("  Median:              {:.2}", stats.median_latency);
        println!("  P95:                 {:.2}", stats.p95_latency);
        println!("  P99:                 {:.2}", stats.p99_latency);
        println!("  Max:                 {:.2}", stats.max_latency);
        println!("\nDiscovery Times:");
        println!("  MEC Server:          {:.2}ms", stats.mec_discovery_time.as_secs_f64() * 1000.0);
        println!("  Avg Device:          {:.2}ms", stats.avg_device_discovery_time);
        println!("\nTest Duration:        {:.2}s", stats.test_duration.as_secs_f64());
    }

    fn print_security_report(&self) {
        let stats = self.calculate_stats();
        println!("\nSecurity Metrics:");
        println!("=================");
        println!("Encryption:");
        println!("  Avg Time:            {:.2}ms", stats.avg_encryption_time);
        println!("  Failure Rate:        {:.2}%", stats.encryption_failure_rate);
        println!("\nKey Exchange:");
        println!("  Avg Time:            {:.2}ms", stats.avg_key_exchange_time);
        println!("  Refresh Rate:        {:.2}/min", stats.key_refresh_rate);
        println!("\nSecurity Errors:");
        println!("  Invalid Keys:        {}", self.security.invalid_key_errors.load(Ordering::Relaxed));
        println!("  Unauthorized:        {}", self.security.unauthorized_requests.load(Ordering::Relaxed));
        println!("  Error Rate:          {:.2}%", stats.security_error_rate);
    }

    // Add new tracking for active devices
    fn track_device_start(&self, device_id: &str) {
        let current = self.active_devices.fetch_add(1, Ordering::SeqCst);
        let new_count = current + 1;
        
        // Update peak if necessary
        let mut peak = self.peak_devices.load(Ordering::Relaxed);
        while new_count > peak {
            match self.peak_devices.compare_exchange(
                peak,
                new_count,
                Ordering::SeqCst,
                Ordering::Relaxed
            ) {
                Ok(_) => break,
                Err(actual) => peak = actual,
            }
        }
        
        info!("Device {} started (Active devices: {}, Peak: {})", 
            device_id, new_count, self.peak_devices.load(Ordering::Relaxed));
    }

    fn track_device_stop(&self, device_id: &str) {
        let current = self.active_devices.fetch_sub(1, Ordering::SeqCst);
        info!("Device {} stopped (Active devices: {})", device_id, current - 1);
    }
}

struct MetricsStats {
    total_requests: u64,
    total_errors: u64,
    avg_latency: f64,
    median_latency: f64,
    p95_latency: f64,
    p99_latency: f64,
    min_latency: f64,
    max_latency: f64,
    requests_per_second: f64,
    concurrent_devices: usize,
    test_duration: Duration,
    avg_device_discovery_time: f64,
    mec_discovery_time: Duration,
    success_rate: f64,
    avg_encryption_time: f64,
    avg_key_exchange_time: f64,
    key_refresh_rate: f64,          // Keys refreshed per minute
    encryption_failure_rate: f64,    // % of failed encryptions
    security_error_rate: f64,        // % of security-related errors
    peak_devices: usize,
}

struct StressTest {
    metrics: Arc<TestMetrics>,
    device_count: usize,
    readings_per_second: u32,
    test_duration: Duration,
    server_url: String,
}

impl StressTest {
    async fn discover_server() -> Result<String> {
        info!("Starting server discovery process");
        
        let config = DiscoveryConfig::default();
        info!("Using multicast address: {} port: {}", config.multicast_addr, config.port);
        
        let socket = UdpSocket::bind("0.0.0.0:1900").await  // Explicitly bind to port 1900
            .map_err(|e| DiscoveryError::NetworkError(e.to_string()))?;

        info!("Bound to address: {}", socket.local_addr()?);

        socket.set_broadcast(true)
            .map_err(|e| DiscoveryError::NetworkError(e.to_string()))?;

        info!("Broadcast enabled");

        // Set SO_REUSEADDR
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let sock_fd = socket.as_raw_fd();
            unsafe {
                let optval: libc::c_int = 1;
                libc::setsockopt(
                    sock_fd,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEADDR,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&optval) as libc::socklen_t,
                );
            }
        }

        socket.join_multicast_v4(
            config.multicast_addr.parse().unwrap(),
            "0.0.0.0".parse().unwrap()
        ).map_err(|e| DiscoveryError::NetworkError(e.to_string()))?;

        info!("Joined multicast group");

        let mut buffer = vec![0u8; 2048];
        let mut retry_count = 0;
        let max_retries = 10;

        while retry_count < max_retries {
            info!("Listening for MEC server announcement (attempt {}/{})", retry_count + 1, max_retries);
            
            match tokio::time::timeout(
                Duration::from_secs(5),
                socket.recv_from(&mut buffer)
            ).await {
                Ok(Ok((len, addr))) => {
                    info!("Received {} bytes from {}", len, addr);
                    match serde_json::from_slice::<DiscoveryPacket>(&buffer[..len]) {
                        Ok(packet) => {
                            debug!("Received packet from device type: {}", packet.device_info.device_type);
                            if packet.device_info.device_type == "mec_server" {
                                let server_ip = addr.ip().to_string();
                                let server_port = packet.device_info.network_info.port;
                                let server_url = format!("http://{}:{}", server_ip, server_port);
                                info!("Found MEC server at {}", server_url);
                                return Ok(server_url);
                            } else {
                                debug!("Ignoring packet from non-server device: {}", packet.device_info.device_type);
                            }
                        },
                        Err(e) => {
                            warn!("Failed to parse discovery packet: {}", e);
                            debug!("Raw packet: {:?}", String::from_utf8_lossy(&buffer[..len]));
                        }
                    }
                },
                Ok(Err(e)) => {
                    error!("Socket receive error: {}", e);
                },
                Err(_) => {
                    debug!("No announcement received in timeout period");
                }
            }

            retry_count += 1;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        Err(DiscoveryError::NetworkError("Failed to discover MEC server".into()))
    }

    async fn run(&self) -> Result<()> {
        info!("Starting stress test with {} devices", self.device_count);
        info!("Each device sending {} readings/second", self.readings_per_second);
        info!("Test duration: {} seconds", self.test_duration.as_secs());

        let mut handles = Vec::new();
        let mut device_ids = Vec::new();

        // Create and start devices
        for i in 0..self.device_count {
            let device_id = format!("stress_device_{}", i);
            info!("Creating device {}", device_id);
            
            let discovery_start = Instant::now();
            let device = SimulatedDevice::new(
                device_id.clone(),
                self.server_url.clone(),
                self.readings_per_second,
                ResourceConstraints::from_env(),
            );
            self.metrics.device_discovery_times.write().push(discovery_start.elapsed());

            let metrics = self.metrics.clone();
            let server_url = self.server_url.clone();
            let test_duration = self.test_duration;
            let readings_per_second = self.readings_per_second;

            // Clone device_id for the device_ids vector
            device_ids.push(device_id.clone());
            
            metrics.track_device_start(&device_id);
            
            let handle = tokio::spawn(async move {
                // Create device with proper types
                let device = SimulatedDevice::new(
                    device_id.clone(),  // Pass String directly
                    server_url.clone(), // Pass String directly
                    readings_per_second,
                    ResourceConstraints::from_env(), // Use proper type
                );

                let start = Instant::now();
                let mut reading_count = 0;

                while start.elapsed() < test_duration {
                    let reading_start = Instant::now();
                    match device.send_reading().await {
                        Ok(_) => {
                            reading_count += 1;
                            metrics.requests_total.fetch_add(1, Ordering::SeqCst);
                            metrics.add_latency(reading_start.elapsed());
                            debug!("Device {} sent reading {}", device_id, reading_count);
                        }
                        Err(e) => {
                            metrics.errors_total.fetch_add(1, Ordering::SeqCst);
                            error!("Device {} failed to send reading: {}", device_id, e);
                        }
                    }

                    let elapsed = reading_start.elapsed();
                    let target_interval = Duration::from_secs_f64(1.0 / readings_per_second as f64);
                    if elapsed < target_interval {
                        tokio::time::sleep(target_interval - elapsed).await;
                    }
                }

                info!("Device {} completed {} readings", device_id, reading_count);
                metrics.track_device_stop(&device_id);
                Ok::<_, DiscoveryError>(())
            });

            handles.push(handle);
        }

        // Print periodic status updates
        let device_ids = device_ids.clone(); // Clone for status updates
        let metrics = self.metrics.clone();
        let _status_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                let active = metrics.active_devices.load(Ordering::Relaxed);
                let total_requests = metrics.requests_total.load(Ordering::Relaxed);
                let errors = metrics.errors_total.load(Ordering::Relaxed);
                
                info!("Status Update:");
                info!("  Active Devices: {}", active);
                info!("  Total Requests: {}", total_requests);
                info!("  Total Errors: {}", errors);
                info!("  Active Device IDs: {}", device_ids.join(", "));
            }
        });

        // Wait for all devices to complete
        for handle in handles {
            if let Err(e) = handle.await {
                error!("Device task failed: {}", e);
            }
        }

        info!("All devices completed successfully");
        Ok(())
    }

    fn generate_report(&self) {
        let stats = self.metrics.calculate_stats();
        let success_rate = if stats.total_requests > 0 {
            ((stats.total_requests - stats.total_errors) as f64 / stats.total_requests as f64) * 100.0
        } else {
            0.0
        };

        println!("\nStress Test Report");
        println!("==================");
        println!("Test Duration: {} seconds", self.test_duration.as_secs());
        println!("Total Devices: {}", self.device_count);
        println!("Total Requests: {}", stats.total_requests);
        println!("Total Errors: {}", stats.total_errors);
        println!("Success Rate: {:.2}%", success_rate);
        println!("Average Latency: {:.2}ms", stats.avg_latency);
        println!("P95 Latency: {:.2}ms", stats.p95_latency);
        println!("P99 Latency: {:.2}ms", stats.p99_latency);
        println!("Requests/second: {:.2}", stats.total_requests as f64 / self.test_duration.as_secs_f64());
    }
}

#[derive(Clone)]
struct ResourceConstraints {
    cpu_cores: usize,
    memory_mb: usize,
    enable_processing_delay: bool,
}

impl ResourceConstraints {
    fn from_env() -> Self {
        Self {
            cpu_cores: std::env::var("DEVICE_CPU_CORES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1),
            memory_mb: std::env::var("DEVICE_MEMORY_MB")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(512),
            enable_processing_delay: std::env::var("DEVICE_ENABLE_DELAYS")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(false),
        }
    }
}

struct SimulatedDevice {
    device_info: DeviceInfo,
    server_url: String,
    readings_per_second: u32,
    constraints: ResourceConstraints,
    client: reqwest::Client,
    metrics: Arc<TestMetrics>,
}

impl SimulatedDevice {
    fn new(id: String, server_url: String, readings_per_second: u32, constraints: ResourceConstraints) -> Self {
        let device_info = DeviceInfo {
            device_id: id,
            device_type: "sensor".to_string(),
            capabilities: vec![
                "heartRate".to_string(),
                "bloodPressure".to_string(),
                "ecg".to_string()
            ],
            network_info: NetworkInfo {
                ip_address: "127.0.0.1".to_string(),
                port: 0,
                mac_address: Uuid::new_v4().to_string(),
            },
            last_seen: Utc::now(),
            status: DeviceStatus::Online,
            firmware_version: "1.0.0".to_string(),
            protocol_version: "1.0".to_string(),
        };

        Self {
            device_info,
            server_url,
            readings_per_second,
            constraints,
            client: reqwest::Client::new(),
            metrics: Arc::new(TestMetrics::new()),
        }
    }

    async fn announce(&self) -> Result<()> {
        // Create announcer with same config as real devices
        let config = DiscoveryConfig {
            multicast_addr: "239.255.255.250".to_string(),
            port: 1900,
            announcement_interval: Duration::from_secs(1),
            security: Default::default(),
            max_packet_size: 1024,
        };

        let announcer = DeviceAnnouncer::new(
            self.device_info.clone(),
            config
        ).await?;

        announcer.announce().await?;

        Ok(())
    }

    async fn run_test(&self, test_duration: Duration) -> Result<()> {
        // First announce the device
        self.announce().await?;

        self.metrics.active_devices.fetch_add(1, Ordering::SeqCst);
        let start = Instant::now();

        while start.elapsed() < test_duration {
            let reading_start = Instant::now();
            match self.send_reading().await {
                Ok(_) => {
                    self.metrics.requests_total.fetch_add(1, Ordering::SeqCst);
                    self.metrics.add_latency(reading_start.elapsed());
                }
                Err(e) => {
                    self.metrics.errors_total.fetch_add(1, Ordering::SeqCst);
                    warn!("Error sending reading: {}", e);
                }
            }

            let elapsed = reading_start.elapsed();
            let target_interval = Duration::from_secs_f64(1.0 / self.readings_per_second as f64);
            if elapsed < target_interval {
                tokio::time::sleep(target_interval - elapsed).await;
            }
        }

        self.metrics.active_devices.fetch_sub(1, Ordering::SeqCst);
        Ok(())
    }

    async fn send_reading(&self) -> Result<()> {
        let encryption_start = Instant::now();
        
        // Get encryption key first
        let key_start = Instant::now();
        let encryption_key = match self.get_encryption_key().await {
            Ok(key) => {
                // Record successful key exchange time
                self.metrics.security.key_exchange_times.write().push(key_start.elapsed());
                key
            }
            Err(e) => {
                self.metrics.security.invalid_key_errors.fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        };

        // Create cipher
        let cipher = match WbAES::new(encryption_key) {
            Ok(c) => c,
            Err(_) => {
                self.metrics.security.encryption_failures.fetch_add(1, Ordering::Relaxed);
                return Err(DiscoveryError::SecurityError("Failed to create cipher".into()));
            }
        };

        // Generate reading
        let reading = self.generate_reading();
        
        // Create metadata and encrypt
        let metadata = EncryptedMetadata {
            timestamp: Utc::now().to_rfc3339(),
            data_type: reading.type_.clone(),
            reading_count: reading.readings.len(),
            device_id: reading.device_id.clone(),
        };

        let metadata_bytes = serde_json::to_vec(&metadata)?;
        let reading_bytes = serde_json::to_vec(&reading)?;
        
        // Record encryption time for both operations
        let encrypt_start = Instant::now();
        let encrypted_metadata = match cipher.encrypt(&metadata_bytes) {
            Ok(em) => em,
            Err(_) => {
                self.metrics.security.encryption_failures.fetch_add(1, Ordering::Relaxed);
                return Err(DiscoveryError::SecurityError("Failed to encrypt metadata".into()));
            }
        };
        
        let encrypted_payload = match cipher.encrypt(&reading_bytes) {
            Ok(ep) => ep,
            Err(_) => {
                self.metrics.security.encryption_failures.fetch_add(1, Ordering::Relaxed);
                return Err(DiscoveryError::SecurityError("Failed to encrypt payload".into()));
            }
        };
        self.metrics.security.encryption_times.write().push(encrypt_start.elapsed());
        
        let encrypted_data = EncryptedData {
            device_id: self.device_info.device_id.clone(),
            encrypted_payload,
            encrypted_metadata,
            payload_nonce: vec![0; 12],
            metadata_nonce: vec![0; 12],
        };

        // Send to server
        let url = format!("{}/api/ingest/encrypted", self.server_url);
        debug!("Sending encrypted reading to {}", url);

        match self.client.post(&url).json(&encrypted_data).send().await {
            Ok(response) => {
                match response.status() {
                    StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                        self.metrics.security.unauthorized_requests.fetch_add(1, Ordering::Relaxed);
                        Err(DiscoveryError::SecurityError("Unauthorized".into()))
                    }
                    status if !status.is_success() => {
                        let error_text = response.text().await
                            .unwrap_or_else(|_| "Could not get error text".to_string());
                        warn!("Server returned error: {} - {}", status, error_text);
                        Err(DiscoveryError::NetworkError(format!(
                            "Server error: {} - {}", status, error_text
                        )))
                    }
                    _ => {
                        // Record successful key refresh if needed
                        if response.headers().contains_key("x-key-refreshed") {
                            self.metrics.security.key_refresh_count.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(())
                    }
                }
            }
            Err(e) => {
                warn!("Failed to send reading: {}", e);
                Err(DiscoveryError::NetworkError(e.to_string()))
            }
        }
    }

    async fn get_encryption_key(&self) -> Result<Vec<u8>> {
        let response = self.client
            .get(format!("{}/api/key", self.server_url))
            .send()
            .await
            .map_err(|e| DiscoveryError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(DiscoveryError::NetworkError(format!(
                "Failed to get key: {}", response.status()
            )));
        }

        let key = response.bytes().await
            .map_err(|e| DiscoveryError::NetworkError(e.to_string()))?;

        Ok(key.to_vec())
    }

    fn generate_reading(&self) -> SensorData {
        let mut readings = HashMap::new();
        
        // Move random number generation inside a block
        {
            let mut rng = rand::thread_rng();
            for capability in &self.device_info.capabilities {
                let value = match capability.as_str() {
                    "heartRate" => rng.gen_range(60.0, 100.0),
                    "bloodPressure" => rng.gen_range(90.0, 140.0),
                    "ecg" => rng.gen_range(-0.5, 0.5),
                    _ => rng.gen_range(0.0, 100.0),
                };
                readings.insert(capability.clone(), json!(value));
            }
        }

        SensorData {
            device_id: self.device_info.device_id.clone(),
            type_: self.device_info.device_type.clone(),
            timestamp: Utc::now().to_rfc3339(),
            readings,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SensorData {
    device_id: String,
    #[serde(rename = "type_")]
    type_: String,
    timestamp: String,
    readings: HashMap<String, serde_json::Value>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    // Set CPU affinity to limit cores
    #[cfg(target_os = "linux")]
    {
        use core_affinity::CoreId;
        let core_ids = core_affinity::get_core_ids().unwrap();
        let available_cores = core_ids.into_iter()
            .take(args.cpu_cores)
            .collect::<Vec<_>>();
        
        if let Some(core_id) = available_cores.first() {
            core_affinity::set_for_current(*core_id);
            info!("Limited process to {} CPU core(s)", args.cpu_cores);
        }
    }

    // Set memory limit
    #[cfg(target_os = "linux")]
    {
        use rlimit::{Resource, setrlimit};
        if let Ok(Resource::AS) = Resource::from_str("AS") {
            if let Err(e) = setrlimit(Resource::AS, args.memory_mb * 1024 * 1024, args.memory_mb * 1024 * 1024) {
                warn!("Failed to set memory limit: {}", e);
            } else {
                info!("Set memory limit to {}MB", args.memory_mb);
            }
        }
    }

    let metrics = Arc::new(TestMetrics::new());
    
    // Record test start time
    *metrics.test_start_time.write() = Some(Instant::now());
    
    // Record MEC discovery time
    let mec_start = Instant::now();
    let server_url = if args.server_url.is_empty() {
        info!("No server URL provided, discovering MEC server...");
        StressTest::discover_server().await?
    } else {
        args.server_url
    };
    *metrics.mec_discovery_time.write() = Some(mec_start.elapsed());

    let test = Arc::new(StressTest {
        metrics: metrics.clone(),
        device_count: args.device_count,
        readings_per_second: args.readings_per_second,
        test_duration: Duration::from_secs(args.test_duration_seconds),
        server_url,
    });

    test.run().await?;
    
    // Record test end time and print report
    *metrics.test_end_time.write() = Some(Instant::now());
    metrics.print_report();
    metrics.print_security_report();
    
    Ok(())
}
