use crate::{controller::Firewall, rules::RuleEngine};

use anyhow::{Context, Result};
use log::{debug, error, info};
use safe_traffic_common::transport::{Request, Response, ResponseData};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

/// 流量监控服务器
pub struct TrafficDaemon {
    firewall: Arc<Firewall>,
    engine: Arc<RuleEngine>,
    socket_path: String,
    max_connections: usize,
}

#[allow(dead_code)]
impl TrafficDaemon {
    /// 创建新的服务器实例
    pub fn new(firewall: Arc<Firewall>, engine: Arc<RuleEngine>) -> Self {
        Self {
            firewall,
            engine,
            socket_path: "/run/traffic.sock".to_string(),
            max_connections: 100,
        }
    }

    /// 设置Unix Domain Socket路径
    pub fn with_socket_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.socket_path = path.as_ref().to_string_lossy().to_string();
        self
    }

    /// 设置最大并发连接数
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// 启动服务器
    pub async fn start(&self) -> Result<()> {
        self.cleanup_socket().await?;

        let listener = UnixListener::bind(&self.socket_path)
            .with_context(|| format!("Failed to bind to socket: {}", self.socket_path))?;

        info!("Traffic monitor server listening on: {}", self.socket_path);

        // 使用信号量限制并发连接数
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.max_connections));

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let firewall = Arc::clone(&self.firewall);
                    let engine = Arc::clone(&self.engine);
                    let semaphore = Arc::clone(&semaphore);

                    tokio::spawn(async move {
                        let _permit = semaphore.acquire().await.unwrap();
                        if let Err(e) = Self::handle_connection(stream, firewall, engine).await {
                            error!("Error handling connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    /// 处理单个客户端连接
    async fn handle_connection(
        mut stream: UnixStream,
        firewall: Arc<Firewall>,
        engine: Arc<RuleEngine>,
    ) -> Result<()> {
        let mut buffer = vec![0u8; 8192]; // 增大缓冲区以处理更大的请求

        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    debug!("Client disconnected");
                    break;
                }
                Ok(bytes_read) => {
                    let request_data = &buffer[..bytes_read];

                    match Self::process_request(request_data, &firewall, &engine).await {
                        Ok(response) => {
                            let response_json = serde_json::to_vec(&response)
                                .context("Failed to serialize response")?;

                            // 添加换行符以便客户端处理
                            let mut response_with_newline = response_json;
                            response_with_newline.push(b'\n');

                            if let Err(e) = stream.write_all(&response_with_newline).await {
                                error!("Failed to write response: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Failed to process request: {}", e);
                            let error_response = Response::Error {
                                message: e.to_string(),
                            };
                            let response_json = serde_json::to_vec(&error_response)
                                .unwrap_or_else(|_| b"{\"status\":\"Error\",\"data\":{\"message\":\"Internal serialization error\"}}".to_vec());
                            let mut response_with_newline = response_json;
                            response_with_newline.push(b'\n');
                            let _ = stream.write_all(&response_with_newline).await;
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to read from stream: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    /// 处理客户端请求，为每个 Firewall 公开方法提供对应的 handler
    async fn process_request(
        data: &[u8],
        firewall: &Arc<Firewall>,
        engine: &Arc<RuleEngine>,
    ) -> Result<Response> {
        let request: Request =
            serde_json::from_slice(data).context("Failed to parse request JSON")?;

        debug!("Processing request: {:?}", request);

        let response_data = match request {
            Request::Limit {
                ip,
                kbps,
                burst,
                seconds,
            } => match firewall.limit(ip, kbps, burst, seconds).await {
                Ok(rule_id) => {
                    let _ = engine
                        .add_limit_rule_by_hand(
                            ip,
                            rule_id.clone(),
                            kbps,
                            burst,
                            seconds,
                            None,
                            None,
                        )
                        .await;
                    let seconds: String = seconds
                        .map(|s| s.to_string())
                        .unwrap_or("infinity".to_string());
                    info!(
                        "Successfully set limit for {}: {} kbps for {} seconds",
                        ip, kbps, seconds
                    );
                    ResponseData::Message(rule_id)
                }
                Err(e) => {
                    error!("Failed to set limit for {}: {}", ip, e);
                    return Ok(Response::Error {
                        message: e.to_string(),
                    });
                }
            },

            Request::BatchLimit {
                ips,
                kbps,
                burst,
                seconds,
            } => {
                match firewall
                    .batch_limit(ips.clone(), kbps, burst, seconds)
                    .await
                {
                    Ok(rule_ids) => {
                        for (i, ip) in ips.iter().enumerate() {
                            let _ = engine
                                .add_limit_rule_by_hand(
                                    *ip,
                                    rule_ids[i].clone(),
                                    kbps,
                                    burst,
                                    seconds,
                                    None,
                                    None,
                                )
                                .await;
                        }
                        let seconds: String = seconds
                            .map(|s| s.to_string())
                            .unwrap_or("infinity".to_string());
                        info!(
                            "Successfully set limit for {} IPs: {} kbps for {} seconds",
                            ips.len(),
                            kbps,
                            seconds
                        );
                        ResponseData::StringList(rule_ids)
                    }
                    Err(e) => {
                        error!("Failed to batch limit {} IPs: {}", ips.len(), e);
                        return Ok(Response::Error {
                            message: e.to_string(),
                        });
                    }
                }
            }

            Request::LimitCidr {
                cidr,
                kbps,
                burst,
                seconds,
            } => {
                match engine
                    .dyn_limit(Box::new(cidr), kbps, burst, seconds, None, None)
                    .await
                {
                    Ok(rule_ids) => {
                        let seconds: String = seconds
                            .map(|s| s.to_string())
                            .unwrap_or("infinity".to_string());
                        info!(
                            "Successfully limit {}  for {} seconds",
                            cidr.clone(),
                            seconds
                        );
                        ResponseData::StringList(rule_ids)
                    }
                    Err(e) => {
                        error!("Failed to limit {} : {}", cidr, e);
                        return Ok(Response::Error {
                            message: e.to_string(),
                        });
                    }
                }
            }

            Request::Ban { ip, seconds } => match firewall.ban(ip, seconds).await {
                Ok(rule_id) => {
                    let _ = engine
                        .add_ban_rule_by_hand(ip, rule_id.clone(), seconds, None, None)
                        .await;
                    let seconds: String = seconds
                        .map(|s| s.to_string())
                        .unwrap_or("infinity".to_string());
                    info!("Successfully banned {} for {} seconds", ip, seconds);
                    ResponseData::Message(rule_id)
                }
                Err(e) => {
                    error!("Failed to ban {}: {}", ip, e);
                    return Ok(Response::Error {
                        message: e.to_string(),
                    });
                }
            },

            /*
            Request::BatchBan { ips, seconds } => {
                match firewall.batch_ban(ips.clone(), seconds).await {
                    Ok(rule_ids) => {
                        for (i, ip) in ips.iter().enumerate() {
                            let _ = engine
                                .add_ban_rule_by_hand(
                                    ip.clone(),
                                    rule_ids[i].clone(),
                                    seconds,
                                    None,
                                    None,
                                )
                                .await;
                        }
                        let seconds: String = seconds
                            .map(|s| s.to_string())
                            .unwrap_or("infinity".to_string());
                        info!(
                            "Successfully batch banned {} IPs for {} seconds",
                            ips.len(),
                            seconds
                        );
                        ResponseData::StringList(rule_ids)
                    }
                    Err(e) => {
                        error!("Failed to batch ban {} IPs: {}", ips.len(), e);
                        return Ok(Response::Error {
                            message: e.to_string(),
                        });
                    }
                }
            }
            */
            Request::BatchBan { ips, seconds } => {
                match engine
                    .dyn_block(Box::new(ips.clone()), seconds, None, None)
                    .await
                {
                    Ok(rule_ids) => {
                        for (i, ip) in ips.iter().enumerate() {
                            let _ = engine
                                .add_ban_rule_by_hand(
                                    *ip,
                                    rule_ids[i].clone(),
                                    seconds,
                                    None,
                                    None,
                                )
                                .await;
                        }
                        let seconds: String = seconds
                            .map(|s| s.to_string())
                            .unwrap_or("infinity".to_string());
                        info!(
                            "Successfully batch banned {} IPs for {} seconds",
                            ips.len(),
                            seconds
                        );
                        ResponseData::StringList(rule_ids)
                    }
                    Err(e) => {
                        error!("Failed to batch ban {} IPs: {}", ips.len(), e);
                        return Ok(Response::Error {
                            message: e.to_string(),
                        });
                    }
                }
            }

            Request::BanCidr { cidr, seconds } => {
                match engine
                    .dyn_block(Box::new(cidr), seconds, None, None)
                    .await
                {
                    Ok(rule_ids) => {
                        let seconds: String = seconds
                            .map(|s| s.to_string())
                            .unwrap_or("infinity".to_string());
                        info!(
                            "Successfully banned {}  for {} seconds",
                            cidr.clone(),
                            seconds
                        );
                        ResponseData::StringList(rule_ids)
                    }
                    Err(e) => {
                        error!("Failed to ban {} : {}", cidr, e);
                        return Ok(Response::Error {
                            message: e.to_string(),
                        });
                    }
                }
            }

            Request::Unblock { rule_id } => match firewall.unblock(&rule_id).await {
                Ok(_) => {
                    info!("Successfully unbanned rule: {}", rule_id);
                    ResponseData::Message(format!("Successfully unbanned rule: {}", rule_id))
                }
                Err(e) => {
                    error!("Failed to unban rule {}: {}", rule_id, e);
                    return Ok(Response::Error {
                        message: e.to_string(),
                    });
                }
            },

            Request::Exclude { ip } => match firewall.add_exclude(&ip).await {
                Ok(_) => {
                    info!("Successfully exclude ip: {}", ip);
                    ResponseData::Message(format!("Successfully excludeip: {}", ip))
                }
                Err(e) => {
                    error!("Failed to exclude ip {}: {}", ip, e);
                    return Ok(Response::Error {
                        message: e.to_string(),
                    });
                }
            },

            Request::GetActiveRules => match firewall.get_active_rules().await {
                Ok(rules) => {
                    debug!("Retrieved {} active rules", rules.len());
                    ResponseData::RuleList(rules)
                }
                Err(e) => {
                    error!("Failed to get active rules: {}", e);
                    return Ok(Response::Error {
                        message: e.to_string(),
                    });
                }
            },

            Request::GetSystemRules => match firewall.get_system_rules().await {
                Ok(rules_output) => {
                    debug!("Retrieved system rules");
                    ResponseData::Message(rules_output)
                }
                Err(e) => {
                    error!("Failed to get system rules: {}", e);
                    return Ok(Response::Error {
                        message: e.to_string(),
                    });
                }
            },

            Request::Cleanup => match firewall.cleanup().await {
                Ok(_) => {
                    info!("Successfully cleaned up all rules");
                    ResponseData::Message("All rules cleaned up successfully".to_string())
                }
                Err(e) => {
                    error!("Failed to cleanup rules: {}", e);
                    return Ok(Response::Error {
                        message: e.to_string(),
                    });
                }
            },

            Request::Flush => match firewall.flush().await {
                Ok(rule_count) => {
                    info!("Successfully cleaned up {} rules", rule_count);
                    ResponseData::Message(format!(
                        "All rules cleaned up successfully, cleaned up {} rules",
                        rule_count
                    ))
                }
                Err(e) => {
                    error!("Failed to cleanup rules: {}", e);
                    return Ok(Response::Error {
                        message: e.to_string(),
                    });
                }
            },

            Request::Stop => match engine.stop().await {
                Ok(()) => {
                    info!("Successfully stop");
                    ResponseData::Message("safe traffic daemon stopped successfully!".to_string())
                }
                Err(e) => {
                    error!("Failed to stopp: {}", e);
                    return Ok(Response::Error {
                        message: e.to_string(),
                    });
                }
            },

            Request::Pause => match engine.pause().await {
                Ok(()) => {
                    info!("Successfully pause rule engine");
                    ResponseData::Message("pause Successfully".to_string())
                }
                Err(e) => {
                    error!("Failed to pause: {}", e);
                    return Ok(Response::Error {
                        message: e.to_string(),
                    });
                }
            },

            Request::Resume => match engine.resume().await {
                Ok(()) => {
                    info!("Successfully resume rule engine");
                    ResponseData::Message("resume Successfully".to_string())
                }
                Err(e) => {
                    error!("Failed to resume: {}", e);
                    return Ok(Response::Error {
                        message: e.to_string(),
                    });
                }
            },

            Request::Status => match firewall.status().await {
                Ok(status_info) => {
                    debug!("Retrieved firewall status");
                    ResponseData::Message(status_info)
                }
                Err(e) => {
                    error!("Failed to get firewall status: {}", e);
                    return Ok(Response::Error {
                        message: e.to_string(),
                    });
                }
            },

            Request::Ping => {
                debug!("Ping request received");
                ResponseData::Pong
            }
        };

        Ok(Response::Success(response_data))
    }

    /// 清理已存在的socket文件
    async fn cleanup_socket(&self) -> Result<()> {
        if tokio::fs::metadata(&self.socket_path).await.is_ok() {
            tokio::fs::remove_file(&self.socket_path)
                .await
                .with_context(|| {
                    format!("Failed to remove existing socket: {}", self.socket_path)
                })?;
            info!("Removed existing socket file: {}", self.socket_path);
        }
        Ok(())
    }

    /// 优雅关闭服务器
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down traffic monitor server");

        // 清理 socket 文件
        if tokio::fs::metadata(&self.socket_path).await.is_ok() {
            tokio::fs::remove_file(&self.socket_path)
                .await
                .with_context(|| {
                    format!(
                        "Failed to remove socket during shutdown: {}",
                        self.socket_path
                    )
                })?;
        }

        info!("Traffic monitor server shutdown complete");
        Ok(())
    }
}

/// 服务器构建器，用于更灵活的配置
#[allow(dead_code)]
pub struct ServerBuilder {
    firewall: Arc<Firewall>,
    engine: Arc<RuleEngine>,
    socket_path: Option<String>,
    max_connections: Option<usize>,
}

#[allow(dead_code)]
impl ServerBuilder {
    pub fn new(firewall: Arc<Firewall>, engine: Arc<RuleEngine>) -> Self {
        Self {
            firewall,
            engine,
            socket_path: None,
            max_connections: None,
        }
    }

    pub fn socket_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.socket_path = Some(path.as_ref().to_string_lossy().to_string());
        self
    }

    pub fn max_connections(mut self, max: usize) -> Self {
        self.max_connections = Some(max);
        self
    }

    pub fn build(self) -> TrafficDaemon {
        let mut server = TrafficDaemon::new(self.firewall, self.engine);

        if let Some(path) = self.socket_path {
            server = server.with_socket_path(path);
        }

        if let Some(max) = self.max_connections {
            server = server.with_max_connections(max);
        }

        server
    }
}

/// 便利宏，用于快速创建服务器
#[macro_export]
macro_rules! create_server {
    ($firewall:expr) => {
        TrafficDaemon::new($firewall)
    };
    ($firewall:expr, socket_path = $path:expr) => {
        TrafficDaemon::new($firewall).with_socket_path($path)
    };
    ($firewall:expr, max_connections = $max:expr) => {
        TrafficDaemon::new($firewall).with_max_connections($max)
    };
    ($firewall:expr, socket_path = $path:expr, max_connections = $max:expr) => {
        TrafficDaemon::new($firewall)
            .with_socket_path($path)
            .with_max_connections($max)
    };
}
