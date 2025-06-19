use anyhow::{Context, Result};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::controller::{Firewall, FirewallRule};

/// 客户端请求类型
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", content = "data")]
pub enum Request {
    /// 设置IP速率限制
    Limit {
        ip: IpAddr,
        kbps: u64,
        burst: Option<u64>,
    },
    /// 封禁IP指定时长
    Ban { ip: IpAddr, seconds: u64 },
    /// 检查规则是否过期
    IsExpiration { rule_id: String, seconds: u64 },
    /// 解封指定规则ID
    Unban { rule_id: String },
    /// 清理过期规则
    CleanupExpired,
    /// 获取所有活跃规则
    GetActiveRules,
    /// 获取系统规则
    GetSystemRules,
    /// 清理所有规则
    Cleanup,
    /// 获取防火墙状态
    Status,
    /// 批量封禁IP
    BatchBan { ips: Vec<IpAddr>, seconds: u64 },
    /// 健康检查
    Ping,
}

/// 服务器响应类型
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", content = "data")]
pub enum Response {
    Success(ResponseData),
    Error { message: String },
}

/// 响应数据类型
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponseData {
    /// 单个字符串结果
    Message(String),
    /// 布尔结果
    Boolean(bool),
    /// 字符串列表结果
    StringList(Vec<String>),
    /// 规则列表结果
    RuleList(Vec<FirewallRule>),
    /// Ping响应
    Pong,
}

/// 流量监控服务器
pub struct TrafficDaemon {
    firewall: Arc<Firewall>,
    socket_path: String,
    max_connections: usize,
}

impl TrafficDaemon {
    /// 创建新的服务器实例
    pub fn new(firewall: Arc<Firewall>) -> Self {
        Self {
            firewall,
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
                    let semaphore = Arc::clone(&semaphore);

                    tokio::spawn(async move {
                        let _permit = semaphore.acquire().await.unwrap();
                        if let Err(e) = Self::handle_connection(stream, firewall).await {
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
    async fn handle_connection(mut stream: UnixStream, firewall: Arc<Firewall>) -> Result<()> {
        let mut buffer = vec![0u8; 8192]; // 增大缓冲区以处理更大的请求

        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    debug!("Client disconnected");
                    break;
                }
                Ok(bytes_read) => {
                    let request_data = &buffer[..bytes_read];

                    match Self::process_request(request_data, &firewall).await {
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
    async fn process_request(data: &[u8], firewall: &Arc<Firewall>) -> Result<Response> {
        let request: Request =
            serde_json::from_slice(data).context("Failed to parse request JSON")?;

        debug!("Processing request: {:?}", request);

        let response_data = match request {
            Request::Limit { ip, kbps, burst } => match firewall.limit(ip, kbps, burst).await {
                Ok(rule_id) => {
                    info!("Successfully set limit for {}: {} kbps", ip, kbps);
                    ResponseData::Message(rule_id)
                }
                Err(e) => {
                    error!("Failed to set limit for {}: {}", ip, e);
                    return Ok(Response::Error {
                        message: e.to_string(),
                    });
                }
            },

            Request::Ban { ip, seconds } => match firewall.ban(ip, seconds).await {
                Ok(rule_id) => {
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

            Request::IsExpiration { rule_id, seconds } => {
                let is_expired = firewall.is_expiration(&rule_id, seconds).await;
                debug!("Rule {} expiration check: {}", rule_id, is_expired);
                ResponseData::Boolean(is_expired)
            }

            Request::Unban { rule_id } => match firewall.unban(&rule_id).await {
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

            Request::CleanupExpired => match firewall.cleanup_expired().await {
                Ok(expired_rules) => {
                    info!("Cleaned up {} expired rules", expired_rules.len());
                    ResponseData::StringList(expired_rules)
                }
                Err(e) => {
                    error!("Failed to cleanup expired rules: {}", e);
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

            Request::BatchBan { ips, seconds } => {
                match firewall.batch_ban(ips.clone(), seconds).await {
                    Ok(rule_ids) => {
                        info!(
                            "Successfully batch banned {} IPs for {} seconds",
                            ips.len(),
                            seconds
                        );
                        ResponseData::StringList(rule_ids)
                    }
                    Err(e) => {
                        error!("Failed to batch ban IPs: {}", e);
                        return Ok(Response::Error {
                            message: e.to_string(),
                        });
                    }
                }
            }

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
pub struct ServerBuilder {
    firewall: Arc<Firewall>,
    socket_path: Option<String>,
    max_connections: Option<usize>,
}

impl ServerBuilder {
    pub fn new(firewall: Arc<Firewall>) -> Self {
        Self {
            firewall,
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
        let mut server = TrafficDaemon::new(self.firewall);

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

/// 客户端辅助结构，用于测试和示例
#[cfg(test)]
pub mod client {
    use super::*;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::UnixStream;

    pub struct TrafficClient {
        stream: UnixStream,
    }

    impl TrafficClient {
        pub async fn connect<P: AsRef<Path>>(socket_path: P) -> Result<Self> {
            let stream = UnixStream::connect(socket_path).await?;
            Ok(Self { stream })
        }

        pub async fn send_request(&mut self, request: Request) -> Result<Response> {
            let request_json = serde_json::to_vec(&request)?;
            self.stream.write_all(&request_json).await?;

            let mut reader = BufReader::new(&mut self.stream);
            let mut response_line = String::new();
            reader.read_line(&mut response_line).await?;

            let response: Response = serde_json::from_str(&response_line.trim())?;
            Ok(response)
        }

        pub async fn limit(&mut self, ip: IpAddr, kbps: u64, burst: Option<u64>) -> Result<String> {
            let request = Request::Limit { ip, kbps, burst };
            match self.send_request(request).await? {
                Response::Success(ResponseData::Message(rule_id)) => Ok(rule_id),
                Response::Error { message } => Err(anyhow::anyhow!(message)),
                _ => Err(anyhow::anyhow!("Unexpected response format")),
            }
        }

        pub async fn ban(&mut self, ip: IpAddr, seconds: u64) -> Result<String> {
            let request = Request::Ban { ip, seconds };
            match self.send_request(request).await? {
                Response::Success(ResponseData::Message(rule_id)) => Ok(rule_id),
                Response::Error { message } => Err(anyhow::anyhow!(message)),
                _ => Err(anyhow::anyhow!("Unexpected response format")),
            }
        }

        pub async fn unban(&mut self, rule_id: String) -> Result<()> {
            let request = Request::Unban { rule_id };
            match self.send_request(request).await? {
                Response::Success(_) => Ok(()),
                Response::Error { message } => Err(anyhow::anyhow!(message)),
            }
        }

        pub async fn get_active_rules(&mut self) -> Result<Vec<FirewallRule>> {
            let request = Request::GetActiveRules;
            match self.send_request(request).await? {
                Response::Success(ResponseData::RuleList(rules)) => Ok(rules),
                Response::Error { message } => Err(anyhow::anyhow!(message)),
                _ => Err(anyhow::anyhow!("Unexpected response format")),
            }
        }

        pub async fn ping(&mut self) -> Result<()> {
            let request = Request::Ping;
            match self.send_request(request).await? {
                Response::Success(ResponseData::Pong) => Ok(()),
                Response::Error { message } => Err(anyhow::anyhow!(message)),
                _ => Err(anyhow::anyhow!("Unexpected response format")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    // 注意：这些测试需要一个真实的 Firewall 实例才能运行
    // 在实际使用中，您需要传入已配置的 Firewall 实例

    #[tokio::test]
    async fn test_server_creation() {
        // 这个测试需要一个真实的 Firewall 实例
        // let firewall = Arc::new(Firewall::new(...).await.unwrap());
        // let server = TrafficDaemon::new(firewall);
        // assert_eq!(server.socket_path, "/run/traffic.sock");
        // assert_eq!(server.max_connections, 100);
    }

    #[tokio::test]
    async fn test_server_builder() {
        // 这个测试需要一个真实的 Firewall 实例
        // let firewall = Arc::new(Firewall::new(...).await.unwrap());
        // let server = ServerBuilder::new(firewall)
        //     .socket_path("/tmp/test.sock")
        //     .max_connections(50)
        //     .build();
        //
        // assert_eq!(server.socket_path, "/tmp/test.sock");
        // assert_eq!(server.max_connections, 50);
    }

    #[test]
    fn test_request_serialization() {
        let request = Request::Ban {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            seconds: 3600,
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: Request = serde_json::from_str(&json).unwrap();

        match deserialized {
            Request::Ban { ip, seconds } => {
                assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
                assert_eq!(seconds, 3600);
            }
            _ => panic!("Unexpected request type"),
        }
    }
}
