use std::sync::Arc;
use std::path::Path;
use std::net::IpAddr;
use tokio::net::UnixStream;
    use tokio::io::{AsyncBufReadExt, BufReader, AsyncWriteExt};
    use serde::{Serialize, Deserialize};
    use chrono::{Utc, DateTime};
    use anyhow::Result;


#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum Action {
    /// 限速模式，参数：kbit/s
    RateLimit { kbps: u64, burst: Option<u64> },
    /// 封禁模式，参数：秒
    Ban { seconds: u64 },
}

/// 防火墙规则信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: String,
    pub ip: IpAddr,
    pub rule_type: Action,
    pub created_at: DateTime<Utc>,
    handle: Option<String>,
}



/// 客户端请求类型
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", content = "data")]
pub enum Request {
    /// 设置IP速率限制
    Limit { 
        ip: IpAddr, 
        kbps: u64, 
        burst: Option<u64> 
    },
    /// 封禁IP指定时长
    Ban { 
        ip: IpAddr, 
        seconds: u64 
    },
    /// 检查规则是否过期
    IsExpiration { 
        rule_id: String, 
        seconds: u64 
    },
    /// 解封指定规则ID
    Unban { 
        rule_id: String 
    },
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
    BatchBan { 
        ips: Vec<IpAddr>, 
        seconds: u64 
    },
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
    // StringList(Vec<String>),
    /// 规则列表结果
    RuleList(Vec<FirewallRule>),
    /// Ping响应
    Pong,
}


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
            let  response = self.send_request(request).await?;
            dbg!(&response);
            match response {
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