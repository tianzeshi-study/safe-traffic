use safe_traffic_common::{
    transport::{Request, Response, ResponseData},
    utils::FirewallRule,
};

use anyhow::Result;
use std::{net::IpAddr, path::Path};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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

    pub async fn limit(
        &mut self,
        ip: IpAddr,
        kbps: u64,
        burst: Option<u64>,
        seconds: Option<u64>,
    ) -> Result<String> {
        let request = Request::Limit {
            ip,
            kbps,
            burst,
            seconds,
        };
        match self.send_request(request).await? {
            Response::Success(ResponseData::Message(rule_id)) => Ok(rule_id),
            Response::Error { message } => Err(anyhow::anyhow!(message)),
            _ => Err(anyhow::anyhow!("Unexpected response format")),
        }
    }

    pub async fn ban(&mut self, ip: IpAddr, seconds: Option<u64>) -> Result<String> {
        let request = Request::Ban { ip, seconds };
        match self.send_request(request).await? {
            Response::Success(ResponseData::Message(rule_id)) => Ok(rule_id),
            Response::Error { message } => Err(anyhow::anyhow!(message)),
            _ => Err(anyhow::anyhow!("Unexpected response format")),
        }
    }

    pub async fn unblock(&mut self, rule_id: String) -> Result<()> {
        let request = Request::Unblock { rule_id };
        match self.send_request(request).await? {
            Response::Success(_) => Ok(()),
            Response::Error { message } => Err(anyhow::anyhow!(message)),
        }
    }

    pub async fn exclude(&mut self, ip: IpAddr) -> Result<()> {
        let request = Request::Exclude { ip };
        match self.send_request(request).await? {
            Response::Success(_) => Ok(()),
            Response::Error { message } => Err(anyhow::anyhow!(message)),
        }
    }

    pub async fn get_active_rules(&mut self) -> Result<Option<Vec<FirewallRule>>> {
        let request = Request::GetActiveRules;
        let response = self.send_request(request).await?;
        dbg!(&response);

        match response {
            Response::Success(ResponseData::RuleList(rules)) => Ok(Some(rules)),
            Response::Success(ResponseData::StringList(rules)) => Ok(None),
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

    pub async fn flush(&mut self) -> Result<String> {
        let request = Request::Flush;
        match self.send_request(request).await? {
            Response::Success(ResponseData::Message(msg)) => Ok(msg),
            Response::Error { message } => Err(anyhow::anyhow!(message)),
            _ => Err(anyhow::anyhow!("Unexpected response format")),
        }
    }

    pub async fn stop(&mut self) -> Result<String> {
        let request = Request::Stop;
        match self.send_request(request).await? {
            Response::Success(ResponseData::Message(msg)) => Ok(msg),
            Response::Error { message } => Err(anyhow::anyhow!(message)),
            _ => Err(anyhow::anyhow!("Unexpected response format")),
        }
    }

    pub async fn pause(&mut self) -> Result<String> {
        let request = Request::Pause;
        match self.send_request(request).await? {
            Response::Success(ResponseData::Message(msg)) => Ok(msg),
            Response::Error { message } => Err(anyhow::anyhow!(message)),
            _ => Err(anyhow::anyhow!("Unexpected response format")),
        }
    }

    pub async fn resume(&mut self) -> Result<String> {
        let request = Request::Resume;
        match self.send_request(request).await? {
            Response::Success(ResponseData::Message(msg)) => Ok(msg),
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
            seconds: Some(3600),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: Request = serde_json::from_str(&json).unwrap();

        match deserialized {
            Request::Ban { ip, seconds } => {
                assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
                assert_eq!(seconds, Some(3600));
            }
            _ => panic!("Unexpected request type"),
        }
    }
}
