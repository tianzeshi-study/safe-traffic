use crate::utils::FirewallRule;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// 客户端请求类型
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", content = "data")]
pub enum Request {
    /// 设置IP速率限制
    Limit {
        ip: IpAddr,
        kbps: u64,
        burst: Option<u64>,
        seconds: Option<u64>,
    },

    /// 批量设置IP速率限制
    BatchLimit {
        ips: Vec<IpAddr>,
        kbps: u64,
        burst: Option<u64>,
        seconds: Option<u64>,
    },

    LimitCidr {
        cidr: IpNet,
        kbps: u64,
        burst: Option<u64>,
        seconds: Option<u64>,
    },

    /// 封禁IP指定时长
    Ban { ip: IpAddr, seconds: Option<u64> },
    /// 批量封禁IP指定时长
    BatchBan {
        ips: Vec<IpAddr>,
        seconds: Option<u64>,
    },

    /// 封禁网段指定时长
    BanCidr { cidr: IpNet, seconds: Option<u64> },
    /// 解封指定规则ID
    Unblock { rule_id: String },
    /// 白名单
    Exclude { ip: IpAddr },

    /// 获取所有活跃规则
    GetActiveRules,
    /// 获取系统规则
    GetSystemRules,
    /// 清理所有规则
    Cleanup,
    /// 获取防火墙状态
    Status,
    /// 健康检查
    Ping,
    ///  清空规则
    Flush,
    ///  停止进程
    Stop,
    /// 暂停规则检查
    Pause,
    /// 恢复规则检查
    Resume,
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
    /// 字符串结果
    StringList(Vec<String>),
    /// 规则列表结果
    RuleList(Vec<FirewallRule>),
    /// Ping响应
    Pong,
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;

    #[test]
    fn test_request_serialization() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let limit_req = Request::Limit {
            ip,
            kbps: 100,
            burst: None,
            seconds: Some(60),
        };
        let json = toml::to_string(&limit_req).unwrap();
        assert!(json.contains("Limit"));
        assert!(json.contains("192.168.1.1"));
    }

    #[test]
    fn test_batch_requests() {
        let ips = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
        let batch_ban = Request::BatchBan {
            ips,
            seconds: Some(120),
        };

        let json = toml::to_string(&batch_ban).unwrap();
        let parsed: Request = toml::from_str(&json).unwrap();

        match parsed {
            Request::BatchBan { ips, seconds } => {
                assert_eq!(ips.len(), 1);
                assert_eq!(seconds, Some(120));
            }
            _ => panic!("Wrong request type"),
        }
    }

    #[test]
    fn test_cidr_requests() {
        let cidr = "192.168.1.0/24".parse::<IpNet>().unwrap();
        let ban_cidr = Request::BanCidr {
            cidr,
            seconds: None,
        };

        let json = toml::to_string(&ban_cidr).unwrap();
        assert!(json.contains("BanCidr"));
        assert!(json.contains("192.168.1.0/24"));
    }

    #[test]
    fn test_simple_requests() {
        let requests = vec![
            Request::GetActiveRules,
            Request::Cleanup,
            Request::Status,
            Request::Ping,
            Request::Flush,
            Request::Stop,
            Request::Pause,
            Request::Resume,
        ];

        for req in requests {
            let json = toml::to_string(&req).unwrap();
            let _: Request = toml::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_response_success() {
        let success = Response::Success(ResponseData::Message("OK".to_string()));
        let json = toml::to_string(&success).unwrap();
        assert!(json.contains("Success"));
        assert!(json.contains("OK"));
    }

    #[test]
    fn test_response_error() {
        let error = Response::Error {
            message: "Failed".to_string(),
        };
        let json = toml::to_string(&error).unwrap();
        let parsed: Response = toml::from_str(&json).unwrap();

        match parsed {
            Response::Error { message } => assert_eq!(message, "Failed"),
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn test_unblock_request() {
        let unblock = Request::Unblock {
            rule_id: "rule123".to_string(),
        };
        let json = toml::to_string(&unblock).unwrap();
        assert!(json.contains("Unblock"));
        assert!(json.contains("rule123"));
    }

    #[test]
    fn test_exclude_request() {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let exclude = Request::Exclude { ip };
        let json = toml::to_string(&exclude).unwrap();
        assert!(json.contains("Exclude"));
        assert!(json.contains("127.0.0.1"));
    }
}
