use crate::utils::FirewallRule;

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
    /// 封禁IP指定时长
    Ban { ip: IpAddr, seconds: u64 },
    /// 检查规则是否过期
    IsExpiration { rule_id: String, seconds: u64 },
    /// 解封指定规则ID
    Unblock { rule_id: String },
    /// 白名单
    Exclude { ip: IpAddr },
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
