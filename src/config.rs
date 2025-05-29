// src/config.rs
use chrono::Duration;
use serde::Deserialize;
use std::{fs, path::Path};

/// 单条规则动作类型：限速或封禁
#[derive(Deserialize, Debug, Clone)]
pub enum Action {
    /// 限速模式，参数：kbit/s
    RateLimit { kbps: u64 },
    /// 封禁模式，参数：秒
    Ban { seconds: u64 },
}

/// 单条流量规则
#[derive(Deserialize, Debug, Clone)]
pub struct Rule {
    /// 滑动窗口时长，秒
    pub window_secs: u64,
    /// 阈值，字节/秒
    pub threshold_bps: u64,
    /// 触发动作
    pub action: Action,
}

/// 全局配置
#[derive(Deserialize, Debug)]
pub struct Config {
    pub table_name: Option<String>,
    pub chain_name: Option<String>,
    pub family: Option<String>,
    /// 主网卡名称
    pub interface: String,
    /// 规则列表
    pub rules: Vec<Rule>,
    /// 日志保留路径
    pub log_path: String,
}

impl Config {
    /// 从文件加载配置
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        // 读取 TOML 文本
        let text = fs::read_to_string(path)?;
        // 解析为 Config 结构
        let cfg: Config = toml::from_str(&text)?;
        Ok(cfg)
    }
}
