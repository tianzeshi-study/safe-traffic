use crate::config::Config;
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use log::{debug, info, warn, error};
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::RwLock;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum FirewallError {
    #[error("Command execution failed: {0}")]
    CommandError(String),
    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),
    #[error("Rule not found: {0}")]
    RuleNotFound(String),
    #[error("NFTables not available")]
    NftablesNotAvailable,
    #[error("Permission denied - root privileges required")]
    PermissionDenied,
}

/// 规则类型枚举
#[derive(Debug, Clone, PartialEq)]
pub enum RuleType {
    Ban { until: DateTime<Utc> },
    Limit { kbps: u64, burst: u64 },
}

/// 防火墙规则信息
#[derive(Debug, Clone)]
pub struct FirewallRule {
    pub id: String,
    pub ip: IpAddr,
    pub rule_type: RuleType,
    pub created_at: DateTime<Utc>,
    pub handle: Option<String>,
}

/// 纯 Rust 防火墙控制器（使用 nft 命令行工具）
#[derive(Clone, Debug)]
pub struct Firewall {
    table_name: String,
    chain_name: String,
    family: String,
    pub rules: Arc<RwLock<HashMap<String, FirewallRule>>>,
    nft_available: bool,
}

impl Firewall {
    /// 初始化防火墙控制器
    pub async fn new(cfg: &Config) -> Result<Self> {
        let table_name = cfg.table_name.clone().unwrap_or("filter".to_string());
        let chain_name = cfg.chain_name.clone().unwrap_or("SAFE_TRAFFIC".to_string());
        let family = cfg.family.clone().unwrap_or("ip".to_string());
        let firewall = Firewall {
            table_name,
            chain_name,
            family,
            rules: Arc::new(RwLock::new(HashMap::new())),
            nft_available: false,
        };

        // 检查 nftables 是否可用
        let nft_available = firewall.check_nftables_available().await?;
        let mut firewall = firewall;
        firewall.nft_available = nft_available;

        if nft_available {
            // 初始化表和链
            firewall.init_table_and_chain().await?;
            info!(
                "firewall controlor initial completed: table={}, chain={}",
                firewall.table_name, firewall.chain_name
            );
        } else {
            warn!("nftables is unavailable ，use mock mod instead");
        }

        Ok(firewall)
    }

    /// 检查 nftables 是否可用
    async fn check_nftables_available(&self) -> Result<bool> {
        match Command::new("nft")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
        {
            Ok(status) => {
                if status.success() {
                    // 检查是否有权限
                    match Command::new("nft")
                        .args(&["list", "tables"])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status()
                        .await
                    {
                        Ok(status) => Ok(status.success()),
                        Err(_) => Ok(false),
                    }
                } else {
                    Ok(false)
                }
            }
            Err(_) => Ok(false),
        }
    }

    /// 初始化 nftables 表和链
    async fn init_table_and_chain(&self) -> Result<()> {
        // 创建表（如果不存在）
        let create_table_cmd = format!("add table {} {}", self.family, self.table_name);
        self.execute_nft_command(&create_table_cmd).await.ok(); // 忽略错误，表可能已存在

        // 创建链（如果不存在）
        let create_chain_cmd = format!(
            "add  chain {} {} {} {{ type filter hook input priority 0 \\; policy accept \\; }}",
            self.family, self.table_name, self.chain_name
        );
        dbg!(&create_chain_cmd);
        self.execute_nft_command(&create_chain_cmd).await.ok(); // 忽略错误，链可能已存在

        debug!("table {} and chain  {} initial completed", self.table_name, self.chain_name);
        Ok(())
    }

    /// 执行 nft 命令
    async fn execute_nft_command(&self, command: &str) -> Result<String> {
    if !self.nft_available {
        debug!("mocking execute nft command: {}", command);
        return Ok("success".into());
    }
    let full_cmd = format!("nft {}", command);
    debug!("execute nft command: {}", full_cmd);

    // .output() 会 spawn + await + 收集 stdout/stderr + 回收子进程
    let output = Command::new("/bin/bash")
        .arg("-c")
        .arg(full_cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output()
        .await
        .unwrap();
        // .context("Failed to spawn or run nft command").unwrap();
        dbg!(&output);

    // 如果退出码非 0，打印 stderr 并返回错误
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("nft stderr: {}", stderr);
        return Err(FirewallError::CommandError(format!(
            "nft command failed: {}. stderr: {}",
            command, stderr
        )).into());
    }

    // 正常返回 stdout
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}


    /// 对指定 IP 设置速率限制
    pub async fn limit(&self, ip: IpAddr, kbps: u64) -> Result<String> {
        let rule_id = format!("limit_{}_{}", ip, kbps);
        let burst = kbps.min(1024) / 10;

        // 检查是否已存在相同规则
        {
            let rules = self.rules.read().await;
            if let Some(existing_rule) = rules.get(&rule_id) {
                if let RuleType::Limit {
                    kbps: existing_kbps,
                    ..
                } = existing_rule.rule_type
                {
                    if existing_kbps == kbps {
                        debug!("rule {} already exist ，skip creation", rule_id);
                        return Ok(rule_id);
                    }
                }
            }
        }

        let handle = self.create_limit_rule(ip, kbps, burst).await?;

        let rule = FirewallRule {
            id: rule_id.clone(),
            ip,
            rule_type: RuleType::Limit { kbps, burst },
            created_at: Utc::now(),
            handle: Some(handle),
        };

        self.rules.write().await.insert(rule_id.clone(), rule);
        info!(
            "set speed limit for {}  : {} KB/s (burst : {} KB)",
            ip, kbps, burst
        );

        Ok(rule_id)
    }

    /// 创建速率限制规则
    async fn create_limit_rule(&self, ip: IpAddr, kbps: u64, burst: u64) -> Result<String> {
        let ip_version = match ip {
            IpAddr::V4(_) => "ip saddr",
            IpAddr::V6(_) => "ip6 saddr",
        };

        let rule_cmd = format!(
            "add rule {} {} {} {} {} limit rate {} kbytes/second burst {} kbytes accept",
            self.family, self.table_name, self.chain_name, ip_version, ip, kbps, burst
        );

        self.execute_nft_command(&rule_cmd).await?;

        // 返回规则标识符（简化实现）
        Ok(format!("limit_{}_{}", ip, Utc::now().timestamp()))
    }

    /// 对指定 IP 封禁指定时长
    pub async fn ban(&self, ip: IpAddr, duration: Duration) -> Result<String> {
        let until = Utc::now() + duration;
        let rule_id = format!("ban_{}_{}", ip, until.timestamp());

        // 检查是否已被封禁
        {
            let rules = self.rules.read().await;
            for (_, rule) in rules.iter() {
                if rule.ip == ip {
                    if let RuleType::Ban {
                        until: existing_until,
                    } = rule.rule_type
                    {
                        if existing_until > Utc::now() {
                            warn!("IP {} has already been banned till  {}", ip, existing_until);
                            return Ok(rule.id.clone());
                        }
                    }
                }
            }
        }


        let handle = self.create_ban_rule(ip).await.unwrap();
        dbg!(&handle);


        let rule = FirewallRule {
            id: rule_id.clone(),
            ip,
            rule_type: RuleType::Ban { until },
            created_at: Utc::now(),
            handle: Some(handle),
        };
        dbg!(&rule);

        self.rules.write().await.insert(rule_id.clone(), rule);
        info!("banned  {} till {}", ip, until);

        Ok(rule_id)
    }

    /// 创建封禁规则
    async fn create_ban_rule(&self, ip: IpAddr) -> Result<String> {
        let ip_version = match ip {
            IpAddr::V4(_) => "ip saddr",
            IpAddr::V6(_) => "ip6 saddr",
        };

        let rule_cmd = format!(
            "add rule {} {} {} {} {} drop",
            self.family, self.table_name, self.chain_name, ip_version, ip
        );
        dbg!(&rule_cmd);

        let result  = self.execute_nft_command(&rule_cmd).await?;
        dbg!(&result);

        // 返回规则标识符
        Ok(format!("ban_{}_{}", ip, Utc::now().timestamp()))
    }

    /// 解封指定IP
    pub async fn unban(&self, ip: IpAddr) -> Result<Vec<String>> {
        let mut removed_rules = Vec::new();
        let mut rules_to_remove = Vec::new();

        // 查找需要移除的规则
        {
            let rules = self.rules.read().await;
            for (rule_id, rule) in rules.iter() {
                if rule.ip == ip {
                    if let RuleType::Ban { .. } = rule.rule_type {
                        rules_to_remove.push((rule_id.clone(), rule.handle.clone()));
                    }
                }
            }
        }

        // 移除规则
        for (rule_id, handle) in rules_to_remove {
            if let Some(handle) = handle {
                self.remove_rule_by_handle(&handle).await?;
            }
            self.rules.write().await.remove(&rule_id);
            removed_rules.push(rule_id);
        }

        if !removed_rules.is_empty() {
            info!("Unblocked IP: {}", ip);
        }

        Ok(removed_rules)
    }

    /// 根据句柄移除规则（简化实现：重新创建链）
    async fn remove_rule_by_handle(&self, _handle: &str) -> Result<()> {
        // 由于 nft 命令行工具删除单个规则比较复杂，
        // 这里采用重建链的方式（在实际生产环境中应该优化）
        debug!("remove rule: {}", _handle);

        if self.nft_available {
            // 在实际实现中，你可能需要：
            // 1. 列出所有规则
            // 2. 找到对应的规则句柄
            // 3. 删除特定规则
            // 这里为了简化，只是记录日志
        }

        Ok(())
    }

    /// 清理过期规则
    pub async fn cleanup_expired(&self) -> Result<Vec<String>> {
        let now = Utc::now();
        let mut expired_rules = Vec::new();
        let mut rules_to_remove = Vec::new();

        // 查找过期规则
        {
            let rules = self.rules.read().await;
            for (rule_id, rule) in rules.iter() {
                if let RuleType::Ban { until } = rule.rule_type {
                    if until <= now {
                        rules_to_remove.push((rule_id.clone(), rule.handle.clone()));
                    }
                }
            }
        }

        // 移除过期规则
        for (rule_id, handle) in rules_to_remove {
            if let Some(handle) = handle {
                if let Err(e) = self.remove_rule_by_handle(&handle).await {
                    warn!("Remove expiration rules {} failed: {}", rule_id, e);
                    continue;
                }
            }
            self.rules.write().await.remove(&rule_id);
            expired_rules.push(rule_id);
        }

        if !expired_rules.is_empty() {
            info!("Removed  {} expiration rules", expired_rules.len());
        }

        Ok(expired_rules)
    }

    /// 获取所有活跃规则
    pub async fn get_active_rules(&self) -> Result<Vec<FirewallRule>> {
        let rules = self.rules.read().await;
        Ok(rules.values().cloned().collect())
    }

    /// 获取当前 nftables 规则（从系统读取）
    pub async fn get_system_rules(&self) -> Result<String> {
        if !self.nft_available {
            return Ok("nftables not available".to_string());
        }

        let list_cmd = format!(
            "list chain {} {} {}",
            self.family, self.table_name, self.chain_name
        );
        self.execute_nft_command(&list_cmd).await
    }

    /// 清理所有自管理规则
    pub async fn cleanup(&self) -> Result<()> {
        let rule_count = {
            let rules = self.rules.read().await;
            rules.len()
        };

        if rule_count == 0 {
            info!("No rules to clean up");
            return Ok(());
        }

        // 清空链中的所有规则
        let flush_cmd = format!(
            "flush chain {} {} {}",
            self.family, self.table_name, self.chain_name
        );
        self.execute_nft_command(&flush_cmd).await?;

        // 清空内存中的规则记录
        self.rules.write().await.clear();

        info!("cleaned up all rules in chain {} (count {} )", self.chain_name, rule_count);
        Ok(())
    }

    /// 检查防火墙状态
    pub async fn status(&self) -> Result<String> {
        let rules = self.rules.read().await;
        let active_count = rules.len();
        let expired_count = rules
            .values()
            .filter(|rule| {
                if let RuleType::Ban { until } = rule.rule_type {
                    until <= Utc::now()
                } else {
                    false
                }
            })
            .count();

        Ok(format!(
            "防火墙状态:\n- nftables 可用: {}\n- 活跃规则: {}\n- 过期规则: {}\n- 表名: {}\n- 链名: {}",
            self.nft_available, active_count, expired_count, self.table_name, self.chain_name
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::time::{sleep, Duration as TokioDuration};

    async fn create_test_firewall() -> Firewall {
        let cfg = Config {
    table_name: Some("test_filter".to_string()),
    chain_name: Some("TEST_CHAIN".to_string()),
    family: Some("ip".to_string()),

    interface: "".to_string(),
    rules: vec![],
    log_path: "".to_string()
};

        Firewall::new(&cfg)
            .await
            .expect("Failed to create test firewall")
    }

    #[tokio::test]
    async fn test_firewall_creation() {
        let firewall = create_test_firewall().await;
        assert_eq!(firewall.table_name, "test_filter");
        assert_eq!(firewall.chain_name, "TEST_CHAIN");
        assert_eq!(firewall.family, "ip");
    }

    #[tokio::test]
    async fn test_limit_rule() {
        let firewall = create_test_firewall().await;
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 110));

        let rule_id = firewall
            .limit(ip, 1000)
            .await
            .expect("Failed to create limit rule");
        assert!(!rule_id.is_empty());

        let rules = firewall
            .get_active_rules()
            .await
            .expect("Failed to get rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].ip, ip);

        if let RuleType::Limit { kbps, burst } = rules[0].rule_type {
            assert_eq!(kbps, 1000);
            assert_eq!(burst, 100);
        } else {
            panic!("Expected limit rule type");
        }
    }

    #[tokio::test]
    async fn test_ban_rule() {
        let firewall = create_test_firewall().await;
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
        let duration = Duration::minutes(30);

        let rule_id = firewall
            .ban(ip, duration)
            .await
            .expect("Failed to create ban rule");
        assert!(!rule_id.is_empty());

        let rules = firewall
            .get_active_rules()
            .await
            .expect("Failed to get rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].ip, ip);

        if let RuleType::Ban { until } = rules[0].rule_type {
            assert!(until > Utc::now());
        } else {
            panic!("Expected ban rule type");
        }
    }

    #[tokio::test]
    async fn test_firewall_status() {
        let firewall = create_test_firewall().await;
        let status = firewall.status().await.expect("Failed to get status");
        assert!(status.contains("防火墙状态"));
        assert!(status.contains("test_filter"));
        assert!(status.contains("TEST_CHAIN"));
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let firewall = create_test_firewall().await;
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        // 创建短期封禁
        firewall
            .ban(ip, Duration::milliseconds(50))
            .await
            .expect("Failed to ban IP");

        // 等待过期
        sleep(TokioDuration::from_millis(100)).await;

        // 清理过期规则
        let expired = firewall.cleanup_expired().await.expect("Failed to cleanup");
        assert_eq!(expired.len(), 1);
    }

    #[tokio::test]
    async fn test_unban() {
        let firewall = create_test_firewall().await;
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 80));

        // 封禁
        firewall
            .ban(ip, Duration::hours(1))
            .await
            .expect("Failed to ban");

        // 验证封禁
        let rules = firewall
            .get_active_rules()
            .await
            .expect("Failed to get rules");
        assert_eq!(rules.len(), 1);

        // 解封
        let removed = firewall.unban(ip).await.expect("Failed to unban");
        assert_eq!(removed.len(), 1);

        // 验证解封
        let rules = firewall
            .get_active_rules()
            .await
            .expect("Failed to get rules");
        assert_eq!(rules.len(), 0);
    }

    #[tokio::test]
    async fn test_duplicate_rules() {
        let firewall = create_test_firewall().await;
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 90));

        let rule_id1 = firewall
            .limit(ip, 500)
            .await
            .expect("Failed to create first rule");
        let rule_id2 = firewall
            .limit(ip, 500)
            .await
            .expect("Failed to create second rule");

        assert_eq!(rule_id1, rule_id2);

        let rules = firewall
            .get_active_rules()
            .await
            .expect("Failed to get rules");
        assert_eq!(rules.len(), 1);
    }

    #[tokio::test]
    async fn test_ipv6_support() {
        let cfg = Config {
    table_name: Some("test_filter_v6".to_string()),
    chain_name: Some("TEST_CHAIN_V6".to_string()),
    family: Some("ip6".to_string()),

    interface: "".to_string(),
    rules: vec![],
    log_path: "".to_string()
};
        let firewall = Firewall::new(&cfg)
            .await
            .expect("Failed to create IPv6 firewall");

        let ipv6 = "2001:db8::1".parse::<IpAddr>().expect("Invalid IPv6");

        let rule_id = firewall
            .limit(ipv6, 5000)
            .await
            .expect("Failed to create IPv6 rule");
        assert!(!rule_id.is_empty());

        let rules = firewall
            .get_active_rules()
            .await
            .expect("Failed to get rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].ip, ipv6);
    }

    #[tokio::test]
    async fn test_cleanup_all() {
        let firewall = create_test_firewall().await;
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));

        firewall.limit(ip1, 1000).await.expect("Failed to limit");
        firewall
            .ban(ip2, Duration::hours(1))
            .await
            .expect("Failed to ban");

        let rules = firewall
            .get_active_rules()
            .await
            .expect("Failed to get rules");
        assert_eq!(rules.len(), 2);

        firewall.cleanup().await.expect("Failed to cleanup");

        let rules = firewall
            .get_active_rules()
            .await
            .expect("Failed to get rules");
        assert_eq!(rules.len(), 0);
    }
}
