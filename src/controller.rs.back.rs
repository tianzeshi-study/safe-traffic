// src/controller.rs
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use ipnet::IpNet;
use log::{debug, info, warn};
use nftnl::{Batch, Chain, FinalizedBatch, ProtoFamily, Rule, Table};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FirewallError {
    #[error("NFTables operation failed: {0}")]
    NftablesError(#[from] nftnl::Error),
    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),
    #[error("Rule not found: {0}")]
    RuleNotFound(String),
    #[error("Table or chain not found")]
    NotFound,
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
    pub handle: u64,
}

/// 防火墙控制器：封装 nftables 管理
#[derive(Clone)]
pub struct Firewall {
    table_name: String,
    chain_name: String,
    family: ProtoFamily,
    rules: Arc<RwLock<HashMap<String, FirewallRule>>>,
}

impl Firewall {
    /// 初始化防火墙控制器
    pub async fn new(
        table_name: Option<&str>,
        chain_name: Option<&str>,
        family: Option<ProtoFamily>,
    ) -> Result<Self> {
        let table_name = table_name.unwrap_or("filter").to_string();
        let chain_name = chain_name.unwrap_or("SAFE_TRAFFIC").to_string();
        let family = family.unwrap_or(ProtoFamily::Ipv4);

        let firewall = Firewall {
            table_name,
            chain_name,
            family,
            rules: Arc::new(RwLock::new(HashMap::new())),
        };

        // 初始化表和链
        firewall.init_table_and_chain().await?;
        
        info!("防火墙控制器初始化完成: table={}, chain={}", 
              firewall.table_name, firewall.chain_name);
        
        Ok(firewall)
    }

    /// 初始化 nftables 表和链
    async fn init_table_and_chain(&self) -> Result<()> {
        let mut batch = Batch::new();
        
        // 创建表
        let table = Table::new(&self.table_name, self.family);
        batch.add(&table, nftnl::MsgType::Add);
        
        // 创建链
        let mut chain = Chain::new(&self.table_name, &self.chain_name, self.family);
        chain.set_hook(nftnl::Hook::Input, 0);
        chain.set_policy(nftnl::Policy::Accept);
        batch.add(&chain, nftnl::MsgType::Add);
        
        // 提交批处理
        let finalized_batch = batch.finalize();
        self.send_batch(finalized_batch).await
            .context("Failed to initialize table and chain")?;
            
        debug!("表 {} 和链 {} 初始化完成", self.table_name, self.chain_name);
        Ok(())
    }

    /// 发送批处理到内核
    async fn send_batch(&self, batch: FinalizedBatch) -> Result<()> {
        tokio::task::spawn_blocking(move || {
            batch.send().map_err(FirewallError::from)
        })
        .await
        .context("Failed to execute batch operation")?
    }

    /// 对指定 IP 设置速率限制
    pub async fn limit(&self, ip: IpAddr, kbps: u64) -> Result<String> {
        let rule_id = format!("limit_{}_{}", ip, kbps);
        let burst = kbps.max(1024) / 10; // 默认突发为速率的10%
        
        // 检查是否已存在相同规则
        {
            let rules = self.rules.read().await;
            if let Some(existing_rule) = rules.get(&rule_id) {
                if let RuleType::Limit { kbps: existing_kbps, .. } = existing_rule.rule_type {
                    if existing_kbps == kbps {
                        debug!("规则 {} 已存在，跳过创建", rule_id);
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
            handle,
        };
        
        self.rules.write().await.insert(rule_id.clone(), rule);
        info!("已为 {} 设置速率限制: {} KB/s (突发: {} KB)", ip, kbps, burst);
        
        Ok(rule_id)
    }

    /// 创建速率限制规则
    async fn create_limit_rule(&self, ip: IpAddr, kbps: u64, burst: u64) -> Result<u64> {
        let mut batch = Batch::new();
        let mut rule = Rule::new(&self.table_name, &self.chain_name, self.family);
        
        // 匹配源IP
        self.add_ip_match(&mut rule, ip)?;
        
        // 添加速率限制
        // 注意：实际的 nftnl 限制表达式需要根据具体版本调整
        rule.add_expr(&nftnl::expr::Limit::new(kbps * 1024, burst * 1024, nftnl::expr::LimitType::Bytes));
        
        // 接受数据包
        rule.add_expr(&nftnl::expr::Verdict::new(nftnl::Verdict::Accept));
        
        batch.add(&rule, nftnl::MsgType::Add);
        let finalized_batch = batch.finalize();
        
        self.send_batch(finalized_batch).await?;
        
        // 返回规则句柄（实际使用中需要从内核获取）
        Ok(self.generate_handle())
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
                    if let RuleType::Ban { until: existing_until } = rule.rule_type {
                        if existing_until > Utc::now() {
                            warn!("IP {} 已被封禁至 {}", ip, existing_until);
                            return Ok(rule.id.clone());
                        }
                    }
                }
            }
        }

        let handle = self.create_ban_rule(ip).await?;
        
        let rule = FirewallRule {
            id: rule_id.clone(),
            ip,
            rule_type: RuleType::Ban { until },
            created_at: Utc::now(),
            handle,
        };
        
        self.rules.write().await.insert(rule_id.clone(), rule);
        info!("已封禁 {} 至 {}", ip, until);
        
        Ok(rule_id)
    }

    /// 创建封禁规则
    async fn create_ban_rule(&self, ip: IpAddr) -> Result<u64> {
        let mut batch = Batch::new();
        let mut rule = Rule::new(&self.table_name, &self.chain_name, self.family);
        
        // 匹配源IP
        self.add_ip_match(&mut rule, ip)?;
        
        // 丢弃数据包
        rule.add_expr(&nftnl::expr::Verdict::new(nftnl::Verdict::Drop));
        
        batch.add(&rule, nftnl::MsgType::Add);
        let finalized_batch = batch.finalize();
        
        self.send_batch(finalized_batch).await?;
        
        Ok(self.generate_handle())
    }

    /// 为规则添加IP匹配条件
    fn add_ip_match(&self, rule: &mut Rule, ip: IpAddr) -> Result<()> {
        match ip {
            IpAddr::V4(ipv4) => {
                // 匹配IPv4源地址
                rule.add_expr(&nftnl::expr::Payload::new(
                    nftnl::expr::PayloadBase::NetworkHeader,
                    12, // IPv4源地址偏移
                    4,  // IPv4地址长度
                ));
                rule.add_expr(&nftnl::expr::Cmp::new(
                    nftnl::expr::CmpOp::Eq,
                    ipv4.octets().to_vec(),
                ));
            }
            IpAddr::V6(ipv6) => {
                // 匹配IPv6源地址
                rule.add_expr(&nftnl::expr::Payload::new(
                    nftnl::expr::PayloadBase::NetworkHeader,
                    8,  // IPv6源地址偏移
                    16, // IPv6地址长度
                ));
                rule.add_expr(&nftnl::expr::Cmp::new(
                    nftnl::expr::CmpOp::Eq,
                    ipv6.octets().to_vec(),
                ));
            }
        }
        Ok(())
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
                        rules_to_remove.push((rule_id.clone(), rule.handle));
                    }
                }
            }
        }
        
        // 移除规则
        for (rule_id, handle) in rules_to_remove {
            self.remove_rule_by_handle(handle).await?;
            self.rules.write().await.remove(&rule_id);
            removed_rules.push(rule_id);
        }
        
        if !removed_rules.is_empty() {
            info!("已解封 IP: {}", ip);
        }
        
        Ok(removed_rules)
    }

    /// 根据句柄移除规则
    async fn remove_rule_by_handle(&self, handle: u64) -> Result<()> {
        let mut batch = Batch::new();
        let mut rule = Rule::new(&self.table_name, &self.chain_name, self.family);
        rule.set_handle(handle);
        
        batch.add(&rule, nftnl::MsgType::Del);
        let finalized_batch = batch.finalize();
        
        self.send_batch(finalized_batch).await?;
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
                        rules_to_remove.push((rule_id.clone(), rule.handle));
                    }
                }
            }
        }
        
        // 移除过期规则
        for (rule_id, handle) in rules_to_remove {
            if let Err(e) = self.remove_rule_by_handle(handle).await {
                warn!("移除过期规则 {} 失败: {}", rule_id, e);
                continue;
            }
            self.rules.write().await.remove(&rule_id);
            expired_rules.push(rule_id);
        }
        
        if !expired_rules.is_empty() {
            info!("清理了 {} 个过期规则", expired_rules.len());
        }
        
        Ok(expired_rules)
    }

    /// 获取所有活跃规则
    pub async fn get_active_rules(&self) -> Result<Vec<FirewallRule>> {
        let rules = self.rules.read().await;
        Ok(rules.values().cloned().collect())
    }

    /// 清理所有自管理规则
    pub async fn cleanup(&self) -> Result<()> {
        let rule_count = {
            let rules = self.rules.read().await;
            rules.len()
        };
        
        if rule_count == 0 {
            info!("没有规则需要清理");
            return Ok(());
        }
        
        // 刷新整个链
        let mut batch = Batch::new();
        let chain = Chain::new(&self.table_name, &self.chain_name, self.family);
        batch.add(&chain, nftnl::MsgType::DelRule);
        
        let finalized_batch = batch.finalize();
        self.send_batch(finalized_batch).await?;
        
        // 清空内存中的规则记录
        self.rules.write().await.clear();
        
        info!("已清理所有 {} 规则 (共 {} 条)", self.chain_name, rule_count);
        Ok(())
    }

    /// 生成规则句柄（简化实现）
    fn generate_handle(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::time::{sleep, Duration as TokioDuration};

    /// 创建测试用防火墙实例
    async fn create_test_firewall() -> Firewall {
        Firewall::new(
            Some("test_filter"),
            Some("TEST_CHAIN"),
            Some(ProtoFamily::Ipv4),
        )
        .await
        .expect("Failed to create test firewall")
    }

    #[tokio::test]
    async fn test_firewall_creation() {
        let firewall = create_test_firewall().await;
        assert_eq!(firewall.table_name, "test_filter");
        assert_eq!(firewall.chain_name, "TEST_CHAIN");
        assert_eq!(firewall.family, ProtoFamily::Ipv4);
    }

    #[tokio::test]
    async fn test_limit_rule() {
        let firewall = create_test_firewall().await;
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        
        let rule_id = firewall.limit(ip, 1000).await.expect("Failed to create limit rule");
        assert!(!rule_id.is_empty());
        
        // 验证规则存在
        let rules = firewall.get_active_rules().await.expect("Failed to get rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].ip, ip);
        
        if let RuleType::Limit { kbps, burst } = rules[0].rule_type {
            assert_eq!(kbps, 1000);
            assert_eq!(burst, 100); // 1000 / 10
        } else {
            panic!("Expected limit rule type");
        }
    }

    #[tokio::test]
    async fn test_ban_rule() {
        let firewall = create_test_firewall().await;
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
        let duration = Duration::minutes(30);
        
        let rule_id = firewall.ban(ip, duration).await.expect("Failed to create ban rule");
        assert!(!rule_id.is_empty());
        
        // 验证规则存在
        let rules = firewall.get_active_rules().await.expect("Failed to get rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].ip, ip);
        
        if let RuleType::Ban { until } = rules[0].rule_type {
            assert!(until > Utc::now());
            assert!(until <= Utc::now() + duration + Duration::seconds(1));
        } else {
            panic!("Expected ban rule type");
        }
    }

    #[tokio::test]
    async fn test_unban() {
        let firewall = create_test_firewall().await;
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 300));
        
        // 首先封禁IP
        firewall.ban(ip, Duration::hours(1)).await.expect("Failed to ban IP");
        
        // 验证规则存在
        let rules = firewall.get_active_rules().await.expect("Failed to get rules");
        assert_eq!(rules.len(), 1);
        
        // 解封IP
        let removed_rules = firewall.unban(ip).await.expect("Failed to unban IP");
        assert_eq!(removed_rules.len(), 1);
        
        // 验证规则已移除
        let rules = firewall.get_active_rules().await.expect("Failed to get rules");
        assert_eq!(rules.len(), 0);
    }

    #[tokio::test]
    async fn test_duplicate_rules() {
        let firewall = create_test_firewall().await;
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 400));
        
        // 创建两个相同的限制规则
        let rule_id1 = firewall.limit(ip, 500).await.expect("Failed to create first rule");
        let rule_id2 = firewall.limit(ip, 500).await.expect("Failed to create second rule");
        
        // 应该返回相同的规则ID
        assert_eq!(rule_id1, rule_id2);
        
        // 只应该有一个规则
        let rules = firewall.get_active_rules().await.expect("Failed to get rules");
        assert_eq!(rules.len(), 1);
    }

    #[tokio::test]
    async fn test_multiple_ips() {
        let firewall = create_test_firewall().await;
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
        let ip3 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 30));
        
        // 为不同IP创建不同类型的规则
        firewall.limit(ip1, 1000).await.expect("Failed to limit ip1");
        firewall.ban(ip2, Duration::hours(1)).await.expect("Failed to ban ip2");
        firewall.limit(ip3, 2000).await.expect("Failed to limit ip3");
        
        // 验证所有规则都存在
        let rules = firewall.get_active_rules().await.expect("Failed to get rules");
        assert_eq!(rules.len(), 3);
        
        // 验证每个IP的规则类型
        let mut limit_count = 0;
        let mut ban_count = 0;
        
        for rule in rules {
            match rule.rule_type {
                RuleType::Limit { .. } => limit_count += 1,
                RuleType::Ban { .. } => ban_count += 1,
            }
        }
        
        assert_eq!(limit_count, 2);
        assert_eq!(ban_count, 1);
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let firewall = create_test_firewall().await;
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 500));
        
        // 创建一个很短时间的封禁
        firewall.ban(ip, Duration::milliseconds(100)).await.expect("Failed to ban IP");
        
        // 等待规则过期
        sleep(TokioDuration::from_millis(200)).await;
        
        // 清理过期规则
        let expired_rules = firewall.cleanup_expired().await.expect("Failed to cleanup expired rules");
        assert_eq!(expired_rules.len(), 1);
        
        // 验证规则已被清理
        let rules = firewall.get_active_rules().await.expect("Failed to get rules");
        assert_eq!(rules.len(), 0);
    }

    #[tokio::test]
    async fn test_cleanup_all() {
        let firewall = create_test_firewall().await;
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
        
        // 创建多个规则
        firewall.limit(ip1, 1000).await.expect("Failed to limit ip1");
        firewall.ban(ip2, Duration::hours(1)).await.expect("Failed to ban ip2");
        
        // 验证规则存在
        let rules = firewall.get_active_rules().await.expect("Failed to get rules");
        assert_eq!(rules.len(), 2);
        
        // 清理所有规则
        firewall.cleanup().await.expect("Failed to cleanup all rules");
        
        // 验证所有规则已被清理
        let rules = firewall.get_active_rules().await.expect("Failed to get rules");
        assert_eq!(rules.len(), 0);
    }

    #[tokio::test]
    async fn test_ipv6_support() {
        let firewall = Firewall::new(
            Some("test_filter_v6"),
            Some("TEST_CHAIN_V6"),
            Some(ProtoFamily::Ipv6),
        )
        .await
        .expect("Failed to create IPv6 firewall");
        
        let ipv6 = "2001:db8::1".parse::<IpAddr>().expect("Invalid IPv6 address");
        
        let rule_id = firewall.limit(ipv6, 5000).await.expect("Failed to create IPv6 limit rule");
        assert!(!rule_id.is_empty());
        
        let rules = firewall.get_active_rules().await.expect("Failed to get rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].ip, ipv6);
    }

    #[tokio::test]
    async fn test_rule_persistence() {
        let firewall = create_test_firewall().await;
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 123));
        
        // 创建规则并记录ID
        let rule_id = firewall.limit(ip, 2000).await.expect("Failed to create rule");
        
        // 获取规则并验证所有字段
        let rules = firewall.get_active_rules().await.expect("Failed to get rules");
        let rule = &rules[0];
        
        assert_eq!(rule.id, rule_id);
        assert_eq!(rule.ip, ip);
        assert!(rule.handle > 0);
        assert!(rule.created_at <= Utc::now());
        
        if let RuleType::Limit { kbps, burst } = rule.rule_type {
            assert_eq!(kbps, 2000);
            assert_eq!(burst, 200); // 2000 / 10
        } else {
            panic!("Expected limit rule type");
        }
    }
}