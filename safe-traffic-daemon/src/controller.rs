use crate::nft::{get_parsed_handle, NftError, NftExecutor};
use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use log::{debug, info, warn};
use safe_traffic_common::{
    config::{Action, Config, FamilyType, HookType, PolicyType},
    utils::FirewallRule,
};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;
use tokio::sync::RwLock;

/// 防火墙控制器（使用池化的 nft 执行器）
#[derive(Clone, Debug)]
pub struct Firewall {
    family: FamilyType,
    table_name: String,
    chain_name: String,
    pub hook: HookType,
    priority: i64,
    policy: PolicyType,
    pub rules: Arc<RwLock<HashMap<String, FirewallRule>>>,
    nft_available: bool,
    executor: Arc<NftExecutor>,
    global_exclude: Arc<RwLock<HashSet<IpAddr>>>,
}

#[allow(dead_code)]
impl Firewall {
    /// 初始化防火墙控制器
    pub async fn new(cfg: &Config, executor: Arc<NftExecutor>) -> Result<Self> {
        let family = cfg.family.clone().unwrap_or(FamilyType::Inet);
        let table_name = cfg
            .table_name
            .clone()
            .unwrap_or("traffic_filter".to_string());
        let chain_name = cfg
            .chain_name
            .clone()
            .unwrap_or("traffic_input".to_string());
        let hook = cfg.hook.clone().unwrap_or(HookType::Input);
        let priority = cfg.priority.unwrap_or(0);
        let policy = cfg.policy.clone().unwrap_or(PolicyType::Accept);
        let global_exclude = Arc::new(RwLock::new(cfg.global_exclude.clone().unwrap_or_default()));

        // 检查 nftables 是否可用
        let nft_available = crate::nft::check_nftables_available().await?;

        let firewall = Firewall {
            family,
            table_name,
            chain_name,
            hook,
            priority,
            policy,
            rules: Arc::new(RwLock::new(HashMap::new())),
            nft_available,
            executor,
            global_exclude,
        };

        if firewall.nft_available {
            // 初始化表和链
            firewall.init_table_and_chain().await?;
        } else {
            warn!("nftables is unavailable, using mock mode instead");
        }

        Ok(firewall)
    }

    /// 检查 nftables 是否可用
    /// 初始化 nftables 表和链
    async fn init_table_and_chain(&self) -> Result<()> {
        let commands = vec![
            format!("add table {} {}", self.family, self.table_name),
            format!(
                "add chain {} {} {} {{ type filter hook {} priority {}  ; policy {} ; }}",
                self.family,
                self.table_name,
                self.chain_name,
                self.hook,
                self.priority,
                self.policy
            ),
        ];

        // self.executor.input(&commands[0]).await?;
        // self.executor.input(&commands[1]).await?;
        match self.executor.execute_batch(commands).await {
            Ok(_s) => {}
            Err(e) => {
                // 试着把 anyhow::Error 转回 NftError
                if let Some(NftError::Timeout) = e.downcast_ref::<NftError>() {
                    warn!("timeout, maybe controller already exist");
                    // 如果想吞掉错误，返回 Ok 或继续
                    return Ok(());
                }
                // 其他错误按原样 return
                return Err(e);
            }
        };

        debug!(
            "Table {} and chain {} initialized",
            self.table_name, self.chain_name
        );
        Ok(())
    }

    /// 对指定 IP 设置永久速率限制
    pub async fn infinity_limit(
        &self,
        ip: IpAddr,
        kbps: u64,
        burst: Option<u64>,
    ) -> Result<String> {
        let rule_id = format!("limit_{}_{}", ip, kbps);
        let burst = if let Some(bur) = burst {
            bur
        } else {
            kbps.min(1024) / 10
        };

        // 检查是否已存在相同规则
        {
            let rules = self.rules.read().await;
            if let Some(existing_rule) = rules.get(&rule_id) {
                if let Action::RateLimit {
                    kbps: existing_kbps,
                    ..
                } = existing_rule.rule_type
                {
                    if existing_kbps == kbps {
                        debug!("Rule {} already exists, skipping creation", rule_id);
                        return Ok(rule_id);
                    }
                }
            }
        }

        let (handle, handle1) = self.create_limit_rule(ip, kbps, burst).await?;

        let rule = FirewallRule {
            id: rule_id.clone(),
            ip,
            rule_type: Action::RateLimit {
                kbps,
                burst: Some(burst),
                seconds: None,
            },
            created_at: Utc::now(),
            handle: vec![handle, handle1],
        };

        self.rules.write().await.insert(rule_id.clone(), rule);
        info!(
            "Set speed limit for {}: {} KB/s (burst: {} KB)",
            ip, kbps, burst
        );

        Ok(rule_id)
    }

    pub async fn limit(
        &self,
        ip: IpAddr,
        kbps: u64,
        burst: Option<u64>,
        seconds: Option<u64>,
    ) -> Result<String> {
        if seconds.is_none() {
            return self.infinity_limit(ip, kbps, burst).await;
        };
        let seconds = seconds.unwrap();

        let duration = Duration::seconds(seconds as i64);

        let burst = if let Some(bur) = burst {
            bur
        } else {
            kbps.min(1024) / 10
        };
        let rule_id = format!("limit_{}_{}_{}_{}", ip, kbps, burst, seconds);

        // 检查是否已存在相同规则
        {
            let rules = self.rules.read().await;

            if let Some(rule) = rules.get(&rule_id) {
                if let Action::RateLimit {
                    kbps: existing_kbps,
                    seconds: sec,
                    ..
                } = rule.rule_type
                {
                    let existing_until = rule.created_at + duration;
                    if existing_until > Utc::now() && existing_kbps == kbps && sec == Some(seconds)
                    {
                        debug!(
                            "IP {} has already been banned until {}, skipping",
                            ip, existing_until
                        );
                        return Ok(rule.id.clone());
                    }
                }
            }
            // }
        }

        let (handle, handle1) = self.create_limit_rule(ip, kbps, burst).await?;

        let rule = FirewallRule {
            id: rule_id.clone(),
            ip,
            rule_type: Action::RateLimit {
                kbps,
                burst: Some(burst),
                seconds: Some(seconds),
            },
            created_at: Utc::now(),
            handle: vec![handle, handle1],
        };

        self.rules.write().await.insert(rule_id.clone(), rule);
        info!(
            "Set speed limit for {}: {} KB/s (burst: {} KB)",
            ip, kbps, burst
        );

        Ok(rule_id)
    }

    async fn is_nft_available(&self) -> bool {
        self.nft_available
    }

    /// 创建速率限制规则
    async fn create_limit_rule(
        &self,
        ip: IpAddr,
        kbps: u64,
        burst: u64,
    ) -> Result<(String, String)> {
        let direction = match self.hook {
            HookType::Input => "saddr",
            HookType::Output => "daddr",
        };

        let ip_version = match ip {
            IpAddr::V4(_) => "ip",
            IpAddr::V6(_) => "ip6",
        };

        let rule_cmd = format!(
            "add rule {} {} {} {} {} {} limit rate {} kbytes/second burst {} kbytes accept",
            self.family, self.table_name, self.chain_name, ip_version, direction, ip, kbps, burst,
        );

        let output_with_handle = self.executor.execute(&rule_cmd).await?;
        let handle = get_parsed_handle(output_with_handle).await?;

        let rule_cmd1 = format!(
            "add rule {} {} {} {} {} {} drop",
            self.family, self.table_name, self.chain_name, ip_version, direction, ip,
        );
        let output_with_handle1 = self.executor.execute(&rule_cmd1).await?;

        let handle1 = get_parsed_handle(output_with_handle1).await?;

        Ok((handle, handle1))
    }

    /// 对指定 IP 封禁指定时长
    pub async fn ban(&self, ip: IpAddr, seconds: Option<u64>) -> Result<String> {
        if seconds.is_none() {
            return self.infinity_ban(ip).await;
        };
        let seconds = seconds.unwrap();
        let duration = Duration::seconds(seconds as i64);
        let now = Utc::now();
        let until = now + duration;
        // let rule_id = format!("ban_{}_{}", ip, until.timestamp());
        let rule_id = format!("ban_{}_{}", ip, seconds);

        // 检查是否已被封禁
        {
            let rules = self.rules.read().await;
            // for (_, rule) in rules.iter() {
            // if rule.ip == ip {
            if let Some(rule) = rules.get(&rule_id) {
                if let Action::Ban { seconds: _sec } = rule.rule_type {
                    let existing_until = rule.created_at + duration;
                    if existing_until > Utc::now() {
                        debug!(
                            "IP {} has already been banned until {}, skipping",
                            ip, existing_until
                        );
                        return Ok(rule.id.clone());
                    }
                }
            }
            // }
        }

        let handle = self.create_ban_rule(ip).await?;
        // let handle = get_parsed_handle(output_with_handle).await?;

        let rule = FirewallRule {
            id: rule_id.clone(),
            ip,
            rule_type: Action::Ban {
                seconds: Some(seconds),
            },
            created_at: now,
            handle: vec![handle],
        };

        self.rules.write().await.insert(rule_id.clone(), rule);
        info!("Banned {} until {} \n rule id : {}", ip, until, &rule_id);

        Ok(rule_id)
    }

    pub async fn infinity_ban(&self, ip: IpAddr) -> Result<String> {
        let now = Utc::now();
        let rule_id = format!("ban_{}", ip);

        {
            let rules = self.rules.read().await;
            if let Some(_existing_rule) = rules.get(&rule_id) {
                debug!("Rule {} already exists, skipping creation", rule_id);
                return Ok(rule_id);
            }
        }

        let handle = self.create_ban_rule(ip).await?;
        // let handle = get_parsed_handle(output_with_handle).await?;

        let rule = FirewallRule {
            id: rule_id.clone(),
            ip,
            rule_type: Action::Ban { seconds: None },
            created_at: now,
            handle: vec![handle],
        };

        self.rules.write().await.insert(rule_id.clone(), rule);
        info!("Banned {} infinity   \n rule id : {}", ip, &rule_id);

        Ok(rule_id)
    }

    /// 创建封禁规则
    async fn create_ban_rule(&self, ip: IpAddr) -> Result<String> {
        let direction = match self.hook {
            HookType::Input => "saddr",
            HookType::Output => "daddr",
        };
        let ip_version = match ip {
            IpAddr::V4(_) => "ip",
            IpAddr::V6(_) => "ip6",
        };

        let rule_cmd = format!(
            "add rule {} {} {} {} {} {} drop",
            self.family, self.table_name, self.chain_name, ip_version, direction, ip
        );

        let output_with_handle = self.executor.execute(&rule_cmd).await?;
        let handle = get_parsed_handle(output_with_handle).await?;

        Ok(handle)
    }

    pub async fn is_expiration(&self, rule_id: &str, seconds: u64, action: &Action) -> bool {
        let duration = Duration::seconds(seconds as i64);
        let now = Utc::now();
        let rules = self.rules.read().await;
        if let Some(rule) = rules.get(rule_id) {
            if &rule.rule_type != action {
                return false;
            }
            // for (_, rule) in rules.iter() {
            // if rule.ip == ip {
            let expiration = rule.created_at + duration;

            now > expiration
        } else {
            false
        }
        // }
    }

    /// 解封指定IP
    pub async fn unblock(&self, id: &str) -> Result<()> {
        debug!("get RwLock to remove rule : {}", id);

        let handles: Vec<String> = {
            let rules = self.rules.read().await;
            let rule = rules
                .get(id)
                .ok_or_else(|| anyhow!("fail to get rule by id: {}", id))?;
            rule.handle.clone()
            // .ok_or_else(|| anyhow!("rule has no handle: {}", id))?
        };
        for handle in handles {
            self.remove_rule_by_handle(&handle).await?;
        }

        let removed = {
            let mut rules = self.rules.write().await;
            rules.remove(id)
        };

        if removed.is_some() {
            info!("Unblocked successful,\n remove rule: {}", id);
        } else {
            warn!("fail to remove rule, maybe not exist: {}", id);
            return Err(anyhow!("fail to remove rule, maybe not exist: {}", id));
        }

        Ok(())
    }

    /// 根据句柄移除规则
    async fn remove_rule_by_handle(&self, handle: &str) -> Result<()> {
        debug!("Removing rule by handle: {}", handle);

        let remove_command = format!(
            "delete rule {} {} {} handle {}",
            self.family, self.table_name, self.chain_name, handle
        );

        self.executor.input(&remove_command).await?;

        debug!("execute command to delete nft rule: {}", &remove_command);

        Ok(())
    }

    /// 获取所有活跃规则
    pub async fn get_active_rules(&self) -> Result<Vec<FirewallRule>> {
        let rules = self.rules.read().await;
        Ok(rules.values().cloned().collect())
    }

    /// 获取当前 nftables 规则（从系统读取）
    pub async fn get_system_rules(&self) -> Result<String> {
        if !self.is_nft_available().await {
            return Ok("nftables not available".to_string());
        }

        let list_cmd = format!(
            "list chain {} {} {}",
            self.family, self.table_name, self.chain_name
        );
        self.executor.execute(&list_cmd).await
    }

    /// 清理所有自管理规则
    pub async fn flush(&self) -> Result<usize> {
        let rule_count = {
            let rules = self.rules.read().await;
            rules.len()
        };

        if rule_count == 0 {
            info!("No rules to clean up");
            return Ok(0);
        }

        // 清空链中的所有规则
        let flush_cmd = format!(
            "flush chain {} {} {}",
            self.family, self.table_name, self.chain_name
        );
        self.executor.input(&flush_cmd).await?;

        // 清空内存中的规则记录
        self.rules.write().await.clear();

        info!(
            "Cleaned up all rules in chain {} (count: {})",
            self.chain_name, rule_count
        );
        Ok(rule_count)
    }

    pub async fn cleanup(&self) -> Result<()> {
        let rule_count = {
            let rules = self.rules.read().await;
            rules.len()
        };

        // if rule_count == 0 {
        // info!("No rules to clean up");
        // return Ok(());
        // }

        let delete_cmd = format!("delete table {} {}", self.family, self.table_name);
        self.executor.input(&delete_cmd).await?;
        let _ = self.executor.execute("list tables").await?;

        // 清空内存中的规则记录
        self.rules.write().await.clear();

        info!(
            "Cleaned up all rules in chain {} (count: {})",
            self.chain_name, rule_count
        );
        Ok(())
    }

    /// 检查防火墙状态
    pub async fn status(&self) -> Result<String> {
        let rules = self.rules.read().await;
        let active_count = rules.len();
        let expired_count = rules
            .values()
            .filter(|rule| {
                if let Action::Ban { seconds } = rule.rule_type {
                    let duration = if let Some(seconds) = seconds {
                        Duration::seconds(seconds as i64)
                    } else {
                        Duration::seconds(0)
                    };
                    let until = Utc::now() + duration;
                    until <= Utc::now()
                } else {
                    false
                }
            })
            .count();

        let (pool_size, available_permits) = self.executor.get_pool_stats().await;

        Ok(format!(
            "防火墙状态:\n- nftables 可用: {}\n- 活跃规则: {}\n- 过期规则: {}\n- 表名: {}\n- 链名: {}\n- 执行器池大小: {}\n- 可用执行器: {}",
            self.is_nft_available().await, active_count, expired_count, self.table_name, self.chain_name, pool_size, available_permits
        ))
    }

    /// 批量封禁
    pub async fn batch_ban(&self, ips: Vec<IpAddr>, seconds: Option<u64>) -> Result<Vec<String>> {
        let mut handles = Vec::with_capacity(ips.len());
        let mut rule_ids = Vec::with_capacity(ips.len());

        let seconds = if let Some(seconds) = seconds {
            seconds
        } else {
            for ip in ips {
                let rule_id = self.infinity_ban(ip).await?;
                rule_ids.push(rule_id);
            }
            return Ok(rule_ids);
        };

        let duration = Duration::seconds(seconds as i64);
        let until = Utc::now() + duration;

        for ip in ips.clone() {
            let rule_id = format!("ban_{}_{}", ip, seconds);
            let handle = self.create_ban_rule(ip).await?;
            // let handle = get_parsed_handle(output_with_handle).await?;

            handles.push(handle);
            rule_ids.push(rule_id);
        }

        // 批量更新内存中的规则
        {
            let mut rules = self.rules.write().await;
            for (i, ip) in ips.into_iter().enumerate() {
                let rule = FirewallRule {
                    id: rule_ids[i].clone(),
                    ip,
                    rule_type: Action::Ban {
                        seconds: Some(seconds),
                    },
                    created_at: Utc::now(),
                    handle: vec![handles[i].clone()],
                };
                rules.insert(rule_ids[i].clone(), rule);
            }
        }

        info!("Batch banned {} IPs until {}", rule_ids.len(), until);
        Ok(rule_ids)
    }

    /// 批量封禁
    pub async fn batch_limit(
        &self,
        ips: Vec<IpAddr>,
        kbps: u64,
        burst: Option<u64>,
        seconds: Option<u64>,
    ) -> Result<Vec<String>> {
        let mut handles = Vec::with_capacity(ips.len());
        let mut rule_ids = Vec::with_capacity(ips.len());

        let seconds = if let Some(seconds) = seconds {
            seconds
        } else {
            for ip in ips {
                let rule_id = self.infinity_limit(ip, kbps, burst).await?;
                rule_ids.push(rule_id);
            }
            return Ok(rule_ids);
        };

        let duration = Duration::seconds(seconds as i64);
        let until = Utc::now() + duration;

        let burst = if let Some(bur) = burst {
            bur
        } else {
            kbps.min(1024) / 10
        };

        for ip in ips.clone() {
            let rule_id = format!("limit_{}_{}", ip, until.timestamp());
            let handle_unit = self.create_limit_rule(ip, kbps, burst).await?;
            handles.push(handle_unit);
            rule_ids.push(rule_id);
        }

        // 批量更新内存中的规则
        {
            let mut rules = self.rules.write().await;
            for (i, ip) in ips.into_iter().enumerate() {
                let rule = FirewallRule {
                    id: rule_ids[i].clone(),
                    ip,
                    rule_type: Action::RateLimit {
                        kbps,
                        burst: Some(burst),
                        seconds: Some(seconds),
                    },
                    created_at: Utc::now(),
                    handle: vec![handles[i].0.clone(), handles[i].1.clone()],
                };
                rules.insert(rule_ids[i].clone(), rule);
            }
        }

        info!("Batch limited {} IPs until {}", rule_ids.len(), until);
        Ok(rule_ids)
    }

    pub async fn is_excluded(&self, ip: &IpAddr) -> bool {
        self.global_exclude.read().await.contains(ip)
    }

    pub async fn add_exclude(&self, ip: &IpAddr) -> Result<()> {
        if self.global_exclude.write().await.insert(*ip) {
            Ok(())
        } else {
            Err(anyhow!("fail to add {} to global exclude", ip))
        }
    }
}

impl Firewall {
    pub async fn ban_cidr(&self, cidr: IpNet, seconds: Option<u64>) -> Result<String> {
        if seconds.is_none() {
            return self.infinity_ban_cidr(cidr).await;
        };
        let seconds = seconds.unwrap();
        let duration = Duration::seconds(seconds as i64);
        let now = Utc::now();
        let until = now + duration;
        let rule_id = format!("ban_{}_{}", cidr, seconds);

        // 检查是否已被封禁
        {
            let rules = self.rules.read().await;
            if let Some(rule) = rules.get(&rule_id) {
                if let Action::Ban { seconds: _sec } = rule.rule_type {
                    let existing_until = rule.created_at + duration;
                    if existing_until > Utc::now() {
                        debug!(
                            "IP {} has already been banned until {}, skipping",
                            cidr.clone(),
                            existing_until
                        );
                        return Ok(rule.id.clone());
                    }
                }
            }
            // }
        }

        let handle = self.create_ban_cidr_rule(cidr).await?;
        // let handle = get_parsed_handle(output_with_handle).await?;
        let ip = cidr.network();

        let rule = FirewallRule {
            id: rule_id.clone(),
            ip,
            rule_type: Action::Ban {
                seconds: Some(seconds),
            },
            created_at: now,
            handle: vec![handle],
        };

        self.rules.write().await.insert(rule_id.clone(), rule);
        info!("Banned {} until {} \n rule id : {}", ip, until, &rule_id);

        Ok(rule_id)
    }

    async fn create_ban_cidr_rule(&self, cidr: IpNet) -> Result<String> {
        let direction = match self.hook {
            HookType::Input => "saddr",
            HookType::Output => "daddr",
        };
        let ip_version = match cidr {
            IpNet::V4(_v4net) => "ip",
            IpNet::V6(_v6net) => "ip6",
        };
        let rule_cmd = format!(
            "add rule {} {} {} {} {} {} drop",
            self.family, self.table_name, self.chain_name, ip_version, direction, cidr
        );

        let output_with_handle = self.executor.execute(&rule_cmd).await?;
        let handle = get_parsed_handle(output_with_handle).await?;

        Ok(handle)
    }

    pub async fn infinity_ban_cidr(&self, cidr: IpNet) -> Result<String> {
        let now = Utc::now();
        let rule_id = format!("ban_{}", cidr);

        {
            let rules = self.rules.read().await;
            if let Some(_existing_rule) = rules.get(&rule_id) {
                debug!("Rule {} already exists, skipping creation", rule_id);
                return Ok(rule_id);
            }
        }

        let handle = self.create_ban_cidr_rule(cidr).await?;
        // let handle = get_parsed_handle(output_with_handle).await?;
        let ip = cidr.network();

        let rule = FirewallRule {
            id: rule_id.clone(),
            ip,
            rule_type: Action::Ban { seconds: None },
            created_at: now,
            handle: vec![handle],
        };

        self.rules.write().await.insert(rule_id.clone(), rule);
        info!("Banned {} infinity   \n rule id : {}", cidr, &rule_id);

        Ok(rule_id)
    }

    pub async fn limit_cidr(
        &self,
        cidr: IpNet,
        kbps: u64,
        burst: Option<u64>,
        seconds: Option<u64>,
    ) -> Result<String> {
        if seconds.is_none() {
            return self.infinity_limit_cidr(cidr, kbps, burst).await;
        };
        let seconds = seconds.unwrap();
        let duration = Duration::seconds(seconds as i64);

        let burst = if let Some(bur) = burst {
            bur
        } else {
            kbps.min(1024) / 10
        };
        let rule_id = format!("limit_{}_{}_{}_{}", cidr, kbps, burst, seconds);

        // 检查是否已存在相同规则
        {
            let rules = self.rules.read().await;
            if let Some(rule) = rules.get(&rule_id) {
                if let Action::RateLimit {
                    kbps: existing_kbps,
                    seconds: sec,
                    ..
                } = rule.rule_type
                {
                    let existing_until = rule.created_at + duration;
                    if existing_until > Utc::now() && existing_kbps == kbps && sec == Some(seconds)
                    {
                        debug!(
                            "IP {} has already been banned until {}, skipping",
                            cidr, existing_until
                        );
                        return Ok(rule.id.clone());
                    }
                }
            }
        }

        let (handle, handle1) = self.create_limit_cidr_rule(cidr, kbps, burst).await?;
        let ip = cidr.network();

        let rule = FirewallRule {
            id: rule_id.clone(),
            ip,
            rule_type: Action::RateLimit {
                kbps,
                burst: Some(burst),
                seconds: Some(seconds),
            },
            created_at: Utc::now(),
            handle: vec![handle, handle1],
        };

        self.rules.write().await.insert(rule_id.clone(), rule);
        info!(
            "Set speed limit for {}: {} KB/s (burst: {} KB)",
            ip, kbps, burst
        );

        Ok(rule_id)
    }

    async fn create_limit_cidr_rule(
        &self,
        cidr: IpNet,
        kbps: u64,
        burst: u64,
    ) -> Result<(String, String)> {
        let direction = match self.hook {
            HookType::Input => "saddr",
            HookType::Output => "daddr",
        };
        let ip_version = match cidr {
            IpNet::V4(_v4net) => "ip",
            IpNet::V6(_v6net) => "ip6",
        };

        let rule_cmd = format!(
            "add rule {} {} {} {} {} {} limit rate {} kbytes/second burst {} kbytes accept",
            self.family, self.table_name, self.chain_name, ip_version, direction, cidr, kbps, burst,
        );

        let output_with_handle = self.executor.execute(&rule_cmd).await?;
        let handle = get_parsed_handle(output_with_handle).await?;

        let rule_cmd1 = format!(
            "add rule {} {} {} {} {} {} drop",
            self.family, self.table_name, self.chain_name, ip_version, direction, cidr,
        );
        let output_with_handle1 = self.executor.execute(&rule_cmd1).await?;

        let handle1 = get_parsed_handle(output_with_handle1).await?;

        Ok((handle, handle1))
    }

    pub async fn infinity_limit_cidr(
        &self,
        cidr: IpNet,
        kbps: u64,
        burst: Option<u64>,
    ) -> Result<String> {
        let burst = if let Some(bur) = burst {
            bur
        } else {
            kbps.min(1024) / 10
        };
        let rule_id = format!("limit_{}_{}_{}", cidr, kbps, burst);

        // 检查是否已存在相同规则
        {
            let rules = self.rules.read().await;
            if let Some(existing_rule) = rules.get(&rule_id) {
                if let Action::RateLimit {
                    kbps: existing_kbps,
                    ..
                } = existing_rule.rule_type
                {
                    if existing_kbps == kbps {
                        debug!("Rule {} already exists, skipping creation", rule_id);
                        return Ok(rule_id);
                    }
                }
            }
        }

        let (handle, handle1) = self.create_limit_cidr_rule(cidr, kbps, burst).await?;
        let ip = cidr.network();

        let rule = FirewallRule {
            id: rule_id.clone(),
            ip,
            rule_type: Action::RateLimit {
                kbps,
                burst: Some(burst),
                seconds: None,
            },
            created_at: Utc::now(),
            handle: vec![handle, handle1],
        };

        self.rules.write().await.insert(rule_id.clone(), rule);
        info!(
            "Set speed limit for {}: {} KB/s (burst: {} KB)",
            ip, kbps, burst
        );

        Ok(rule_id)
    }
}

#[async_trait::async_trait]
pub trait Controllable: Send + Sync + 'static {
    type Controller;
    async fn ban(&self, seconds: Option<u64>, controller: &Self::Controller)
        -> Result<Vec<String>>;
    async fn limit(
        &self,
        kbps: u64,
        burst: Option<u64>,
        seconds: Option<u64>,
        controller: &Self::Controller,
    ) -> Result<Vec<String>>;
    async fn to_handle(&self) -> Result<Vec<String>>;
}

#[async_trait::async_trait]
impl Controllable for IpAddr {
    type Controller = Arc<Firewall>;

    async fn ban(
        &self,
        seconds: Option<u64>,
        controller: &Self::Controller,
    ) -> Result<Vec<String>> {
        let rule_id = controller.ban(self.clone(), seconds).await?;
        Ok(vec![rule_id])
    }

    async fn limit(
        &self,
        kbps: u64,
        burst: Option<u64>,
        seconds: Option<u64>,
        controller: &Self::Controller,
    ) -> Result<Vec<String>> {
        let rule_id = controller.limit(self.clone(), kbps, burst, seconds).await?;
        Ok(vec![rule_id])
    }

    async fn to_handle(&self) -> Result<Vec<String>> {
        Ok(vec![self.clone().to_string()])
    }
}

#[async_trait::async_trait]
impl Controllable for Vec<IpAddr> {
    type Controller = Arc<Firewall>;

    async fn ban(
        &self,
        seconds: Option<u64>,
        controller: &Self::Controller,
    ) -> Result<Vec<String>> {
        controller.batch_ban(self.clone(), seconds).await
    }

    async fn limit(
        &self,
        kbps: u64,
        burst: Option<u64>,
        seconds: Option<u64>,
        controller: &Self::Controller,
    ) -> Result<Vec<String>> {
        controller
            .batch_limit(self.clone(), kbps, burst, seconds)
            .await
    }

    async fn to_handle(&self) -> Result<Vec<String>> {
        let handles: Vec<String> = self.iter().map(|v| v.to_string()).collect();
        Ok(handles)
    }
}

#[async_trait::async_trait]
impl Controllable for safe_traffic_common::transport::Request {
    type Controller = Arc<Firewall>;

    async fn ban(
        &self,
        _seconds: Option<u64>,
        controller: &Self::Controller,
    ) -> Result<Vec<String>> {
        let rule_ids = match self {
            Self::BatchBan { ips, seconds } => ips.ban(*seconds, &controller).await?,
            _ => {
                unimplemented!()
            }
        };
        Ok(rule_ids)
    }

    async fn limit(
        &self,
        _kbps: u64,
        _burst: Option<u64>,
        _seconds: Option<u64>,
        _controller: &Self::Controller,
    ) -> Result<Vec<String>> {
        unimplemented!()
    }

    async fn to_handle(&self) -> Result<Vec<String>> {
        let handles = match self {
            Self::BatchBan {
                ips,
                seconds: _seconds,
            } => ips.to_handle().await?,
            _ => {
                unimplemented!()
            }
        };
        Ok(handles)
    }
}

#[async_trait::async_trait]
impl Controllable for IpNet {
    type Controller = Arc<Firewall>;

    async fn ban(
        &self,
        seconds: Option<u64>,
        controller: &Self::Controller,
    ) -> Result<Vec<String>> {
        let rule_id = controller.ban_cidr(self.clone(), seconds).await?;
        Ok(vec![rule_id])
    }

    async fn limit(
        &self,
        kbps: u64,
        burst: Option<u64>,
        seconds: Option<u64>,
        controller: &Self::Controller,
    ) -> Result<Vec<String>> {
        let rule_id = controller
            .limit_cidr(self.clone(), kbps, burst, seconds)
            .await?;
        Ok(vec![rule_id])
    }

    async fn to_handle(&self) -> Result<Vec<String>> {
        Ok(vec![self.network().clone().to_string()])
    }
}

#[async_trait::async_trait]
impl Controllable for Vec<IpNet> {
    type Controller = Arc<Firewall>;

    async fn ban(
        &self,
        seconds: Option<u64>,
        controller: &Self::Controller,
    ) -> Result<Vec<String>> {
        let mut rule_ids = Vec::with_capacity(self.len());
        for cidr in self {
            let mut rule_vec = cidr.ban(seconds, &controller).await?;
            rule_ids.append(&mut rule_vec);
        }

        Ok(rule_ids)
    }

    async fn limit(
        &self,
        kbps: u64,
        burst: Option<u64>,
        seconds: Option<u64>,
        controller: &Self::Controller,
    ) -> Result<Vec<String>> {
        let mut rule_ids = Vec::with_capacity(self.len());
        for cidr in self {
            let mut rule_vec = cidr.limit(kbps, burst, seconds, &controller).await?;
            rule_ids.append(&mut rule_vec);
        }

        Ok(rule_ids)
    }

    async fn to_handle(&self) -> Result<Vec<String>> {
        let handles: Vec<String> = self.iter().map(|v| v.network().to_string()).collect();
        Ok(handles)
    }
}
