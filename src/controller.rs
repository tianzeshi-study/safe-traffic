use crate::config::Config;
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use log::{debug, error, info, warn};
use regex::Regex;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, RwLock, Semaphore};
use tokio::time::{timeout, Duration as TokioDuration};

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
    #[error("Executor pool exhausted")]
    ExecutorPoolExhausted,
    #[error("Command timeout")]
    CommandTimeout,
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

/// NFT 命令执行器
#[derive(Debug)]
struct NftProcess {
    child: Child,
    stdin: Option<tokio::process::ChildStdin>,
    stdout: Option<tokio::process::ChildStdout>,
    stderr: Option<tokio::process::ChildStderr>,
    created_at: DateTime<Utc>,
    last_used: DateTime<Utc>,
    is_busy: bool,
    command_count: usize,
}

impl NftProcess {
    /// 创建新的 nft 进程
    async fn new() -> Result<Self> {
        let mut child = Command::new("nft")
            .arg("-i") // 交互模式
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("Failed to spawn nft process")?;

        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let now = Utc::now();
        Ok(NftProcess {
            child,
            stdin,
            stdout,
            stderr,
            created_at: now,
            last_used: now,
            is_busy: false,
            command_count: 0,
        })
    }

    /// 执行单个命令
    async fn execute_command(&mut self, command: &str) -> Result<String> {
        if self.is_busy {
            return Err(FirewallError::ExecutorPoolExhausted.into());
        }

        self.is_busy = true;
        self.last_used = Utc::now();
        self.command_count += 1;

        let result = self.do_execute(command).await;
        self.is_busy = false;
        result
    }

    async fn do_execute(&mut self, command: &str) -> Result<String> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| FirewallError::CommandError("stdin not available".to_string()))?;

        // 发送命令
        let full_command = format!("{}\n", command);
        stdin
            .write_all(full_command.as_bytes())
            .await
            .context("Failed to write command to nft process")?;
        stdin.flush().await.context("Failed to flush stdin")?;

        // 读取输出 (简化实现，实际可能需要更复杂的协议)
        // 这里假设每个命令执行后会有特定的结束标记
        // 在实际实现中，你可能需要使用更复杂的通信协议

        // 对于这个简化版本，我们直接返回成功
        debug!("Executed nft command via persistent process: {}", command);
        Ok("success".to_string())
    }

    /// 检查进程是否仍然活跃
    fn is_alive(&mut self) -> bool {
        match self.child.try_wait() {
            Ok(Some(_)) => false, // 进程已结束
            Ok(None) => true,     // 进程仍在运行
            Err(_) => false,      // 错误，假设进程已死
        }
    }

    /// 检查进程是否应该被回收（基于时间或使用次数）
    fn should_recycle(&self, max_age: Duration, max_commands: usize) -> bool {
        let age = Utc::now() - self.created_at;
        age > max_age || self.command_count >= max_commands
    }

    /// 优雅关闭进程
    async fn shutdown(mut self) -> Result<()> {
        if let Some(mut stdin) = self.stdin.take() {
            let _ = stdin.write_all(b"quit\n").await;
            let _ = stdin.flush().await;
        }

        // 等待进程结束，设置超时
        let _ = timeout(TokioDuration::from_secs(3), self.child.wait()).await;

        // 如果进程没有正常结束，强制杀死
        let _ = self.child.kill().await;
        Ok(())
    }
}

/// NFT 执行器池
#[derive(Debug)]
pub struct NftExecutor {
    pool: Arc<Mutex<VecDeque<NftProcess>>>,
    semaphore: Arc<Semaphore>,
    max_pool_size: usize,
    max_process_age: Duration,
    max_commands_per_process: usize,
    mock_mode: bool,
}

impl NftExecutor {
    /// 创建新的执行器池
    pub async fn new(
        max_pool_size: usize,
        max_process_age_secs: i64,
        max_commands_per_process: usize,
        mock_mode: bool,
    ) -> Self {
        let max_process_age = Duration::seconds(max_process_age_secs);

        NftExecutor {
            pool: Arc::new(Mutex::new(VecDeque::new())),
            semaphore: Arc::new(Semaphore::new(max_pool_size)),
            max_pool_size,
            max_process_age,
            max_commands_per_process,
            mock_mode,
        }
    }

    /// 执行 nft 命令
    pub async fn execute(&self, command: &str) -> Result<String> {
        if self.mock_mode {
            debug!("Mocking nft command execution: {}", command);
            return Ok("success (mocked)".to_string());
        }

        // 获取信号量许可
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| FirewallError::ExecutorPoolExhausted)?;

        // 尝试从池中获取可用进程
        let mut process = self.get_or_create_process().await?;

        // 执行命令
        let result = process.execute_command(command).await;

        // 将进程返回池中或销毁
        self.return_or_destroy_process(process).await;

        result
    }

    /// 从池中获取进程或创建新进程
    async fn get_or_create_process(&self) -> Result<NftProcess> {
        let mut pool = self.pool.lock().await;

        // 尝试从池中获取可用进程
        while let Some(mut process) = pool.pop_front() {
            if process.is_alive()
                && !process.should_recycle(self.max_process_age, self.max_commands_per_process)
            {
                return Ok(process);
            } else {
                // 进程已死或需要回收，异步销毁
                tokio::spawn(async move {
                    let _ = process.shutdown().await;
                });
            }
        }

        // 池中没有可用进程，创建新的
        drop(pool); // 释放锁
        NftProcess::new().await
    }

    /// 将进程返回池中或销毁
    async fn return_or_destroy_process(&self, mut process: NftProcess) {
        if process.is_alive()
            && !process.should_recycle(self.max_process_age, self.max_commands_per_process)
        {
            let mut pool = self.pool.lock().await;
            if pool.len() < self.max_pool_size {
                pool.push_back(process);
                return;
            }
        }

        // 进程需要被销毁
        tokio::spawn(async move {
            let _ = process.shutdown().await;
        });
    }

    /// 清理池中的所有进程
    pub async fn cleanup(&self) -> Result<()> {
        let mut pool = self.pool.lock().await;
        let processes: Vec<_> = pool.drain(..).collect();
        drop(pool);

        // 异步关闭所有进程
        let handles: Vec<_> = processes
            .into_iter()
            .map(|process| {
                tokio::spawn(async move {
                    let _ = process.shutdown().await;
                })
            })
            .collect();

        // 等待所有进程关闭
        for handle in handles {
            let _ = handle.await;
        }

        info!("NftExecutor pool cleaned up");
        Ok(())
    }

    /// 获取池状态信息
    pub async fn get_pool_stats(&self) -> (usize, usize) {
        let pool = self.pool.lock().await;
        let pool_size = pool.len();
        let available_permits = self.semaphore.available_permits();
        (pool_size, available_permits)
    }

    /// 执行批量命令（更高效）
    pub async fn execute_batch(&self, commands: Vec<String>) -> Result<Vec<String>> {
        if self.mock_mode {
            debug!(
                "Mocking batch nft command execution: {} commands",
                commands.len()
            );
            return Ok(commands
                .iter()
                .map(|_| "success (mocked)".to_string())
                .collect());
        }

        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| FirewallError::ExecutorPoolExhausted)?;

        let mut process = self.get_or_create_process().await?;
        let mut results = Vec::new();

        for command in commands {
            let result = process.execute_command(&command).await?;
            results.push(result);
        }

        self.return_or_destroy_process(process).await;
        Ok(results)
    }
}

/// 纯 Rust 防火墙控制器（使用池化的 nft 执行器）
#[derive(Clone, Debug)]
pub struct Firewall {
    table_name: String,
    chain_name: String,
    family: String,
    pub rules: Arc<RwLock<HashMap<String, FirewallRule>>>,
    nft_available: bool,
    executor: Arc<NftExecutor>,
}

impl Firewall {
    /// 初始化防火墙控制器
    pub async fn new(cfg: &Config) -> Result<Self> {
        let table_name = cfg.table_name.clone().unwrap_or("filter".to_string());
        let chain_name = cfg.chain_name.clone().unwrap_or("SAFE_TRAFFIC".to_string());
        let family = cfg.family.clone().unwrap_or("ip".to_string());

        // 检查 nftables 是否可用
        let nft_available = Self::check_nftables_available().await?;

        // 创建执行器池
        let max_pool_size = cfg.executor_pool_size.unwrap_or(5);
        let max_process_age = cfg.executor_max_age_secs.unwrap_or(300);
        let max_commands_per_process = cfg.executor_max_commands.unwrap_or(100);

        let executor = Arc::new(
            NftExecutor::new(
                max_pool_size,
                max_process_age,
                max_commands_per_process,
                !nft_available,
            )
            .await,
        );

        let firewall = Firewall {
            table_name,
            chain_name,
            family,
            rules: Arc::new(RwLock::new(HashMap::new())),
            nft_available,
            executor,
        };

        if nft_available {
            // 初始化表和链
            firewall.init_table_and_chain().await?;
            info!(
                "Firewall controller initialized: table={}, chain={}, executor_pool_size={}",
                firewall.table_name, firewall.chain_name, max_pool_size
            );
        } else {
            warn!("nftables is unavailable, using mock mode instead");
        }

        Ok(firewall)
    }

    /// 检查 nftables 是否可用
    async fn check_nftables_available() -> Result<bool> {
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
        let commands = vec![
            format!("add table {} {}", self.family, self.table_name),
            format!(
                "add chain {} {} {} {{ type filter hook input priority 0 \\; policy accept \\; }}",
                self.family, self.table_name, self.chain_name
            ),
        ];

        // 使用批量执行，更高效
        let _results = self.executor.execute_batch(commands).await?;

        debug!(
            "Table {} and chain {} initialized",
            self.table_name, self.chain_name
        );
        Ok(())
    }

    /// 执行 nft 命令（使用池化执行器）
    async fn execute_nft_command(&self, command: &str) -> Result<String> {
        self.executor.execute(command).await
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
                        warn!("Rule {} already exists, skipping creation", rule_id);
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
            "Set speed limit for {}: {} KB/s (burst: {} KB)",
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

        // 返回规则标识符
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
                            warn!(
                                "IP {} has already been banned until {}, skipping",
                                ip, existing_until
                            );
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
            handle: Some(handle),
        };

        self.rules.write().await.insert(rule_id.clone(), rule);
        info!("Banned {} until {}", ip, until);

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

        self.execute_nft_command(&rule_cmd).await?;

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

    /// 根据句柄移除规则
    async fn remove_rule_by_handle(&self, _handle: &str) -> Result<()> {
        debug!("Removing rule: {}", _handle);
        // 实际实现中，你可能需要更复杂的规则删除逻辑
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
                    warn!("Failed to remove expired rule {}: {}", rule_id, e);
                    continue;
                }
            }
            self.rules.write().await.remove(&rule_id);
            expired_rules.push(rule_id);
        }

        if !expired_rules.is_empty() {
            info!("Removed {} expired rules", expired_rules.len());
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
                if let RuleType::Ban { until } = rule.rule_type {
                    until <= Utc::now()
                } else {
                    false
                }
            })
            .count();

        let (pool_size, available_permits) = self.executor.get_pool_stats().await;

        Ok(format!(
            "防火墙状态:\n- nftables 可用: {}\n- 活跃规则: {}\n- 过期规则: {}\n- 表名: {}\n- 链名: {}\n- 执行器池大小: {}\n- 可用执行器: {}",
            self.nft_available, active_count, expired_count, self.table_name, self.chain_name, pool_size, available_permits
        ))
    }

    /// 批量添加规则（更高效）
    pub async fn batch_ban(&self, ips: Vec<IpAddr>, duration: Duration) -> Result<Vec<String>> {
        let mut commands = Vec::new();
        let mut rule_ids = Vec::new();
        let until = Utc::now() + duration;

        for ip in ips.clone() {
            let rule_id = format!("ban_{}_{}", ip, until.timestamp());
            let ip_version = match ip {
                IpAddr::V4(_) => "ip saddr",
                IpAddr::V6(_) => "ip6 saddr",
            };

            let rule_cmd = format!(
                "add rule {} {} {} {} {} drop",
                self.family, self.table_name, self.chain_name, ip_version, ip
            );

            commands.push(rule_cmd);
            rule_ids.push(rule_id);
        }

        // 批量执行命令
        self.executor.execute_batch(commands).await?;

        // 批量更新内存中的规则
        {
            let mut rules = self.rules.write().await;
            for (i, ip) in ips.into_iter().enumerate() {
                let rule = FirewallRule {
                    id: rule_ids[i].clone(),
                    ip,
                    rule_type: RuleType::Ban { until },
                    created_at: Utc::now(),
                    handle: Some(format!("ban_{}_{}", ip, Utc::now().timestamp())),
                };
                rules.insert(rule_ids[i].clone(), rule);
            }
        }

        info!("Batch banned {} IPs until {}", rule_ids.len(), until);
        Ok(rule_ids)
    }
}

impl Drop for Firewall {
    fn drop(&mut self) {
        // 异步清理执行器池
        let executor = self.executor.clone();
        tokio::spawn(async move {
            let _ = executor.cleanup().await;
        });
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
            log_path: "".to_string(),
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
            log_path: "".to_string(),
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
