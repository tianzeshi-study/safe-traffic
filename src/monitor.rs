use crate::{
    config::Config,
    controller::Firewall,
    nft::{parser::*, NftError, NftExecutor},
    rules::{RuleEngine, TrafficStats},
};
use dashmap::DashMap;
use futures::stream::TryStreamExt;
use log::{debug, error, info, warn};
use rtnetlink::{new_connection, Handle};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::RwLock, time};

/// 每个IP的详细流量统计
#[derive(Debug, Clone)]
pub struct IpTrafficStats {
    #[allow(dead_code)]
    pub ip: IpAddr,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    #[allow(dead_code)]
    pub last_updated: Instant,
}

/// 流量监控器
pub struct TrafficMonitor {
    handle: Handle,
    #[allow(dead_code)]
    interface: String,
    stats: Arc<DashMap<IpAddr, TrafficStats>>,
    update_interval: Duration,
    executor: Arc<NftExecutor>,
}

impl TrafficMonitor {
    pub fn new(
        handle: Handle,
        interface: String,
        stats: Arc<DashMap<IpAddr, TrafficStats>>,
        update_interval: Duration,
        executor: Arc<NftExecutor>,
    ) -> Self {
        Self {
            handle,
            interface,
            stats,
            update_interval,
            executor,
        }
    }

    /// 启动流量监控
    pub async fn start(&self) -> anyhow::Result<()> {
        self.setup_nft_table_structure().await?;
        let mut interval = time::interval(self.update_interval);

        loop {
            interval.tick().await;

            if let Err(e) = self.update_traffic_stats_per_ip().await {
                error!("更新流量统计失败: {:?}", e);
                continue;
            }

            // 清理过期的流量统计
            self.cleanup_expired_stats().await;
        }
    }

    /// 更新每个IP的流量统计
    async fn update_traffic_stats_per_ip(&self) -> anyhow::Result<()> {
        let ip_stats = self.get_traffic_via_nftables_json().await?;
        self.update_stats_from_ip_data(ip_stats).await?;
        Ok(())
    }

    /// 通过 nftables JSON 格式获取流量统计
    async fn get_traffic_via_nftables_json(
        &self,
    ) -> anyhow::Result<HashMap<IpAddr, IpTrafficStats>> {
        let mut ip_stats = HashMap::new();

        // 确保规则存在
        self.ensure_nftables_rules().await?;

        // 获取输入链的流量统计 (JSON 格式)
        let input_cmd = "list chain inet traffic_monitor input_stats";
        let input_output = self.executor.execute(input_cmd).await?;
        self.parse_nft_json_output(&input_output, &mut ip_stats, "input")
            .await?;

        // 获取输出链的流量统计 (JSON 格式)
        let output_cmd = "list chain inet traffic_monitor output_stats";
        let output_output = self.executor.execute(output_cmd).await?;
        self.parse_nft_json_output(&output_output, &mut ip_stats, "output")
            .await?;

        Ok(ip_stats)
    }

    /// 解析 nft JSON 输出
    async fn parse_nft_json_output(
        &self,
        json_output: &str,
        ip_stats: &mut HashMap<IpAddr, IpTrafficStats>,
        direction: &str,
    ) -> anyhow::Result<()> {
        let nft_data: NftJsonOutput = serde_json::from_str(json_output)
            .map_err(|e| anyhow::anyhow!("解析 NFT JSON 失败: {}", e))?;

        for obj in nft_data.nftables {
            if let NftObject::Rule(rule_obj) = obj {
                if let Some(expr_list) = &rule_obj.rule.expr {
                    // 查找匹配的IP地址和对应的计数器
                    let mut ip_addr: Option<IpAddr> = None;
                    let mut counter_info: Option<(u64, u64)> = None;

                    for expr in expr_list {
                        match expr {
                            Expression::Match(match_expr) => {
                                ip_addr = self.extract_ip_from_match(match_expr, direction);
                            }
                            Expression::Counter(counter_expr) => {
                                counter_info = Some((
                                    counter_expr.counter.packets,
                                    counter_expr.counter.bytes,
                                ));
                            }
                            _ => {}
                        }
                    }

                    // 如果找到了IP和计数器信息，更新统计
                    if let (Some(ip), Some((packets, bytes))) = (ip_addr, counter_info) {
                        let entry = ip_stats.entry(ip).or_insert_with(|| IpTrafficStats {
                            ip,
                            rx_bytes: 0,
                            tx_bytes: 0,
                            rx_packets: 0,
                            tx_packets: 0,
                            last_updated: Instant::now(),
                        });

                        if direction == "input" {
                            entry.rx_bytes += bytes;
                            entry.rx_packets += packets;
                        } else {
                            entry.tx_bytes += bytes;
                            entry.tx_packets += packets;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// 从匹配表达式中提取IP地址
    fn extract_ip_from_match(&self, match_expr: &MatchExpr, direction: &str) -> Option<IpAddr> {
        let match_obj = &match_expr.r#match;

        // 检查是否是IP地址匹配
        if let Ok(left_str) = serde_json::to_string(&match_obj.left) {
            let expected_field = if direction == "input" {
                "saddr"
            } else {
                "daddr"
            };

            if left_str.contains(expected_field) {
                // 提取右侧的IP地址值
                if let Ok(ip_str) = match_obj
                    .right
                    .as_str()
                    .ok_or("")
                    .and_then(|s| s.parse::<IpAddr>().map_err(|_e| "parse error"))
                {
                    return Some(ip_str);
                }
                // 也可能是数组格式，尝试解析
                if let Some(ip_str) = match_obj.right.as_str() {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }
        }

        None
    }

    /// 确保 nftables 规则存在
    async fn ensure_nftables_rules(&self) -> anyhow::Result<()> {
        // self.setup_nft_table_structure().await?;

        let active_ips = self.get_active_ips().await?;
        dbg!(&active_ips.len());
        for ip in active_ips {
            self.ensure_ip_counter_rules(&ip.to_string()).await?;
        }

        Ok(())
    }

    /// 设置 nftables 表和链结构
    async fn setup_nft_table_structure(&self) -> anyhow::Result<()> {
        let commands = vec![
            "add table inet traffic_monitor".to_string(),
            "add chain inet traffic_monitor input_stats { type filter hook input priority -100; policy accept; }".to_string(),
            "add chain inet traffic_monitor output_stats { type filter hook output priority -100; policy accept; }".to_string()
            ];
        match self.executor.execute_batch(commands).await {
            Ok(_s) => {}
            Err(e) => {
                if let Some(NftError::Timeout) = e.downcast_ref::<NftError>() {
                    warn!("timeout, maybe monitor already exist");
                    return Ok(());
                }
                return Err(e);
            }
        };

        Ok(())
    }

    /// 为特定IP确保计数器规则存在
    async fn ensure_ip_counter_rules(&self, ip: &str) -> anyhow::Result<()> {
        let ip_family = identify_ip(ip).await?;
        // 检查现有规则
        let check_cmd = "list chain inet traffic_monitor input_stats";
        let existing_rules = self.executor.execute(check_cmd).await.unwrap_or_default();

        if !existing_rules.contains(&format!("\"{}\"", ip)) {
            // 添加输入流量计数规则
            let input_rule = format!(
                "add rule inet traffic_monitor input_stats {} saddr {} counter accept",
                ip_family, ip
            );
            let _ = self.executor.execute(&input_rule).await;

            // 添加输出流量计数规则
            let output_rule = format!(
                "add rule inet traffic_monitor output_stats {} daddr {} counter accept",
                ip_family, ip
            );
            let _ = self.executor.execute(&output_rule).await;
        }

        Ok(())
    }

    /// 获取活跃的IP地址
    async fn get_active_ips(&self) -> anyhow::Result<Vec<IpAddr>> {
        let mut ips = Vec::new();

        // 从现有统计中获取
        // for entry in self.stats.iter() {
        // ips.push(*entry.key());
        // }

        // 从当前连接中获取
        if let Ok(connections) = self.get_active_connections().await {
            dbg!(&connections.len());
            ips.extend(connections);
        }

        // 去重并排序
        ips.sort();
        ips.dedup();

        Ok(ips)
    }

    /// 获取活跃的网络连接IP地址
    async fn get_active_connections(&self) -> anyhow::Result<Vec<IpAddr>> {
        let mut connections = Vec::new();

        // 从 /proc/net/tcp* 读取连接信息
        if let Ok(tcp_connections) = self.parse_proc_net_tcp().await {
            connections.extend(tcp_connections);
        }

        // 从 /proc/net/udp* 读取连接信息
        if let Ok(udp_connections) = self.parse_proc_net_udp().await {
            connections.extend(udp_connections);
        }

        // 去重
        connections.sort();
        connections.dedup();

        if connections.is_empty() {
            connections.extend(self.get_local_ips().await?);
        }

        Ok(connections)
    }

    /// 解析 /proc/net/tcp* 文件
    async fn parse_proc_net_tcp(&self) -> anyhow::Result<Vec<IpAddr>> {
        let mut ips = Vec::new();

        if let Ok(content) = tokio::fs::read_to_string("/proc/net/tcp").await {
            ips.extend(self.parse_net_file_content(&content, false)?);
        }

        if let Ok(content) = tokio::fs::read_to_string("/proc/net/tcp6").await {
            ips.extend(self.parse_net_file_content(&content, true)?);
        }

        Ok(ips)
    }

    /// 解析 /proc/net/udp* 文件
    async fn parse_proc_net_udp(&self) -> anyhow::Result<Vec<IpAddr>> {
        let mut ips = Vec::new();

        if let Ok(content) = tokio::fs::read_to_string("/proc/net/udp").await {
            ips.extend(self.parse_net_file_content(&content, false)?);
        }

        if let Ok(content) = tokio::fs::read_to_string("/proc/net/udp6").await {
            ips.extend(self.parse_net_file_content(&content, true)?);
        }

        Ok(ips)
    }

    /// 解析网络文件内容
    fn parse_net_file_content(&self, content: &str, is_ipv6: bool) -> anyhow::Result<Vec<IpAddr>> {
        let mut ips = Vec::new();

        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 3 {
                continue;
            }

            // 解析本地和远程地址
            for addr_field in [fields[1], fields[2]].iter() {
                if let Ok(ip) = self.parse_address(addr_field, is_ipv6) {
                    if !ip.is_loopback() && !ip.is_unspecified() {
                        ips.push(ip);
                    }
                }
            }
        }

        Ok(ips)
    }

    /// 解析地址字符串
    fn parse_address(&self, addr_str: &str, is_ipv6: bool) -> anyhow::Result<IpAddr> {
        let parts: Vec<&str> = addr_str.split(':').collect();
        if parts.len() != 2 {
            anyhow::bail!("无效的地址格式: {}", addr_str);
        }

        let addr_hex = parts[0];

        if is_ipv6 {
            if addr_hex.len() != 32 {
                anyhow::bail!("无效的IPv6地址长度: {}", addr_hex);
            }

            let mut bytes = [0u8; 16];
            for i in 0..16 {
                let hex_byte = &addr_hex[i * 2..i * 2 + 2];
                bytes[i] = u8::from_str_radix(hex_byte, 16)?;
            }

            Ok(IpAddr::V6(Ipv6Addr::from(bytes)))
        } else {
            if addr_hex.len() != 8 {
                anyhow::bail!("无效的IPv4地址长度: {}", addr_hex);
            }

            let addr_u32 = u32::from_str_radix(addr_hex, 16)?;
            let bytes = addr_u32.to_le_bytes();
            Ok(IpAddr::V4(Ipv4Addr::from(bytes)))
        }
    }

    /// 获取本地IP地址
    async fn get_local_ips(&self) -> anyhow::Result<Vec<IpAddr>> {
        let mut ips = Vec::new();
        let mut addresses = self.handle.address().get().execute();

        while let Some(msg) = addresses.try_next().await? {
            for attr in &msg.attributes {
                if let netlink_packet_route::address::AddressAttribute::Address(ip_addr) = attr {
                    let ip = ip_addr.to_canonical();
                    if !ip.is_loopback() {
                        ips.push(ip);
                    }
                }
            }
        }

        Ok(ips)
    }

    /// 更新统计数据
    async fn update_stats_from_ip_data(
        &self,
        ip_stats: HashMap<IpAddr, IpTrafficStats>,
    ) -> anyhow::Result<()> {
        for (ip, new_stats) in ip_stats {
            let mut stats = self.stats.entry(ip).or_insert_with(TrafficStats::default);

            // 计算增量
            let rx_delta = new_stats.rx_bytes.saturating_sub(stats.rx_bytes);
            dbg!(&new_stats.rx_bytes, &stats.rx_bytes, &rx_delta);
            let tx_delta = new_stats.tx_bytes.saturating_sub(stats.tx_bytes);

            // 更新统计
            stats.rx_bytes = new_stats.rx_bytes;
            stats.tx_bytes = new_stats.tx_bytes;
            stats.rx_delta = rx_delta;
            stats.tx_delta = tx_delta;
            stats.last_updated = Instant::now();

            if rx_delta > 0 || tx_delta > 0 {
                debug!(
                    "IP {} traffic updated : RX +{} bytes, TX +{} bytes",
                    ip, rx_delta, tx_delta
                );
            }
        }

        Ok(())
    }

    /// 清理过期的流量统计
    async fn cleanup_expired_stats(&self) {
        let now = Instant::now();
        let expire_duration = Duration::from_secs(300); // 5分钟过期

        self.stats
            .retain(|_ip, stats| now.duration_since(stats.last_updated) < expire_duration);
    }

    /// 清理 nftables 规则
    #[allow(dead_code)]
    pub async fn cleanup_nftables_rules(&self) -> anyhow::Result<()> {
        let _ = self
            .executor
            .execute("delete table inet traffic_monitor")
            .await;
        Ok(())
    }
}

async fn identify_ip(ip_str: &str) -> anyhow::Result<&str> {
    match ip_str.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => Ok("ip"),
        Ok(IpAddr::V6(_)) => Ok("ip6"),
        Err(e) => {
            error!("{} 不是合法的 IP 地址: {}", ip_str, e);
            Err(e.into())
        }
    }
}

/// 运行主监控逻辑
pub async fn run(
    cfg: Config,
    // fw: &Arc<RwLock<Firewall>>,
    fw: Arc<Firewall>,
    executor: Arc<NftExecutor>,
) -> anyhow::Result<()> {
    let stats = Arc::new(DashMap::<IpAddr, TrafficStats>::new());
    let engine = RuleEngine::new(cfg.rules.clone(), stats.clone());

    let (connection, handle, _messages) = new_connection()?;
    tokio::spawn(connection);

    let monitor = TrafficMonitor::new(
        handle,
        cfg.interface.clone(),
        stats,
        Duration::from_secs(cfg.monitor_interval.unwrap_or(1)),
        executor,
    );

    info!(
        "Traffic monitoring and rules engines have been started, monitoring interface: {}",
        cfg.interface
    );

    let monitor_task = monitor.start();
    let engine_task = start_rule_engine(
        engine,
        fw,
        Duration::from_secs(cfg.rule_check_interval.unwrap_or(1)),
    );

    tokio::try_join!(monitor_task, engine_task)?;
    Ok(())
}

/// 启动规则引擎任务
async fn start_rule_engine(
    engine: RuleEngine,
    // fw: &Arc<RwLock<Firewall>>,
    fw: Arc<Firewall>,
    check_interval: Duration,
) -> anyhow::Result<()> {
    let mut interval = time::interval(check_interval);

    loop {
        interval.tick().await;
        // let mut fw_guard = fw.write().await;

        match engine.check_and_apply(Arc::clone(&fw)).await {
            Ok(_) => {}
            Err(e) => error!("check and apply fail {}", e),
        }
        // drop(fw_guard);
        // drop(fw);
    }
}
