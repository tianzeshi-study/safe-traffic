use crate::{
    config::Config,
    controller::Firewall,
    rules::{RuleEngine, TrafficStats},
    nft::NftExecutor
};
use dashmap::DashMap;
use futures::stream::TryStreamExt;
use log::{debug, error, info};
// use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
use rtnetlink::{new_connection, Handle};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::RwLock, time};

/// 接口统计信息
#[derive(Debug, Clone)]
pub struct InterfaceStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

/// 流量监控器
pub struct TrafficMonitor {
    handle: Handle,
    interface: String,
    stats: Arc<DashMap<IpAddr, TrafficStats>>,
    last_interface_stats: Arc<RwLock<Option<InterfaceStats>>>,
    update_interval: Duration,
    executor: Arc<NftExecutor>,
}

impl TrafficMonitor {
    pub fn new(
        handle: Handle,
        interface: String,
        stats: Arc<DashMap<IpAddr, TrafficStats>>,
        update_interval: Duration,
        executor: Arc<NftExecutor>
    ) -> Self {
        Self {
            handle,
            interface,
            stats,
            last_interface_stats: Arc::new(RwLock::new(None)),
            update_interval,
            executor
        }
    }

    /// 启动流量监控
    pub async fn start(&self) -> anyhow::Result<()> {
        let mut interval = time::interval(self.update_interval);

        loop {
            interval.tick().await;

            // if let Err(e) = self.update_traffic_stats().await {
            if let Err(e) = self.update_traffic_stats_per_ip().await {
                error!("更新流量统计失败: {:?}", e);
                continue;
            }

            // 清理过期的流量统计
            let expired_rules = self.cleanup_expired_stats().await;
            // dbg!(&expired_rules);
        }
    }

    /// 获取活跃的网络连接IP地址
    async fn get_active_connections(&self) -> anyhow::Result<Vec<IpAddr>> {
        let mut connections = Vec::new();

        // 方法1: 从 /proc/net/tcp 和 /proc/net/tcp6 读取连接信息
        if let Ok(tcp_connections) = self.parse_proc_net_tcp().await {
            connections.extend(tcp_connections);
        }

        // 方法2: 从 /proc/net/udp 和 /proc/net/udp6 读取连接信息
        if let Ok(udp_connections) = self.parse_proc_net_udp().await {
            connections.extend(udp_connections);
        }

        // 去重
        connections.sort();
        connections.dedup();

        if connections.is_empty() {
            // 如果没有找到连接，添加一些默认的本地IP
            connections.extend(self.get_local_ips().await?);
        }

        Ok(connections)
    }

    /// 解析 /proc/net/tcp* 文件获取TCP连接
    async fn parse_proc_net_tcp(&self) -> anyhow::Result<Vec<IpAddr>> {
        let mut ips = Vec::new();

        // 解析IPv4 TCP连接
        if let Ok(content) = tokio::fs::read_to_string("/proc/net/tcp").await {
            ips.extend(self.parse_net_file_content(&content, false)?);
        }

        // 解析IPv6 TCP连接
        if let Ok(content) = tokio::fs::read_to_string("/proc/net/tcp6").await {
            ips.extend(self.parse_net_file_content(&content, true)?);
        }

        Ok(ips)
    }

    /// 解析 /proc/net/udp* 文件获取UDP连接
    async fn parse_proc_net_udp(&self) -> anyhow::Result<Vec<IpAddr>> {
        let mut ips = Vec::new();

        // 解析IPv4 UDP连接
        if let Ok(content) = tokio::fs::read_to_string("/proc/net/udp").await {
            ips.extend(self.parse_net_file_content(&content, false)?);
        }

        // 解析IPv6 UDP连接
        if let Ok(content) = tokio::fs::read_to_string("/proc/net/udp6").await {
            ips.extend(self.parse_net_file_content(&content, true)?);
        }

        Ok(ips)
    }

    /// 解析网络文件内容
    fn parse_net_file_content(&self, content: &str, is_ipv6: bool) -> anyhow::Result<Vec<IpAddr>> {
        let mut ips = Vec::new();

        for line in content.lines().skip(1) {
            // 跳过标题行
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 3 {
                continue;
            }

            // 解析本地地址
            if let Ok(ip) = self.parse_address(fields[1], is_ipv6) {
                if !ip.is_loopback() && !ip.is_unspecified() {
                    ips.push(ip);
                }
            }

            // 解析远程地址
            if let Ok(ip) = self.parse_address(fields[2], is_ipv6) {
                if !ip.is_loopback() && !ip.is_unspecified() {
                    ips.push(ip);
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
            // IPv6地址解析
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
            // IPv4地址解析
            if addr_hex.len() != 8 {
                anyhow::bail!("无效的IPv4地址长度: {}", addr_hex);
            }

            let addr_u32 = u32::from_str_radix(addr_hex, 16)?;
            let bytes = addr_u32.to_le_bytes(); // 小端序
            Ok(IpAddr::V4(Ipv4Addr::from(bytes)))
        }
    }

    /// 获取本地IP地址
    async fn get_local_ips(&self) -> anyhow::Result<Vec<IpAddr>> {
        let mut ips = Vec::new();

        // 获取所有网络接口的IP地址
        let mut addresses = self.handle.address().get().execute();

        while let Some(msg) = addresses.try_next().await? {
            for attr in &msg.attributes {
                match attr {
                    netlink_packet_route::address::AddressAttribute::Address(ip_addr) => {
                        match msg.header.family {
                            netlink_packet_route::AddressFamily::Inet => {
                                if ip_addr.is_ipv4() {
                                    // let mut bytes = ip_addr.as_octets();
                                    // let ip = IpAddr::V4(Ipv4Addr::from(bytes));
                                    let ip = ip_addr.to_canonical();
                                    if !ip_addr.is_loopback() {
                                        ips.push(ip);
                                    }
                                }
                            }
                            netlink_packet_route::AddressFamily::Inet6 => {
                                if ip_addr.is_ipv6() {
                                    let ip = ip_addr.to_canonical();
                                    if !ip.is_loopback() {
                                        ips.push(ip);
                                    }
                                }
                            }
                            _ => continue,
                        }
                    }
                    _ => continue,
                }
            }
        }

        Ok(ips)
    }

    /// 清理过期的流量统计
    async fn cleanup_expired_stats(&self) {
        let now = Instant::now();
        let expire_duration = Duration::from_secs(300); // 5分钟过期

        self.stats
            .retain(|_ip, stats| now.duration_since(stats.last_updated) < expire_duration);
    }
}




/// 运行主监控逻辑
pub async fn run(cfg: Config, fw: &Arc<RwLock<Firewall>>, executor: Arc<NftExecutor>) -> anyhow::Result<()> {
    // 并发安全的 IP 流量统计表
    let stats = Arc::new(DashMap::<IpAddr, TrafficStats>::new());

    // 规则引擎实例
    let engine = RuleEngine::new(cfg.rules.clone(), stats.clone());

    // 建立 netlink 监听连接
    let (connection, handle, _messages) = new_connection()?;
    tokio::spawn(connection);

    // 创建流量监控器
    let monitor = TrafficMonitor::new(
        handle,
        cfg.interface.clone(),
        stats,
        Duration::from_secs(cfg.monitor_interval.unwrap_or(1)),
        executor
    );

    info!(
        "Traffic monitoring and rules engines have been started, monitoring interface: {}",
        cfg.interface
    );

    // 启动监控任务
    let monitor_task = monitor.start();

    // 启动规则引擎任务
    let engine_task = start_rule_engine(
        engine,
        &fw,
        Duration::from_secs(cfg.rule_check_interval.unwrap_or(1)),
    );

    // 等待任务完成
    tokio::try_join!(monitor_task, engine_task)?;

    Ok(())
}

/// 启动规则引擎任务
async fn start_rule_engine(
    engine: RuleEngine,
    fw: &Arc<RwLock<Firewall>>,
    check_interval: Duration,
) -> anyhow::Result<()> {
    let mut interval = time::interval(check_interval);

    loop {
        interval.tick().await;

        let mut fw_guard = fw.write().await;

        // if let Err(e) = engine.check_and_apply(&mut fw_guard).await {
        // error!("Checking engine rules fail   : {:?}", e);
        // }
        match engine.check_and_apply(&mut fw_guard).await {
            Ok(_v) => {}
            Err(e) => error!("check and apply fail {}", e),
        }
        drop(fw_guard);
    }
}

/////////
// 直接获取每个IP流量信息的监控方案
/// 每个IP的详细流量统计
#[derive(Debug, Clone)]
pub struct IpTrafficStats {
    pub ip: IpAddr,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub last_updated: Instant,
    pub connections: Vec<ConnectionDetail>,
}

/// 连接详细信息
#[derive(Debug, Clone)]
pub struct ConnectionDetail {
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub protocol: String,
    pub state: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}
/*
impl TrafficMonitor {
    /// 主要的流量更新方法 - 直接获取每个IP的流量
    async fn update_traffic_stats_per_ip(&self) -> anyhow::Result<()> {
        // 方法1: 通过nftables规则获取每个IP的流量
        let ip_stats = self.get_traffic_via_nftables().await?;
        self.update_stats_from_ip_data(ip_stats).await?;
        Ok(())
    }

    /// 方法1: 通过nftables规则获取每个IP的流量统计
    async fn get_traffic_via_nftables(&self) -> anyhow::Result<HashMap<IpAddr, IpTrafficStats>> {
        let mut ip_stats = HashMap::new();

        // 首先确保有nftables规则来统计流量
        self.ensure_nftables_rules().await?;

        // 获取nftables统计信息 - 输入流量
        let output = Command::new("nft")
            .args(["-a", "list", "chain", "inet", "traffic_monitor", "input_stats"])
            .output()?;

        if !output.status.success() {
            anyhow::bail!("执行nft命令失败: {}", String::from_utf8_lossy(&output.stderr));
        }

        let stdout = String::from_utf8(output.stdout)?;
        self.parse_nft_chain_output(&stdout, &mut ip_stats, "input").await?;

        // 获取输出流量统计
        let output = Command::new("nft")
            .args(["-a", "list", "chain", "inet", "traffic_monitor", "output_stats"])
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8(output.stdout)?;
            self.parse_nft_chain_output(&stdout, &mut ip_stats, "output").await?;
        }

        Ok(ip_stats)
    }

    /// 确保nftables规则存在以统计每个IP的流量
    async fn ensure_nftables_rules(&self) -> anyhow::Result<()> {
        // 首先创建表和链结构
        self.setup_nft_table_structure().await?;

        // 获取当前活跃的IP地址
        let active_ips = self.get_active_ips().await?;

        for ip in active_ips {
            let ip_str = ip.to_string();
            
            // 为每个IP创建计数器规则
            self.ensure_ip_counter_rules(&ip_str).await?;
        }

        Ok(())
    }

    /// 设置nftables表和链结构
    async fn setup_nft_table_structure(&self) -> anyhow::Result<()> {
        // 创建表 (如果不存在)
        let _result = Command::new("nft")
            .args(["add", "table", "inet", "traffic_monitor"])
            .output();

        // 创建输入统计链
        let _result = Command::new("nft")
            .args([
                "add", "chain", "inet", "traffic_monitor", "input_stats",
                "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}"
            ])
            .output();

        // 创建输出统计链
        let _result = Command::new("nft")
            .args([
                "add", "chain", "inet", "traffic_monitor", "output_stats", 
                "{", "type", "filter", "hook", "output", "priority", "0", ";", "policy", "accept", ";", "}"
            ])
            .output();

        Ok(())
    }

    /// 为特定IP确保计数器规则存在
    async fn ensure_ip_counter_rules(&self, ip: &str) -> anyhow::Result<()> {
        // 检查规则是否已存在
        let check_input = Command::new("nft")
            .args(["list", "chain", "inet", "traffic_monitor", "input_stats"])
            .output()?;

        let existing_rules = String::from_utf8_lossy(&check_input.stdout);
        
        // 如果规则不存在，则添加
        if !existing_rules.contains(&format!("ip saddr {}", ip)) {
            // 输入流量计数规则
            let _result = Command::new("nft")
                .args([
                    "add", "rule", "inet", "traffic_monitor", "input_stats",
                    "ip", "saddr", ip, "counter", "accept"
                ])
                .output();
        }

        if !existing_rules.contains(&format!("ip daddr {}", ip)) {
            // 输出流量计数规则  
            let _result = Command::new("nft")
                .args([
                    "add", "rule", "inet", "traffic_monitor", "output_stats",
                    "ip", "daddr", ip, "counter", "accept"
                ])
                .output();
        }

        Ok(())
    }

    /// 解析nftables链输出获取流量统计
    async fn parse_nft_chain_output(
        &self,
        output: &str,
        ip_stats: &mut HashMap<IpAddr, IpTrafficStats>,
        direction: &str,
    ) -> anyhow::Result<()> {
        let lines: Vec<&str> = output.lines().collect();
        let mut i = 0;
        
        while i < lines.len() {
            let line = lines[i].trim();
            
            // 查找包含IP地址和counter的规则
            if line.contains("counter packets") {
                // 解析IP地址
                let ip_addr = if direction == "input" {
                    self.extract_ip_from_saddr_rule(line)
                } else {
                    self.extract_ip_from_daddr_rule(line)
                };

                if let Some(ip_str) = ip_addr {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        // 解析计数器信息
                        let (packets, bytes) = self.parse_counter_info(line)?;
                        
                        let entry = ip_stats.entry(ip).or_insert_with(|| IpTrafficStats {
                            ip,
                            rx_bytes: 0,
                            tx_bytes: 0,
                            rx_packets: 0,
                            tx_packets: 0,
                            last_updated: Instant::now(),
                            connections: Vec::new(),
                        });

                        // 根据方向更新统计
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
            i += 1;
        }

        Ok(())
    }

    /// 从saddr规则中提取IP地址
    fn extract_ip_from_saddr_rule(&self, rule: &str) -> Option<String> {
        // 匹配 "ip saddr 192.168.1.1 counter packets ..."
        if let Some(start) = rule.find("ip saddr ") {
            let after_saddr = &rule[start + 9..];
            if let Some(end) = after_saddr.find(' ') {
                return Some(after_saddr[..end].to_string());
            }
        }
        None
    }

    /// 从daddr规则中提取IP地址
    fn extract_ip_from_daddr_rule(&self, rule: &str) -> Option<String> {
        // 匹配 "ip daddr 192.168.1.1 counter packets ..."
        if let Some(start) = rule.find("ip daddr ") {
            let after_daddr = &rule[start + 9..];
            if let Some(end) = after_daddr.find(' ') {
                return Some(after_daddr[..end].to_string());
            }
        }
        None
    }

    /// 解析计数器信息
    fn parse_counter_info(&self, rule: &str) -> anyhow::Result<(u64, u64)> {
        // 匹配 "counter packets 123 bytes 456"
        let mut packets = 0u64;
        let mut bytes = 0u64;

        if let Some(packets_pos) = rule.find("packets ") {
            let after_packets = &rule[packets_pos + 8..];
            if let Some(space_pos) = after_packets.find(' ') {
                packets = after_packets[..space_pos].parse().unwrap_or(0);
            }
        }

        if let Some(bytes_pos) = rule.find("bytes ") {
            let after_bytes = &rule[bytes_pos + 6..];
            let bytes_str = after_bytes.split_whitespace().next().unwrap_or("0");
            bytes = bytes_str.parse().unwrap_or(0);
        }

        Ok((packets, bytes))
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
            let tx_delta = new_stats.tx_bytes.saturating_sub(stats.tx_bytes);

            // 更新统计
            stats.rx_bytes = new_stats.rx_bytes;
            stats.tx_bytes = new_stats.tx_bytes;
            stats.last_updated = Instant::now();

            if rx_delta > 0 || tx_delta > 0 {
                debug!(
                    "IP {} 流量更新: RX +{} bytes, TX +{} bytes",
                    ip, rx_delta, tx_delta
                );
            }
        }

        Ok(())
    }

    /// 辅助方法：获取所有活跃IP
    async fn get_active_ips(&self) -> anyhow::Result<Vec<IpAddr>> {
        let mut ips = Vec::new();

        // 从现有统计中获取
        for entry in self.stats.iter() {
            ips.push(*entry.key());
        }

        // 从当前连接中获取
        if let Ok(connections) = self.get_active_connections().await {
            ips.extend(connections);
        }

        // 去重
        ips.sort();
        ips.dedup();

        Ok(ips)
    }

    /// 清理nftables规则 (可选的清理方法)
    pub async fn cleanup_nftables_rules(&self) -> anyhow::Result<()> {
        // 删除整个表 (这会删除所有相关的链和规则)
        let _result = Command::new("nft")
            .args(["delete", "table", "inet", "traffic_monitor"])
            .output();

        Ok(())
    }

    /// 重置特定IP的计数器 (可选功能)
    pub async fn reset_ip_counters(&self, ip: &str) -> anyhow::Result<()> {
        // nftables 支持重置计数器
        let output = Command::new("nft")
            .args(["-a", "list", "chain", "inet", "traffic_monitor", "input_stats"])
            .output()?;
        
        let rules_output = String::from_utf8(output.stdout)?;
        
        // 找到对应IP的规则句柄并重置
        for line in rules_output.lines() {
            if line.contains(&format!("ip saddr {}", ip)) && line.contains("# handle") {
                if let Some(handle) = self.extract_rule_handle(line) {
                    let _result = Command::new("nft")
                        .args(["reset", "rule", "inet", "traffic_monitor", "input_stats", "handle", &handle])
                        .output();
                }
            }
        }

        Ok(())
    }

    /// 从规则中提取句柄ID
    fn extract_rule_handle(&self, rule: &str) -> Option<String> {
        if let Some(handle_pos) = rule.find("# handle ") {
            let after_handle = &rule[handle_pos + 9..];
            if let Some(space_or_end) = after_handle.find(|c: char| c.is_whitespace()) {
                return Some(after_handle[..space_or_end].to_string());
            } else {
                return Some(after_handle.to_string());
            }
        }
        None
    }
}



*/
impl TrafficMonitor {

    async fn update_traffic_stats_per_ip(&self) -> anyhow::Result<()> {

        let ip_stats = self.get_traffic_via_nftables().await?;
        self.update_stats_from_ip_data(ip_stats).await?;
        Ok(())
    }


    async fn get_traffic_via_nftables(&self) -> anyhow::Result<HashMap<IpAddr, IpTrafficStats>> {
        let mut ip_stats = HashMap::new();

        // 首先确保有nftables规则来统计流量
        self.ensure_nftables_rules().await?;

        // 获取nftables统计信息 - 输入流量
        let cmd = ["list", "chain", "inet", "traffic_monitor", "input_stats"]
        .join(" ");
        
        
            let output = self.executor.execute(&cmd).await?;
            dbg!(&output);


        self.parse_nft_chain_output(&output, &mut ip_stats, "input").await?;

        // 获取输出流量统计
        let output = self.executor.execute(&["list", "chain", "inet", "traffic_monitor", "output_stats"].join(" ")).await?;



            self.parse_nft_chain_output(&output, &mut ip_stats, "output").await?;


        Ok(ip_stats)
    }

    /// 确保nftables规则存在以统计每个IP的流量
    async fn ensure_nftables_rules(&self) -> anyhow::Result<()> {
        // 首先创建表和链结构
        self.setup_nft_table_structure().await?;

        // 获取当前活跃的IP地址
        let active_ips = self.get_active_ips().await?;

        for ip in active_ips {
            let ip_str = ip.to_string();
            
            // 为每个IP创建计数器规则
            self.ensure_ip_counter_rules(&ip_str).await?;
        }

        Ok(())
    }

    /// 设置nftables表和链结构
    async fn setup_nft_table_structure(&self) -> anyhow::Result<()> {
        // 创建表 (如果不存在)
        let _result = Command::new("nft")
            .args(["add", "table", "inet", "traffic_monitor"])
            .output();

        // 创建输入统计链
        let _result = Command::new("nft")
            .args([
                "add", "chain", "inet", "traffic_monitor", "input_stats",
                "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}"
            ])
            .output();

        // 创建输出统计链
        let _result = Command::new("nft")
            .args([
                "add", "chain", "inet", "traffic_monitor", "output_stats", 
                "{", "type", "filter", "hook", "output", "priority", "0", ";", "policy", "accept", ";", "}"
            ])
            .output();

        Ok(())
    }

    /// 为特定IP确保计数器规则存在
    async fn ensure_ip_counter_rules(&self, ip: &str) -> anyhow::Result<()> {
        // 检查规则是否已存在
        let check_input = Command::new("nft")
            .args(["list", "chain", "inet", "traffic_monitor", "input_stats"])
            .output()?;

        let existing_rules = String::from_utf8_lossy(&check_input.stdout);
        
        // 如果规则不存在，则添加
        if !existing_rules.contains(&format!("ip saddr {}", ip)) {
            // 输入流量计数规则
            let _result = Command::new("nft")
                .args([
                    "add", "rule", "inet", "traffic_monitor", "input_stats",
                    "ip", "saddr", ip, "counter", "accept"
                ])
                .output();
        }

        if !existing_rules.contains(&format!("ip daddr {}", ip)) {
            // 输出流量计数规则  
            let _result = Command::new("nft")
                .args([
                    "add", "rule", "inet", "traffic_monitor", "output_stats",
                    "ip", "daddr", ip, "counter", "accept"
                ])
                .output();
        }

        Ok(())
    }

    /// 解析nftables链输出获取流量统计
    async fn parse_nft_chain_output(
        &self,
        output: &str,
        ip_stats: &mut HashMap<IpAddr, IpTrafficStats>,
        direction: &str,
    ) -> anyhow::Result<()> {
        let lines: Vec<&str> = output.lines().collect();
        let mut i = 0;
        
        while i < lines.len() {
            let line = lines[i].trim();
            
            // 查找包含IP地址和counter的规则
            if line.contains("counter packets") {
                // 解析IP地址
                let ip_addr = if direction == "input" {
                    self.extract_ip_from_saddr_rule(line)
                } else {
                    self.extract_ip_from_daddr_rule(line)
                };

                if let Some(ip_str) = ip_addr {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        // 解析计数器信息
                        let (packets, bytes) = self.parse_counter_info(line)?;
                        
                        let entry = ip_stats.entry(ip).or_insert_with(|| IpTrafficStats {
                            ip,
                            rx_bytes: 0,
                            tx_bytes: 0,
                            rx_packets: 0,
                            tx_packets: 0,
                            last_updated: Instant::now(),
                            connections: Vec::new(),
                        });

                        // 根据方向更新统计
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
            i += 1;
        }

        Ok(())
    }

    /// 从saddr规则中提取IP地址
    fn extract_ip_from_saddr_rule(&self, rule: &str) -> Option<String> {
        // 匹配 "ip saddr 192.168.1.1 counter packets ..."
        if let Some(start) = rule.find("ip saddr ") {
            let after_saddr = &rule[start + 9..];
            if let Some(end) = after_saddr.find(' ') {
                return Some(after_saddr[..end].to_string());
            }
        }
        None
    }

    /// 从daddr规则中提取IP地址
    fn extract_ip_from_daddr_rule(&self, rule: &str) -> Option<String> {
        // 匹配 "ip daddr 192.168.1.1 counter packets ..."
        if let Some(start) = rule.find("ip daddr ") {
            let after_daddr = &rule[start + 9..];
            if let Some(end) = after_daddr.find(' ') {
                return Some(after_daddr[..end].to_string());
            }
        }
        None
    }

    /// 解析计数器信息
    fn parse_counter_info(&self, rule: &str) -> anyhow::Result<(u64, u64)> {
        // 匹配 "counter packets 123 bytes 456"
        let mut packets = 0u64;
        let mut bytes = 0u64;

        if let Some(packets_pos) = rule.find("packets ") {
            let after_packets = &rule[packets_pos + 8..];
            if let Some(space_pos) = after_packets.find(' ') {
                packets = after_packets[..space_pos].parse().unwrap_or(0);
            }
        }

        if let Some(bytes_pos) = rule.find("bytes ") {
            let after_bytes = &rule[bytes_pos + 6..];
            let bytes_str = after_bytes.split_whitespace().next().unwrap_or("0");
            bytes = bytes_str.parse().unwrap_or(0);
        }

        Ok((packets, bytes))
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
            let tx_delta = new_stats.tx_bytes.saturating_sub(stats.tx_bytes);

            // 更新统计
            stats.rx_bytes = new_stats.rx_bytes;
            stats.tx_bytes = new_stats.tx_bytes;
            stats.last_updated = Instant::now();

            if rx_delta > 0 || tx_delta > 0 {
                debug!(
                    "IP {} 流量更新: RX +{} bytes, TX +{} bytes",
                    ip, rx_delta, tx_delta
                );
            }
        }

        Ok(())
    }

    /// 辅助方法：获取所有活跃IP
    async fn get_active_ips(&self) -> anyhow::Result<Vec<IpAddr>> {
        let mut ips = Vec::new();

        // 从现有统计中获取
        for entry in self.stats.iter() {
            ips.push(*entry.key());
        }

        // 从当前连接中获取
        if let Ok(connections) = self.get_active_connections().await {
            ips.extend(connections);
        }

        // 去重
        ips.sort();
        ips.dedup();

        Ok(ips)
    }

    /// 清理nftables规则 (可选的清理方法)
    pub async fn cleanup_nftables_rules(&self) -> anyhow::Result<()> {
        // 删除整个表 (这会删除所有相关的链和规则)
        let _result = Command::new("nft")
            .args(["delete", "table", "inet", "traffic_monitor"])
            .output();

        Ok(())
    }

    /// 重置特定IP的计数器 (可选功能)
    pub async fn reset_ip_counters(&self, ip: &str) -> anyhow::Result<()> {
        // nftables 支持重置计数器
        let output = Command::new("nft")
            .args(["-a", "list", "chain", "inet", "traffic_monitor", "input_stats"])
            .output()?;
        
        let rules_output = String::from_utf8(output.stdout)?;
        
        // 找到对应IP的规则句柄并重置
        for line in rules_output.lines() {
            if line.contains(&format!("ip saddr {}", ip)) && line.contains("# handle") {
                if let Some(handle) = self.extract_rule_handle(line) {
                    let _result = Command::new("nft")
                        .args(["reset", "rule", "inet", "traffic_monitor", "input_stats", "handle", &handle])
                        .output();
                }
            }
        }

        Ok(())
    }

    /// 从规则中提取句柄ID
    fn extract_rule_handle(&self, rule: &str) -> Option<String> {
        if let Some(handle_pos) = rule.find("# handle ") {
            let after_handle = &rule[handle_pos + 9..];
            if let Some(space_or_end) = after_handle.find(|c: char| c.is_whitespace()) {
                return Some(after_handle[..space_or_end].to_string());
            } else {
                return Some(after_handle.to_string());
            }
        }
        None
    }
}



