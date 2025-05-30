// src/monitor.rs
use crate::{config::Config, controller::Firewall, rules::RuleEngine};
use dashmap::DashMap;
use futures::stream::TryStreamExt;
use log::{debug, error, info, warn};
use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
use rtnetlink::{new_connection, Handle};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::RwLock, task, time};

// 网络地址族常量（因为 netlink_packet_route 0.22 没有 constants 模块）
const AF_INET: u8 = 2; // IPv4
const AF_INET6: u8 = 10; // IPv6

/// 流量统计结构体
#[derive(Debug, Clone)]
pub struct TrafficStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_updated: Instant,
}

impl Default for TrafficStats {
    fn default() -> Self {
        Self {
            rx_bytes: 0,
            tx_bytes: 0,
            last_updated: Instant::now(),
        }
    }
}

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
}

impl TrafficMonitor {
    pub fn new(
        handle: Handle,
        interface: String,
        stats: Arc<DashMap<IpAddr, TrafficStats>>,
        update_interval: Duration,
    ) -> Self {
        Self {
            handle,
            interface,
            stats,
            last_interface_stats: Arc::new(RwLock::new(None)),
            update_interval,
        }
    }

    /// 启动流量监控
    pub async fn start(&self) -> anyhow::Result<()> {
        let mut interval = time::interval(self.update_interval);

        loop {
            interval.tick().await;

            // if let Err(e) = self.update_traffic_stats().await {
            // if let Err(e) = self.update_traffic_stats_per_ip().await {
            if let Err(e) = self.update_traffic_stats_native().await {
                error!("更新流量统计失败: {:?}", e);
                continue;
            }

            // 清理过期的流量统计
            self.cleanup_expired_stats().await;
        }
    }

    /// 更新流量统计
    async fn update_traffic_stats(&self) -> anyhow::Result<()> {
        let current_stats = self.get_interface_stats().await?;
        let mut last_stats_guard = self.last_interface_stats.write().await;

        if let Some(ref last_stats) = *last_stats_guard {
            let rx_delta = current_stats.rx_bytes.saturating_sub(last_stats.rx_bytes);
            let tx_delta = current_stats.tx_bytes.saturating_sub(last_stats.tx_bytes);

            if rx_delta > 0 || tx_delta > 0 {
                debug!(
                    "接口 {} 流量变化: RX +{} bytes, TX +{} bytes",
                    self.interface, rx_delta, tx_delta
                );

                // 在实际应用中，这里应该通过其他方式获取具体的IP地址
                // 例如：解析网络包、从连接跟踪表读取、或使用其他网络监控工具
                // self.distribute_traffic_by_connections(rx_delta, tx_delta)
                self.distribute_traffic_by_weighted_connections(rx_delta, tx_delta)
                    .await?;
            }
        }

        *last_stats_guard = Some(current_stats);
        Ok(())
    }

    /// 根据当前网络连接分配流量
    async fn distribute_traffic_by_connections(
        &self,
        rx_delta: u64,
        tx_delta: u64,
    ) -> anyhow::Result<()> {
        // 获取当前活跃的网络连接
        let active_connections = self.get_active_connections().await?;

        if active_connections.is_empty() {
            debug!("没有找到活跃连接，跳过流量分配");
            return Ok(());
        }

        // 简单平均分配策略（实际应用中可能需要更复杂的逻辑）
        let rx_per_connection = rx_delta / active_connections.len() as u64;
        let tx_per_connection = tx_delta / active_connections.len() as u64;

        for ip in active_connections {
            let mut stats = self.stats.entry(ip).or_insert_with(TrafficStats::default);
            stats.rx_bytes = stats.rx_bytes.saturating_add(rx_per_connection);
            stats.tx_bytes = stats.tx_bytes.saturating_add(tx_per_connection);
            stats.last_updated = Instant::now();

            debug!(
                "更新IP {} 流量统计: RX +{}, TX +{}",
                ip, rx_per_connection, tx_per_connection
            );
        }

        Ok(())
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

    /// 获取接口统计信息
    async fn get_interface_stats(&self) -> anyhow::Result<InterfaceStats> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(self.interface.clone())
            .execute();

        while let Some(msg) = links.try_next().await? {
            if self.is_interface_up(&msg) {
                return self.extract_interface_stats(&msg);
            }
        }

        anyhow::bail!("接口 {} 未找到或未启用", self.interface)
    }

    /// 检查接口是否处于 UP 状态
    fn is_interface_up(&self, msg: &LinkMessage) -> bool {
        msg.header.flags.contains(LinkFlags::Up)
    }

    /// 从链路消息中提取统计信息
    fn extract_interface_stats(&self, msg: &LinkMessage) -> anyhow::Result<InterfaceStats> {
        for attr in &msg.attributes {
            match attr {
                LinkAttribute::Stats64(stats) => {
                    return Ok(InterfaceStats {
                        rx_bytes: stats.rx_bytes,
                        tx_bytes: stats.tx_bytes,
                        rx_packets: stats.rx_packets,
                        tx_packets: stats.tx_packets,
                    });
                }
                LinkAttribute::Stats(stats) => {
                    return Ok(InterfaceStats {
                        rx_bytes: stats.rx_bytes as u64,
                        tx_bytes: stats.tx_bytes as u64,
                        rx_packets: stats.rx_packets as u64,
                        tx_packets: stats.tx_packets as u64,
                    });
                }
                _ => continue,
            }
        }
        anyhow::bail!("无法获取接口 {} 的统计信息", self.interface)
    }
}



/// 连接信息结构体
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: String, // "tcp" 或 "udp"
    pub state: String,    // 连接状态
    pub last_activity: Instant,
    pub historical_rx: u64,
    pub historical_tx: u64,
    pub weight: f64,      // 权重，用于分配流量
}

impl TrafficMonitor {
    /// 根据连接权重分配流量（替换原来的简单平均分配）
    async fn distribute_traffic_by_weighted_connections(
        &self,
        rx_delta: u64,
        tx_delta: u64,
    ) -> anyhow::Result<()> {
        // 获取活跃连接的详细信息
        let active_connections = self.get_active_connections_with_info().await?;
        
        if active_connections.is_empty() {
            debug!("没有找到活跃连接，跳过流量分配");
            return Ok(());
        }
        
        // 计算权重并分配流量
        let distributed_traffic = self.calculate_weighted_distribution(
            &active_connections, 
            rx_delta, 
            tx_delta
        ).await?;
        
        // 更新统计信息
        for (ip, (rx_bytes, tx_bytes)) in distributed_traffic {
            let mut stats = self.stats.entry(ip).or_insert_with(TrafficStats::default);
            stats.rx_bytes = stats.rx_bytes.saturating_add(rx_bytes);
            stats.tx_bytes = stats.tx_bytes.saturating_add(tx_bytes);
            stats.last_updated = Instant::now();
            
            debug!("更新IP {} 流量统计: RX +{}, TX +{}", ip, rx_bytes, tx_bytes);
        }
        
        Ok(())
    }

    /// 计算基于权重的流量分配
    async fn calculate_weighted_distribution(
        &self,
        connections: &[ConnectionInfo],
        total_rx: u64,
        total_tx: u64,
    ) -> anyhow::Result<HashMap<IpAddr, (u64, u64)>> {
        let mut distribution = HashMap::new();
        
        // 方法1: 基于历史流量比例分配
        let total_historical_rx: u64 = connections.iter()
            .map(|conn| conn.historical_rx)
            .sum();
        let total_historical_tx: u64 = connections.iter()
            .map(|conn| conn.historical_tx)
            .sum();
        
        if total_historical_rx > 0 || total_historical_tx > 0 {
            // 基于历史流量比例分配
            for conn in connections {
                let rx_ratio = if total_historical_rx > 0 {
                    conn.historical_rx as f64 / total_historical_rx as f64
                } else {
                    1.0 / connections.len() as f64
                };
                
                let tx_ratio = if total_historical_tx > 0 {
                    conn.historical_tx as f64 / total_historical_tx as f64
                } else {
                    1.0 / connections.len() as f64
                };
                
                let allocated_rx = (total_rx as f64 * rx_ratio) as u64;
                let allocated_tx = (total_tx as f64 * tx_ratio) as u64;
                
                *distribution.entry(conn.ip).or_insert((0, 0)) = (allocated_rx, allocated_tx);
            }
        } else {
            // 方法2: 基于连接类型和状态的权重分配
            self.distribute_by_connection_weight(connections, total_rx, total_tx, &mut distribution);
        }
        
        Ok(distribution)
    }
    
    /// 基于连接类型和状态分配流量
    fn distribute_by_connection_weight(
        &self,
        connections: &[ConnectionInfo],
        total_rx: u64,
        total_tx: u64,
        distribution: &mut HashMap<IpAddr, (u64, u64)>,
    ) {
        let total_weight: f64 = connections.iter().map(|conn| conn.weight).sum();
        
        if total_weight > 0.0 {
            for conn in connections {
                let weight_ratio = conn.weight / total_weight;
                let allocated_rx = (total_rx as f64 * weight_ratio) as u64;
                let allocated_tx = (total_tx as f64 * weight_ratio) as u64;
                
                *distribution.entry(conn.ip).or_insert((0, 0)) = (allocated_rx, allocated_tx);
            }
        } else {
            // fallback 到平均分配
            let rx_per_connection = total_rx / connections.len() as u64;
            let tx_per_connection = total_tx / connections.len() as u64;
            
            for conn in connections {
                *distribution.entry(conn.ip).or_insert((0, 0)) = (rx_per_connection, tx_per_connection);
            }
        }
    }

    /// 获取带详细信息的活跃连接
    async fn get_active_connections_with_info(&self) -> anyhow::Result<Vec<ConnectionInfo>> {
        let mut connections = Vec::new();
        
        // 解析TCP连接
        if let Ok(tcp_connections) = self.parse_proc_net_tcp_with_info().await {
            connections.extend(tcp_connections);
        }
        
        // 解析UDP连接
        if let Ok(udp_connections) = self.parse_proc_net_udp_with_info().await {
            connections.extend(udp_connections);
        }
        
        // 计算权重
        for conn in &mut connections {
            conn.weight = self.calculate_connection_weight(conn);
        }
        
        Ok(connections)
    }
    
    /// 计算连接权重
    fn calculate_connection_weight(&self, conn: &ConnectionInfo) -> f64 {
        let mut weight = 1.0;
        
        // 基于协议类型调整权重
        match conn.protocol.as_str() {
            "tcp" => {
                // TCP连接根据状态调整权重
                match conn.state.as_str() {
                    "01" => weight *= 2.0, // ESTABLISHED - 活跃连接，权重更高
                    "02" => weight *= 0.5, // SYN_SENT
                    "03" => weight *= 0.5, // SYN_RECV
                    "08" => weight *= 0.1, // CLOSE_WAIT
                    "0A" => weight *= 0.1, // LISTEN - 监听状态，流量较少
                    _ => weight *= 1.0,
                }
            }
            "udp" => {
                weight *= 1.5; // UDP连接通常更活跃
            }
            _ => {}
        }
        
        // 基于历史流量调整权重
        let total_historical = conn.historical_rx + conn.historical_tx;
        if total_historical > 0 {
            // 流量越大，权重越高（对数缩放避免过度倾斜）
            weight *= (total_historical as f64).log10().max(1.0);
        }
        
        // 基于最近活动时间调整权重
        let inactive_duration = Instant::now().duration_since(conn.last_activity);
        if inactive_duration.as_secs() > 60 {
            weight *= 0.5; // 长时间不活跃的连接权重降低
        }
        
        weight
    }

    /// 解析TCP连接详细信息
    async fn parse_proc_net_tcp_with_info(&self) -> anyhow::Result<Vec<ConnectionInfo>> {
        let mut connections = Vec::new();
        
        // 解析IPv4 TCP连接
        if let Ok(content) = tokio::fs::read_to_string("/proc/net/tcp").await {
            connections.extend(self.parse_net_file_with_info(&content, "tcp", false)?);
        }
        
        // 解析IPv6 TCP连接
        if let Ok(content) = tokio::fs::read_to_string("/proc/net/tcp6").await {
            connections.extend(self.parse_net_file_with_info(&content, "tcp", true)?);
        }
        
        Ok(connections)
    }

    /// 解析UDP连接详细信息
    async fn parse_proc_net_udp_with_info(&self) -> anyhow::Result<Vec<ConnectionInfo>> {
        let mut connections = Vec::new();
        
        // 解析IPv4 UDP连接
        if let Ok(content) = tokio::fs::read_to_string("/proc/net/udp").await {
            connections.extend(self.parse_net_file_with_info(&content, "udp", false)?);
        }
        
        // 解析IPv6 UDP连接
        if let Ok(content) = tokio::fs::read_to_string("/proc/net/udp6").await {
            connections.extend(self.parse_net_file_with_info(&content, "udp", true)?);
        }
        
        Ok(connections)
    }

    /// 解析网络文件内容并提取详细信息
    fn parse_net_file_with_info(
        &self, 
        content: &str, 
        protocol: &str, 
        is_ipv6: bool
    ) -> anyhow::Result<Vec<ConnectionInfo>> {
        let mut connections = Vec::new();
        
        for line in content.lines().skip(1) { // 跳过标题行
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 {
                continue;
            }
            
            // 解析本地地址
            if let Ok((ip, port)) = self.parse_address_with_port(fields[1], is_ipv6) {
                if !ip.is_loopback() && !ip.is_unspecified() {
                    // 获取历史流量统计
                    let (historical_rx, historical_tx) = if let Some(stats) = self.stats.get(&ip) {
                        (stats.rx_bytes, stats.tx_bytes)
                    } else {
                        (0, 0)
                    };
                    
                    connections.push(ConnectionInfo {
                        ip,
                        port,
                        protocol: protocol.to_string(),
                        state: fields[3].to_string(), // 连接状态
                        last_activity: Instant::now(),
                        historical_rx,
                        historical_tx,
                        weight: 1.0, // 将在后续计算
                    });
                }
            }
        }
        
        Ok(connections)
    }
    
    /// 解析带端口的地址
    fn parse_address_with_port(&self, addr_str: &str, is_ipv6: bool) -> anyhow::Result<(IpAddr, u16)> {
        let parts: Vec<&str> = addr_str.split(':').collect();
        if parts.len() != 2 {
            anyhow::bail!("无效的地址格式: {}", addr_str);
        }
        
        let addr_hex = parts[0];
        let port = u16::from_str_radix(parts[1], 16)?;
        
        let ip = if is_ipv6 {
            // IPv6地址解析
            if addr_hex.len() != 32 {
                anyhow::bail!("无效的IPv6地址长度: {}", addr_hex);
            }
            
            let mut bytes = [0u8; 16];
            for i in 0..16 {
                let hex_byte = &addr_hex[i*2..i*2+2];
                bytes[i] = u8::from_str_radix(hex_byte, 16)?;
            }
            
            IpAddr::V6(Ipv6Addr::from(bytes))
        } else {
            // IPv4地址解析
            if addr_hex.len() != 8 {
                anyhow::bail!("无效的IPv4地址长度: {}", addr_hex);
            }
            
            let addr_u32 = u32::from_str_radix(addr_hex, 16)?;
            let bytes = addr_u32.to_le_bytes(); // 小端序
            IpAddr::V4(Ipv4Addr::from(bytes))
        };
        
        Ok((ip, port))
    }
}
/// 运行主监控逻辑
pub async fn run(cfg: Config, fw: &Arc<RwLock<Firewall>>) -> anyhow::Result<()> {
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
            Ok(v) => {}
            Err(e) => error!("check and apply fail {}", e),
        }
        drop(fw_guard);
    }
}

/////////
// 直接获取每个IP流量信息的监控方案
use std::path::Path;
use std::process::Command;

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

impl TrafficMonitor {
    /// 主要的流量更新方法 - 直接获取每个IP的流量
    async fn update_traffic_stats_per_ip(&self) -> anyhow::Result<()> {
        // 方法1: 通过iptables规则获取每个IP的流量
        if let Ok(ip_stats) = self.get_traffic_via_iptables().await {
            self.update_stats_from_ip_data(ip_stats).await?;
            return Ok(());
        }
        
        // 方法2: 通过netstat和ss命令获取连接级流量
        if let Ok(ip_stats) = self.get_traffic_via_netstat().await {
            self.update_stats_from_ip_data(ip_stats).await?;
            return Ok(());
        }
        
        // 方法3: 通过解析/proc/net/dev和连接表计算
        if let Ok(ip_stats) = self.get_traffic_via_proc_analysis().await {
            self.update_stats_from_ip_data(ip_stats).await?;
            return Ok(());
        }
        
        // 方法4: 使用BPF/eBPF (如果可用)
        if let Ok(ip_stats) = self.get_traffic_via_bpf().await {
            self.update_stats_from_ip_data(ip_stats).await?;
            return Ok(());
        }
        
        warn!("所有流量获取方法都失败，回退到原始方法");
        self.update_traffic_stats().await
    }

    /// 方法1: 通过iptables规则获取每个IP的流量统计
    async fn get_traffic_via_iptables(&self) -> anyhow::Result<HashMap<IpAddr, IpTrafficStats>> {
        let mut ip_stats = HashMap::new();
        
        // 首先确保有iptables规则来统计流量
        self.ensure_iptables_rules().await?;
        
        // 获取iptables统计信息
        let output = Command::new("iptables")
            .args(["-L", "INPUT", "-v", "-n", "-x"])
            .output()?;
        
        if !output.status.success() {
            anyhow::bail!("执行iptables命令失败");
        }
        
        let stdout = String::from_utf8(output.stdout)?;
        self.parse_iptables_output(&stdout, &mut ip_stats)?;
        
        // 同样处理OUTPUT链
        let output = Command::new("iptables")
            .args(["-L", "OUTPUT", "-v", "-n", "-x"])
            .output()?;
        
        if output.status.success() {
            let stdout = String::from_utf8(output.stdout)?;
            self.parse_iptables_output(&stdout, &mut ip_stats)?;
        }
        
        Ok(ip_stats)
    }
    
    /// 确保iptables规则存在以统计每个IP的流量
    async fn ensure_iptables_rules(&self) -> anyhow::Result<()> {
        // 获取当前活跃的IP地址
        let active_ips = self.get_active_ips().await?;
        
        for ip in active_ips {
            // 为每个IP创建INPUT和OUTPUT规则
            let ip_str = ip.to_string();
            
            // INPUT规则 (接收流量)
            let _result = Command::new("iptables")
                .args(["-I", "INPUT", "-s", &ip_str, "-j", "ACCEPT"])
                .output();
            
            // OUTPUT规则 (发送流量)
            let _result = Command::new("iptables")
                .args(["-I", "OUTPUT", "-d", &ip_str, "-j", "ACCEPT"])
                .output();
        }
        
        Ok(())
    }
    
    /// 解析iptables输出获取流量统计
    fn parse_iptables_output(
        &self, 
        output: &str, 
        ip_stats: &mut HashMap<IpAddr, IpTrafficStats>
    ) -> anyhow::Result<()> {
        for line in output.lines().skip(2) { // 跳过标题行
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 9 {
                continue;
            }
            
            // 格式: pkts bytes target prot opt in out source destination
            let packets: u64 = fields[0].parse().unwrap_or(0);
            let bytes: u64 = fields[1].parse().unwrap_or(0);
            let source = fields[7];
            let destination = fields[8];
            
            // 解析源IP和目标IP
            if let Ok(src_ip) = source.parse::<IpAddr>() {
                let entry = ip_stats.entry(src_ip).or_insert_with(|| IpTrafficStats {
                    ip: src_ip,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    rx_packets: 0,
                    tx_packets: 0,
                    last_updated: Instant::now(),
                    connections: Vec::new(),
                });
                entry.tx_bytes += bytes;
                entry.tx_packets += packets;
            }
            
            if let Ok(dst_ip) = destination.parse::<IpAddr>() {
                let entry = ip_stats.entry(dst_ip).or_insert_with(|| IpTrafficStats {
                    ip: dst_ip,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    rx_packets: 0,
                    tx_packets: 0,
                    last_updated: Instant::now(),
                    connections: Vec::new(),
                });
                entry.rx_bytes += bytes;
                entry.rx_packets += packets;
            }
        }
        
        Ok(())
    }

    /// 方法2: 通过ss命令获取连接级流量统计
    async fn get_traffic_via_netstat(&self) -> anyhow::Result<HashMap<IpAddr, IpTrafficStats>> {
        let mut ip_stats = HashMap::new();
        
        // 使用ss命令获取详细的连接信息
        let output = Command::new("ss")
            .args(["-tuln", "-e", "-i"]) // -e显示扩展信息, -i显示内部TCP信息
            .output()?;
        
        if !output.status.success() {
            anyhow::bail!("执行ss命令失败");
        }
        
        let stdout = String::from_utf8(output.stdout)?;
        self.parse_ss_output(&stdout, &mut ip_stats)?;
        
        Ok(ip_stats)
    }
    
    /// 解析ss命令输出
    fn parse_ss_output(
        &self, 
        output: &str, 
        ip_stats: &mut HashMap<IpAddr, IpTrafficStats>
    ) -> anyhow::Result<()> {
        for line in output.lines() {
            if line.starts_with("tcp") || line.starts_with("udp") {
                if let Ok(connection) = self.parse_ss_line(line) {
                    // 将连接信息添加到对应IP的统计中
                    let entry = ip_stats.entry(connection.remote_ip).or_insert_with(|| IpTrafficStats {
                        ip: connection.remote_ip,
                        rx_bytes: 0,
                        tx_bytes: 0,
                        rx_packets: 0,
                        tx_packets: 0,
                        last_updated: Instant::now(),
                        connections: Vec::new(),
                    });
                    
                    entry.rx_bytes += connection.rx_bytes;
                    entry.tx_bytes += connection.tx_bytes;
                    entry.connections.push(connection);
                }
            }
        }
        
        Ok(())
    }
    
    /// 解析单行ss输出
    fn parse_ss_line(&self, line: &str) -> anyhow::Result<ConnectionDetail> {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            anyhow::bail!("ss输出格式不正确");
        }
        
        let protocol = fields[0].to_string();
        let state = fields[1].to_string();
        let local_addr = fields[4];
        let remote_addr = if fields.len() > 5 { fields[5] } else { "0.0.0.0:0" };
        
        // 解析地址
        let (local_ip, local_port) = self.parse_socket_address(local_addr)?;
        let (remote_ip, remote_port) = self.parse_socket_address(remote_addr)?;
        
        // 从扩展信息中提取流量统计 (如果可用)
        let (rx_bytes, tx_bytes) = self.extract_traffic_from_ss_line(line);
        
        Ok(ConnectionDetail {
            local_port,
            remote_ip,
            remote_port,
            protocol,
            state,
            rx_bytes,
            tx_bytes,
        })
    }
    
    /// 从ss输出行提取流量信息
    fn extract_traffic_from_ss_line(&self, line: &str) -> (u64, u64) {
        // ss -i 输出包含类似 "bytes_sent:1234 bytes_received:5678" 的信息
        let mut rx_bytes = 0u64;
        let mut tx_bytes = 0u64;
        
        if let Some(start) = line.find("bytes_sent:") {
            if let Some(end) = line[start..].find(' ') {
                if let Ok(bytes) = line[start+11..start+end].parse::<u64>() {
                    tx_bytes = bytes;
                }
            }
        }
        
        if let Some(start) = line.find("bytes_received:") {
            if let Some(end) = line[start..].find(' ') {
                if let Ok(bytes) = line[start+15..start+end].parse::<u64>() {
                    rx_bytes = bytes;
                }
            }
        }
        
        (rx_bytes, tx_bytes)
    }

    /// 方法3: 通过分析/proc文件系统获取每IP流量
    async fn get_traffic_via_proc_analysis(&self) -> anyhow::Result<HashMap<IpAddr, IpTrafficStats>> {
        let mut ip_stats = HashMap::new();
        
        // 读取网络连接信息
        let connections = self.get_all_connections_with_pids().await?;
        
        // 为每个连接获取进程级别的网络统计
        for conn in connections {
            if let Ok(traffic) = self.get_process_network_stats(conn.pid).await {
                let entry = ip_stats.entry(conn.remote_ip).or_insert_with(|| IpTrafficStats {
                    ip: conn.remote_ip,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    rx_packets: 0,
                    tx_packets: 0,
                    last_updated: Instant::now(),
                    connections: Vec::new(),
                });
                
                entry.rx_bytes += traffic.0;
                entry.tx_bytes += traffic.1;
                entry.connections.push(ConnectionDetail {
                    local_port: conn.local_port,
                    remote_ip: conn.remote_ip,
                    remote_port: conn.remote_port,
                    protocol: conn.protocol,
                    state: conn.state,
                    rx_bytes: traffic.0,
                    tx_bytes: traffic.1,
                });
            }
        }
        
        Ok(ip_stats)
    }

    /// 方法4: 使用BPF获取每IP流量 (需要BPF支持)
    async fn get_traffic_via_bpf(&self) -> anyhow::Result<HashMap<IpAddr, IpTrafficStats>> {
        // 这里需要BPF/eBPF支持，可以使用类似bcc-tools的工具
        // 或者使用Rust的aya库来编写BPF程序
        
        // 示例：使用现有的BPF工具
        let output = Command::new("python3")
            .args(["-c", r#"
import subprocess
import json

# 使用bcc的tcptop工具获取每个连接的流量
try:
    result = subprocess.run(['tcptop', '-C', '-c', '1'], 
                          capture_output=True, text=True, timeout=2)
    if result.returncode == 0:
        print(result.stdout)
except:
    pass
"#])
            .output();
        
        if let Ok(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                return self.parse_bpf_output(&stdout);
            }
        }
        
        anyhow::bail!("BPF方法不可用")
    }
    
    /// 解析BPF工具输出
    fn parse_bpf_output(&self, output: &str) -> anyhow::Result<HashMap<IpAddr, IpTrafficStats>> {
        let mut ip_stats = HashMap::new();
        
        for line in output.lines() {
            // 解析tcptop输出格式
            // 通常格式为: PID COMM LADDR RADDR RX_KB TX_KB
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 6 {
                if let (Ok(remote_ip), Ok(rx_kb), Ok(tx_kb)) = (
                    self.extract_ip_from_addr(fields[4]),
                    fields[5].parse::<f64>(),
                    fields[6].parse::<f64>()
                ) {
                    let entry = ip_stats.entry(remote_ip).or_insert_with(|| IpTrafficStats {
                        ip: remote_ip,
                        rx_bytes: 0,
                        tx_bytes: 0,
                        rx_packets: 0,
                        tx_packets: 0,
                        last_updated: Instant::now(),
                        connections: Vec::new(),
                    });
                    
                    entry.rx_bytes += (rx_kb * 1024.0) as u64;
                    entry.tx_bytes += (tx_kb * 1024.0) as u64;
                }
            }
        }
        
        Ok(ip_stats)
    }

    /// 从地址字符串提取IP
    fn extract_ip_from_addr(&self, addr: &str) -> anyhow::Result<IpAddr> {
        if let Some(colon_pos) = addr.rfind(':') {
            let ip_str = &addr[..colon_pos];
            Ok(ip_str.parse()?)
        } else {
            Ok(addr.parse()?)
        }
    }

    /// 更新统计数据
    async fn update_stats_from_ip_data(
        &self, 
        ip_stats: HashMap<IpAddr, IpTrafficStats>
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
    
    /// 辅助方法：解析socket地址
    fn parse_socket_address(&self, addr: &str) -> anyhow::Result<(IpAddr, u16)> {
        if let Some(colon_pos) = addr.rfind(':') {
            let ip_str = &addr[..colon_pos];
            let port_str = &addr[colon_pos + 1..];
            
            let ip: IpAddr = ip_str.parse()?;
            let port: u16 = port_str.parse()?;
            
            Ok((ip, port))
        } else {
            anyhow::bail!("无效的socket地址格式: {}", addr);
        }
    }

    /// 获取带PID的连接信息 (需要root权限)
    async fn get_all_connections_with_pids(&self) -> anyhow::Result<Vec<ConnectionWithPid>> {
        // 实现留给具体的系统调用或工具
        // 可以使用netstat -p 或 lsof -i
        Ok(Vec::new())
    }

    /// 获取进程的网络统计
    async fn get_process_network_stats(&self, pid: u32) -> anyhow::Result<(u64, u64)> {
        // 读取 /proc/{pid}/net/dev 或类似文件
        // 这个方法的实现取决于具体的系统和权限
        Ok((0, 0))
    }
}

/// 带PID的连接信息
#[derive(Debug)]
struct ConnectionWithPid {
    pub pid: u32,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub protocol: String,
    pub state: String,
}


/////////

// Rust原生方法获取每个IP的流量统计


use std::fs;
use std::io::{self, BufRead, BufReader};


/// 连接状态枚举
#[derive(Debug, Clone)]
pub enum ConnectionState {
    Established = 0x01,
    SynSent = 0x02,
    SynRecv = 0x03,
    FinWait1 = 0x04,
    FinWait2 = 0x05,
    TimeWait = 0x06,
    Close = 0x07,
    CloseWait = 0x08,
    LastAck = 0x09,
    Listen = 0x0A,
    Closing = 0x0B,
    Unknown,
}

impl From<u8> for ConnectionState {
    fn from(state: u8) -> Self {
        match state {
            0x01 => ConnectionState::Established,
            0x02 => ConnectionState::SynSent,
            0x03 => ConnectionState::SynRecv,
            0x04 => ConnectionState::FinWait1,
            0x05 => ConnectionState::FinWait2,
            0x06 => ConnectionState::TimeWait,
            0x07 => ConnectionState::Close,
            0x08 => ConnectionState::CloseWait,
            0x09 => ConnectionState::LastAck,
            0x0A => ConnectionState::Listen,
            0x0B => ConnectionState::Closing,
            _ => ConnectionState::Unknown,
        }
    }
}

/// 单个连接的详细信息
#[derive(Debug, Clone)]
pub struct PerConnectionInfo {
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub state: ConnectionState,
    pub inode: u64,
    pub uid: u32,
    pub protocol: String,
}

/// 每个IP的流量统计（通过连接关联）
#[derive(Debug, Clone)]
pub struct IpTrafficDetail {
    pub ip: IpAddr,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub connections: Vec<PerConnectionInfo>,
    pub last_updated: Instant,
}

impl TrafficMonitor {
    /// 使用Rust原生方法更新流量统计
    async fn update_traffic_stats_native(&self) -> anyhow::Result<()> {
        // 1. 获取所有网络连接
        let connections = self.get_all_connections_native().await?;
        
        // 2. 通过连接信息计算每个IP的流量
        let ip_traffic_map = self.calculate_ip_traffic_from_connections(&connections).await?;
        
        // 3. 更新内部统计
        self.update_internal_stats(ip_traffic_map).await;
        
        Ok(())
    }

    /// 获取所有网络连接（TCP + UDP）
    async fn get_all_connections_native(&self) -> anyhow::Result<Vec<PerConnectionInfo>> {
        let mut all_connections = Vec::new();
        
        // 获取TCP连接
        all_connections.extend(self.read_tcp_connections("/proc/net/tcp", false).await?);
        all_connections.extend(self.read_tcp_connections("/proc/net/tcp6", true).await?);
        
        // 获取UDP连接
        all_connections.extend(self.read_udp_connections("/proc/net/udp", false).await?);
        all_connections.extend(self.read_udp_connections("/proc/net/udp6", true).await?);
        
        Ok(all_connections)
    }

    /// 读取TCP连接信息
    async fn read_tcp_connections(&self, path: &str, is_ipv6: bool) -> anyhow::Result<Vec<PerConnectionInfo>> {
        let mut connections = Vec::new();
        
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        
        for (line_num, line) in reader.lines().enumerate() {
            if line_num == 0 { continue; } // 跳过标题行
            
            let line = line?;
            if let Ok(conn) = self.parse_tcp_line(&line, is_ipv6) {
                connections.push(conn);
            }
        }
        
        Ok(connections)
    }

    /// 读取UDP连接信息
    async fn read_udp_connections(&self, path: &str, is_ipv6: bool) -> anyhow::Result<Vec<PerConnectionInfo>> {
        let mut connections = Vec::new();
        
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        
        for (line_num, line) in reader.lines().enumerate() {
            if line_num == 0 { continue; } // 跳过标题行
            
            let line = line?;
            if let Ok(conn) = self.parse_udp_line(&line, is_ipv6) {
                connections.push(conn);
            }
        }
        
        Ok(connections)
    }

    /// 解析TCP连接行
    fn parse_tcp_line(&self, line: &str, is_ipv6: bool) -> anyhow::Result<PerConnectionInfo> {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            anyhow::bail!("TCP行格式不正确");
        }

        // 格式: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
        let local_addr = fields[1];
        let remote_addr = fields[2];
        let state_hex = fields[3];
        let uid = fields[7].parse::<u32>().unwrap_or(0);
        let inode = fields[9].parse::<u64>().unwrap_or(0);

        let (local_ip, local_port) = self.parse_address_native(local_addr, is_ipv6)?;
        let (remote_ip, remote_port) = self.parse_address_native(remote_addr, is_ipv6)?;
        
        let state_num = u8::from_str_radix(state_hex, 16).unwrap_or(0);
        let state = ConnectionState::from(state_num);

        Ok(PerConnectionInfo {
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            state,
            inode,
            uid,
            protocol: "tcp".to_string(),
        })
    }

    /// 解析UDP连接行
    fn parse_udp_line(&self, line: &str, is_ipv6: bool) -> anyhow::Result<PerConnectionInfo> {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            anyhow::bail!("UDP行格式不正确");
        }

        let local_addr = fields[1];
        let remote_addr = fields[2];
        let uid = fields[7].parse::<u32>().unwrap_or(0);
        let inode = fields[9].parse::<u64>().unwrap_or(0);

        let (local_ip, local_port) = self.parse_address_native(local_addr, is_ipv6)?;
        let (remote_ip, remote_port) = self.parse_address_native(remote_addr, is_ipv6)?;

        Ok(PerConnectionInfo {
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            state: ConnectionState::Established, // UDP没有状态概念
            inode,
            uid,
            protocol: "udp".to_string(),
        })
    }

    /// 解析地址字符串 (原生方法)
    fn parse_address_native(&self, addr_str: &str, is_ipv6: bool) -> anyhow::Result<(IpAddr, u16)> {
        let parts: Vec<&str> = addr_str.split(':').collect();
        if parts.len() != 2 {
            anyhow::bail!("地址格式错误: {}", addr_str);
        }

        let addr_hex = parts[0];
        let port = u16::from_str_radix(parts[1], 16)?;

        let ip = if is_ipv6 {
            if addr_hex.len() != 32 {
                anyhow::bail!("IPv6地址长度错误");
            }
            
            let mut bytes = [0u8; 16];
            for i in 0..16 {
                let start = i * 2;
                let end = start + 2;
                bytes[i] = u8::from_str_radix(&addr_hex[start..end], 16)?;
            }
            
            IpAddr::V6(Ipv6Addr::from(bytes))
        } else {
            if addr_hex.len() != 8 {
                anyhow::bail!("IPv4地址长度错误");
            }
            
            let addr_u32 = u32::from_str_radix(addr_hex, 16)?;
            let bytes = addr_u32.to_le_bytes(); // 小端序转换
            IpAddr::V4(Ipv4Addr::from(bytes))
        };

        Ok((ip, port))
    }

    /// 通过连接信息计算每个IP的流量
    async fn calculate_ip_traffic_from_connections(
        &self, 
        connections: &[PerConnectionInfo]
    ) -> anyhow::Result<HashMap<IpAddr, IpTrafficDetail>> {
        let mut ip_traffic_map = HashMap::new();

        // 方法1: 通过socket统计信息获取流量
        for conn in connections {
            // 获取socket的流量统计
            if let Ok((rx_bytes, tx_bytes)) = self.get_socket_traffic_by_inode(conn.inode).await {
                // 为本地IP和远程IP分别记录流量
                self.add_traffic_to_map(&mut ip_traffic_map, conn.local_ip, rx_bytes, tx_bytes, conn.clone());
                self.add_traffic_to_map(&mut ip_traffic_map, conn.remote_ip, tx_bytes, rx_bytes, conn.clone());
            }
        }

        // 方法2: 如果方法1失败，使用网络接口统计推算
        if ip_traffic_map.is_empty() {
            return self.estimate_traffic_from_interface_stats(connections).await;
        }

        Ok(ip_traffic_map)
    }

    /// 通过inode获取socket的流量统计
    async fn get_socket_traffic_by_inode(&self, inode: u64) -> anyhow::Result<(u64, u64)> {
        // 查找对应的进程
        if let Ok(pid) = self.find_process_by_socket_inode(inode).await {
            // 读取进程的网络统计
            return self.get_process_network_stats_native(pid).await;
        }

        // 如果找不到进程，尝试从 /proc/net/sockstat 推算
        self.estimate_socket_traffic(inode).await
    }

    /// 通过socket inode查找进程ID
    async fn find_process_by_socket_inode(&self, target_inode: u64) -> anyhow::Result<u32> {
        let proc_dir = fs::read_dir("/proc")?;
        
        for entry in proc_dir {
            let entry = entry?;
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();
            
            // 只处理数字目录（进程ID）
            if let Ok(pid) = file_name_str.parse::<u32>() {
                if let Ok(found_inode) = self.check_process_sockets(pid, target_inode).await {
                    if found_inode {
                        return Ok(pid);
                    }
                }
            }
        }
        
        anyhow::bail!("未找到对应的进程")
    }

    /// 检查进程的socket是否包含目标inode
    async fn check_process_sockets(&self, pid: u32, target_inode: u64) -> anyhow::Result<bool> {
        let fd_dir_path = format!("/proc/{}/fd", pid);
        
        if let Ok(fd_dir) = fs::read_dir(&fd_dir_path) {
            for fd_entry in fd_dir {
                let fd_entry = fd_entry?;
                let link_path = fd_entry.path();
                
                if let Ok(link_target) = fs::read_link(&link_path) {
                    let link_str = link_target.to_string_lossy();
                    if link_str.starts_with("socket:[") {
                        // 提取inode号
                        if let Some(start) = link_str.find('[') {
                            if let Some(end) = link_str.find(']') {
                                let inode_str = &link_str[start+1..end];
                                if let Ok(inode) = inode_str.parse::<u64>() {
                                    if inode == target_inode {
                                        return Ok(true);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        Ok(false)
    }

    /// 获取进程的网络统计信息
    async fn get_process_network_stats_native(&self, pid: u32) -> anyhow::Result<(u64, u64)> {
        // 方法1: 读取 /proc/{pid}/net/dev
        let net_dev_path = format!("/proc/{}/net/dev", pid);
        if let Ok(content) = fs::read_to_string(&net_dev_path) {
            if let Ok((rx, tx)) = self.parse_proc_net_dev(&content) {
                return Ok((rx, tx));
            }
        }

        // 方法2: 读取 /proc/{pid}/status 中的网络相关信息
        let status_path = format!("/proc/{}/status", pid);
        if let Ok(content) = fs::read_to_string(&status_path) {
            if let Ok((rx, tx)) = self.parse_proc_status_network(&content) {
                return Ok((rx, tx));
            }
        }

        // 方法3: 读取 /proc/{pid}/io
        let io_path = format!("/proc/{}/io", pid);
        if let Ok(content) = fs::read_to_string(&io_path) {
            return self.parse_proc_io(&content);
        }

        Ok((0, 0))
    }

    /// 解析 /proc/net/dev 内容
    fn parse_proc_net_dev(&self, content: &str) -> anyhow::Result<(u64, u64)> {
        let mut total_rx = 0u64;
        let mut total_tx = 0u64;

        for line in content.lines().skip(2) { // 跳过标题行
            let line = line.trim();
            if let Some(colon_pos) = line.find(':') {
                let stats_part = &line[colon_pos + 1..];
                let fields: Vec<&str> = stats_part.split_whitespace().collect();
                
                if fields.len() >= 9 {
                    // RX bytes是第1个字段，TX bytes是第9个字段
                    if let (Ok(rx), Ok(tx)) = (fields[0].parse::<u64>(), fields[8].parse::<u64>()) {
                        total_rx += rx;
                        total_tx += tx;
                    }
                }
            }
        }

        Ok((total_rx, total_tx))
    }

    /// 解析 /proc/{pid}/io 内容
    fn parse_proc_io(&self, content: &str) -> anyhow::Result<(u64, u64)> {
        let mut read_bytes = 0u64;
        let mut write_bytes = 0u64;

        for line in content.lines() {
            if line.starts_with("read_bytes:") {
                if let Some(value_str) = line.split_whitespace().nth(1) {
                    read_bytes = value_str.parse().unwrap_or(0);
                }
            } else if line.starts_with("write_bytes:") {
                if let Some(value_str) = line.split_whitespace().nth(1) {
                    write_bytes = value_str.parse().unwrap_or(0);
                }
            }
        }

        Ok((read_bytes, write_bytes))
    }

    /// 解析 /proc/status 中的网络信息
    fn parse_proc_status_network(&self, content: &str) -> anyhow::Result<(u64, u64)> {
        // /proc/status 通常不包含网络统计，但可以尝试其他字段
        Ok((0, 0))
    }

    /// 估算socket流量
    async fn estimate_socket_traffic(&self, _inode: u64) -> anyhow::Result<(u64, u64)> {
        // 可以通过 /proc/net/sockstat 等文件尝试估算
        // 这里返回0作为fallback
        Ok((0, 0))
    }

    /// 从接口统计估算流量分配
    async fn estimate_traffic_from_interface_stats(
        &self,
        connections: &[PerConnectionInfo]
    ) -> anyhow::Result<HashMap<IpAddr, IpTrafficDetail>> {
        let mut ip_traffic_map = HashMap::new();
        
        // 获取接口总流量
        let interface_stats = self.get_interface_stats().await?;
        
        // 按连接权重分配
        let active_connections: Vec<_> = connections.iter()
            .filter(|conn| !conn.remote_ip.is_loopback() && !conn.remote_ip.is_unspecified())
            .collect();
        
        if !active_connections.is_empty() {
            let rx_per_connection = interface_stats.rx_bytes / active_connections.len() as u64;
            let tx_per_connection = interface_stats.tx_bytes / active_connections.len() as u64;
            
            for conn in active_connections {
                self.add_traffic_to_map(
                    &mut ip_traffic_map, 
                    conn.remote_ip, 
                    rx_per_connection, 
                    tx_per_connection, 
                    conn.clone()
                );
            }
        }
        
        Ok(ip_traffic_map)
    }

    /// 添加流量到映射表
    fn add_traffic_to_map(
        &self,
        map: &mut HashMap<IpAddr, IpTrafficDetail>,
        ip: IpAddr,
        rx_bytes: u64,
        tx_bytes: u64,
        connection: PerConnectionInfo,
    ) {
        let entry = map.entry(ip).or_insert_with(|| IpTrafficDetail {
            ip,
            rx_bytes: 0,
            tx_bytes: 0,
            connections: Vec::new(),
            last_updated: Instant::now(),
        });
        
        entry.rx_bytes += rx_bytes;
        entry.tx_bytes += tx_bytes;
        entry.connections.push(connection);
        entry.last_updated = Instant::now();
    }

    /// 更新内部统计
    async fn update_internal_stats(&self, ip_traffic_map: HashMap<IpAddr, IpTrafficDetail>) {
        for (ip, traffic_detail) in ip_traffic_map {
            let mut stats = self.stats.entry(ip).or_insert_with(TrafficStats::default);
            
            // 计算增量
            let rx_delta = traffic_detail.rx_bytes.saturating_sub(stats.rx_bytes);
            let tx_delta = traffic_detail.tx_bytes.saturating_sub(stats.tx_bytes);
            
            stats.rx_bytes = traffic_detail.rx_bytes;
            stats.tx_bytes = traffic_detail.tx_bytes;
            stats.last_updated = Instant::now();
            
            if rx_delta > 0 || tx_delta > 0 {
                debug!(
                    "IP {} 流量更新: RX +{} bytes, TX +{} bytes (连接数: {})",
                    ip, rx_delta, tx_delta, traffic_detail.connections.len()
                );
            }
        }
    }
}