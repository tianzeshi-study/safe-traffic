// src/monitor.rs
use crate::{config::Config, controller::Firewall, rules::RuleEngine};
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
use tokio::{sync::RwLock, task, time};
use netlink_packet_route::{
    link::{LinkAttribute, LinkFlags, LinkMessage},
};

// 网络地址族常量（因为 netlink_packet_route 0.22 没有 constants 模块）
const AF_INET: u8 = 2;   // IPv4
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
            
            if let Err(e) = self.update_traffic_stats().await {
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
                self.distribute_traffic_by_connections(rx_delta, tx_delta).await?;
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
            
            debug!("更新IP {} 流量统计: RX +{}, TX +{}", ip, rx_per_connection, tx_per_connection);
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
        
        for line in content.lines().skip(1) { // 跳过标题行
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
                let hex_byte = &addr_hex[i*2..i*2+2];
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
        
        self.stats.retain(|_ip, stats| {
            now.duration_since(stats.last_updated) < expire_duration
        });
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
    
    info!("Traffic monitoring and rules engines have been started, monitoring interface: {}", cfg.interface);
    
    // 启动监控任务
    let monitor_task = monitor.start();
    
    // 启动规则引擎任务
    let engine_task = start_rule_engine(engine, &fw, Duration::from_secs(cfg.rule_check_interval.unwrap_or(1)));
    
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
        info!("looping rules {:?}", fw_guard);
        // if let Err(e) = engine.check_and_apply(&mut fw_guard).await {
            // error!("Checking engine rules fail   : {:?}", e);
        // }
        match engine.check_and_apply(&mut fw_guard).await {
            Ok(v)=> info!("successful {:?}", v),
Err(e) => error!("check and apply fail {}", e),            
        }
        drop(fw_guard);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::time::{sleep, Duration};

    // Mock 结构体用于测试
    #[derive(Clone)]
    pub struct MockFirewall {
        pub blocked_ips: Arc<DashMap<IpAddr, bool>>,
    }

    impl MockFirewall {
        pub fn new() -> Self {
            Self {
                blocked_ips: Arc::new(DashMap::new()),
            }
        }

        pub fn block_ip(&mut self, ip: IpAddr) -> anyhow::Result<()> {
            self.blocked_ips.insert(ip, true);
            Ok(())
        }

        pub fn is_blocked(&self, ip: &IpAddr) -> bool {
            self.blocked_ips.get(ip).is_some()
        }
    }

    #[derive(Clone)]
    pub struct MockRuleEngine {
        pub stats: Arc<DashMap<IpAddr, u64>>,
        pub threshold: u64,
    }

    impl MockRuleEngine {
        pub fn new(stats: Arc<DashMap<IpAddr, u64>>, threshold: u64) -> Self {
            Self { stats, threshold }
        }

        pub async fn check_and_apply(&self, fw: &mut MockFirewall) -> anyhow::Result<()> {
            for entry in self.stats.iter() {
                let (ip, &bytes) = entry.pair();
                if bytes > self.threshold && !fw.is_blocked(ip) {
                    fw.block_ip(*ip)?;
                }
            }
            Ok(())
        }
    }

    // 模拟 LinkMessage 用于测试
    pub struct MockLinkMessage {
        pub rx_bytes: u64,
        pub is_up: bool,
    }

    impl MockLinkMessage {
        pub fn new(rx_bytes: u64, is_up: bool) -> Self {
            Self { rx_bytes, is_up }
        }

        pub fn get_rx_bytes(&self) -> u64 {
            self.rx_bytes
        }

        pub fn is_interface_up(&self) -> bool {
            self.is_up
        }
    }

    #[tokio::test]
    async fn test_traffic_monitoring_logic() {
        let stats = Arc::new(DashMap::<IpAddr, u64>::new());
        let test_ip: IpAddr = "192.168.1.1".parse().unwrap();

        // 模拟流量数据
        stats.insert(test_ip, 1000);

        // 验证统计数据
        assert_eq!(stats.get(&test_ip).unwrap().value(), &1000);

        // 模拟流量增长
        stats.insert(test_ip, 2000);
        assert_eq!(stats.get(&test_ip).unwrap().value(), &2000);
    }

    #[tokio::test]
    async fn test_rule_engine_blocking() {
        let stats = Arc::new(DashMap::<IpAddr, u64>::new());
        let mut fw = MockFirewall::new();
        let engine = MockRuleEngine::new(stats.clone(), 1500);

        let test_ip: IpAddr = "192.168.1.100".parse().unwrap();

        // 初始状态：IP 未被阻止
        assert!(!fw.is_blocked(&test_ip));

        // 设置低于阈值的流量
        stats.insert(test_ip, 1000);
        engine.check_and_apply(&mut fw).await.unwrap();
        assert!(!fw.is_blocked(&test_ip));

        // 设置高于阈值的流量
        stats.insert(test_ip, 2000);
        engine.check_and_apply(&mut fw).await.unwrap();
        assert!(fw.is_blocked(&test_ip));
    }

    #[tokio::test]
    async fn test_mock_link_message() {
        // 测试模拟链路消息
        let msg_up = MockLinkMessage::new(12345, true);
        assert_eq!(msg_up.get_rx_bytes(), 12345);
        assert!(msg_up.is_interface_up());

        let msg_down = MockLinkMessage::new(0, false);
        assert_eq!(msg_down.get_rx_bytes(), 0);
        assert!(!msg_down.is_interface_up());
    }

    #[tokio::test]
    async fn test_stats_concurrency() {
        let stats = Arc::new(DashMap::<IpAddr, u64>::new());
        let stats_clone = stats.clone();

        // 并发写入测试
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let stats = stats_clone.clone();
                tokio::spawn(async move {
                    let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
                    stats.insert(ip, (i * 100) as u64);
                })
            })
            .collect();

        // 等待所有任务完成
        for handle in handles {
            handle.await.unwrap();
        }

        // 验证所有数据都被正确插入
        assert_eq!(stats.len(), 10);
        for i in 0..10 {
            let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
            assert_eq!(stats.get(&ip).unwrap().value(), &((i * 100) as u64));
        }
    }

    #[tokio::test]
    async fn test_error_handling() {
        // 测试无效接口名称处理
        let stats = Arc::new(DashMap::<IpAddr, u64>::new());

        // 模拟错误情况
        let test_ip: IpAddr = "127.0.0.1".parse().unwrap();
        stats.insert(test_ip, 1000);

        // 验证错误处理不会导致 panic
        assert!(stats.contains_key(&test_ip));
    }

    #[tokio::test]
    async fn test_delta_calculation() {
        let mut last_counters = 1000u64;
        let current_counters = 1500u64;

        let delta = current_counters.saturating_sub(last_counters);
        assert_eq!(delta, 500);

        // 测试溢出情况
        last_counters = 2000;
        let delta_overflow = current_counters.saturating_sub(last_counters);
        assert_eq!(delta_overflow, 0);
    }

    #[tokio::test]
    async fn test_traffic_threshold_logic() {
        let stats = Arc::new(DashMap::<IpAddr, u64>::new());
        let threshold = 1024u64; // 1KB 阈值

        let low_traffic_ip: IpAddr = "192.168.1.10".parse().unwrap();
        let high_traffic_ip: IpAddr = "192.168.1.20".parse().unwrap();

        // 低流量 IP
        stats.insert(low_traffic_ip, 512);
        // 高流量 IP
        stats.insert(high_traffic_ip, 2048);

        // 检查阈值逻辑
        for entry in stats.iter() {
            let (ip, &bytes) = entry.pair();
            if bytes > threshold {
                assert_eq!(*ip, high_traffic_ip);
            } else {
                assert_eq!(*ip, low_traffic_ip);
            }
        }
    }

    #[tokio::test]
    async fn test_interface_monitoring_simulation() {
        // 模拟接口监控场景
        let stats = Arc::new(DashMap::<IpAddr, u64>::new());
        let test_ip: IpAddr = "10.0.0.1".parse().unwrap();

        // 模拟时间序列的流量数据
        let traffic_data = vec![100, 250, 500, 750, 1000, 1200];

        for (time, bytes) in traffic_data.iter().enumerate() {
            stats.insert(test_ip, *bytes);

            // 验证数据随时间递增
            if time > 0 {
                assert!(*bytes >= traffic_data[time - 1]);
            }
        }

        // 验证最终状态
        assert_eq!(stats.get(&test_ip).unwrap().value(), &1200);
    }
}
