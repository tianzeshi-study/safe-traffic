use crate::{
    config::Config,
    controller::Firewall,
    rules::{RuleEngine, TrafficStats},
};
use dashmap::DashMap;
use futures::stream::TryStreamExt;
use log::{debug, error, info};
use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
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
            if let Err(e) = self.update_traffic_stats_per_ip().await {
                error!("更新流量统计失败: {:?}", e);
                continue;
            }

            // 清理过期的流量统计
            let expired_rules = self.cleanup_expired_stats().await;
            dbg!(&expired_rules);
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
    pub weight: f64, // 权重，用于分配流量
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

impl TrafficMonitor {
    /// 主要的流量更新方法 - 直接获取每个IP的流量
    async fn update_traffic_stats_per_ip(&self) -> anyhow::Result<()> {
        // 方法1: 通过iptables规则获取每个IP的流量
        let ip_stats = self.get_traffic_via_iptables().await?;
        self.update_stats_from_ip_data(ip_stats).await?;
        Ok(())
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
        ip_stats: &mut HashMap<IpAddr, IpTrafficStats>,
    ) -> anyhow::Result<()> {
        for line in output.lines().skip(2) {
            // 跳过标题行
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
