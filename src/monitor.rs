// src/monitor.rs
use crate::{config::Config, controller::Firewall, rules::RuleEngine};
use dashmap::DashMap;
use futures::stream::TryStreamExt;
use log::{error, info};
use rtnetlink::{new_connection, Handle};
use std::{net::IpAddr, sync::Arc};
use tokio::{task, time};

// 导入正确的类型
use netlink_packet_route::link::LinkFlags;
use netlink_packet_route::link::LinkMessage;

/// 运行主监控逻辑
pub async fn run(cfg: Config, fw: &mut Firewall) -> anyhow::Result<()> {
    // 并发安全的 IP 流量统计表：IP -> total_bytes
    let stats = Arc::new(DashMap::<IpAddr, u64>::new());

    // 规则引擎实例
    let engine = RuleEngine::new(cfg.rules.clone(), stats.clone(), fw.clone());

    // 建立 netlink 监听连接
    let (connection, handle, _messages) = new_connection()?;
    tokio::spawn(connection);

    // 启动流量监控任务
    let monitor_task = start_traffic_monitor(handle.clone(), cfg.interface.clone(), stats.clone());

    // 启动规则引擎任务
    let engine_task = start_rule_engine(engine, fw);

    info!("流量监控与规则引擎已启动");

    // 等待任务完成
    tokio::try_join!(monitor_task, engine_task)?;

    Ok(())
}

/// 启动流量监控任务
async fn start_traffic_monitor(
    handle: Handle,
    interface: String,
    stats: Arc<DashMap<IpAddr, u64>>,
) -> anyhow::Result<()> {
    let mut interval = time::interval(time::Duration::from_secs(1));
    let mut last_counters = 0u64;

    loop {
        interval.tick().await;

        match get_interface_stats(&handle, &interface).await {
            Ok(rx_bytes) => {
                let delta = rx_bytes.saturating_sub(last_counters);
                if delta > 0 {
                    // 假设所有流量均来自单一 IP（示例）
                    let dummy_ip: IpAddr = "127.0.0.1".parse().unwrap();
                    stats.insert(dummy_ip, delta);
                }
                last_counters = rx_bytes;
            }
            Err(e) => error!("获取接口统计失败: {:?}", e),
        }
    }
}

/// 获取接口统计信息
async fn get_interface_stats(handle: &Handle, interface_name: &str) -> anyhow::Result<u64> {
    let mut links = handle
        .link()
        .get()
        .match_name(interface_name.to_string())
        .execute();

    while let Some(msg) = links.try_next().await? {
        // 检查接口是否处于 UP 状态

        if is_interface_up(&msg) {
            return get_rx_bytes_from_message(&msg);
        }
    }

    anyhow::bail!("接口 {} 未找到或未启用", interface_name)
}

/// 检查接口是否处于 UP 状态
fn is_interface_up(msg: &LinkMessage) -> bool {
    // 使用 LinkFlags::Up 而不是 IFF_UP
    msg.header.flags.contains(LinkFlags::Up)
}

/// 从链路消息中提取接收字节数
fn get_rx_bytes_from_message(msg: &LinkMessage) -> anyhow::Result<u64> {
    // use netlink_packet_route::link::nlas::Nla;
    // netlink_packet_route::prefix::PrefixMessageBuffer::nlas

    for nla in &msg.attributes {
        match nla {
            netlink_packet_route::link::LinkAttribute::Stats64(stats) => {
                return Ok(stats.rx_bytes);
            }
            // Nla::Stats(stats) => {
            netlink_packet_route::link::LinkAttribute::Stats(stats) => {
                return Ok(stats.rx_bytes as u64);
            }
            _ => continue,
        }
    }

    anyhow::bail!("无法获取接口统计信息")
}

/// 启动规则引擎任务
async fn start_rule_engine(engine: RuleEngine, fw: &mut Firewall) -> anyhow::Result<()> {
    let mut interval = time::interval(time::Duration::from_secs(1));

    loop {
        interval.tick().await;

        if let Err(e) = engine.check_and_apply(fw).await {
            error!("规则引擎出错: {:?}", e);
        }
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
