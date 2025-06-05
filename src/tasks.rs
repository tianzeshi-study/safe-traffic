use crate::{
    config::Config,
    controller::Firewall,
    monitor::TrafficMonitor,
    nft::NftExecutor,
    rules::{RuleEngine, TrafficStats},
};
use dashmap::DashMap;
use log::info;
use rtnetlink::new_connection;
use std::{net::IpAddr, sync::Arc, time::Duration};

/// 运行主监控逻辑
pub async fn run(cfg: Config, fw: Arc<Firewall>, executor: Arc<NftExecutor>) -> anyhow::Result<()> {
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
    let engine_task = engine.start(
        fw,
        Duration::from_secs(cfg.rule_check_interval.unwrap_or(1)),
    );

    tokio::try_join!(monitor_task, engine_task)?;
    Ok(())
}
