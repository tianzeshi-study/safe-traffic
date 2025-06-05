use crate::{
    config::Config,
    controller::Firewall,
    nft::{parser::*, NftError, NftExecutor},
    rules::{RuleEngine, TrafficStats},
    monitor::TrafficMonitor,
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

/// 运行主监控逻辑
pub async fn run(
    cfg: Config,
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
    let engine_task =         engine.start(fw,        Duration::from_secs(cfg.rule_check_interval.unwrap_or(1)),   );

    tokio::try_join!(monitor_task, engine_task)?;
    Ok(())
}

