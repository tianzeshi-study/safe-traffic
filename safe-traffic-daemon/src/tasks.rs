use crate::{
    controller::Firewall, daemon::TrafficDaemon, monitor::TrafficMonitor, nft::NftExecutor,
    rules::RuleEngine,
};

use dashmap::DashMap;
use log::{error, info};

use safe_traffic_common::{config::Config, utils::TrafficStats};
use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::signal;

/// 运行主监控逻辑
pub async fn run(cfg: Config, fw: Arc<Firewall>, executor: Arc<NftExecutor>) -> anyhow::Result<()> {
    let stats = Arc::new(DashMap::<IpAddr, TrafficStats>::new());
    let engine = Arc::new(RuleEngine::new(
        cfg.rules.clone(),
        stats.clone(),
        fw.clone(),
    ));

    let monitor = Arc::new(TrafficMonitor::new(
        cfg.interface.clone(),
        stats,
        // Duration::from_secs(cfg.monitor_interval.unwrap_or(1)),
        Duration::from_secs(cfg.check_interval.unwrap_or(10)),
        // Duration::from_secs(10),
        executor.clone(),
    ));
    let daemon = Arc::new(TrafficDaemon::new(fw.clone(), engine.clone()));

    info!(
        "Traffic monitoring and rules engines have been started, monitoring interface: {}",
        cfg.interface
    );

    // 启动各个组件任务
    let monitor_clone = monitor.clone();
    let engine_clone = engine.clone();
    let daemon_clone = daemon.clone();

    let monitor_task = tokio::spawn(async move { monitor_clone.start().await });

    let engine_task = tokio::spawn(async move {
        engine_clone
            .start(Duration::from_secs(cfg.check_interval.unwrap_or(10)))
            .await
    });
    let daemon_task = tokio::spawn(async move { daemon_clone.start().await });

    // 创建 Ctrl+C 信号处理器
    let ctrl_c = tokio::spawn(async {
        signal::ctrl_c().await.expect("Failed to listen for ctrl+c");
        info!("Received Ctrl+C signal, initiating graceful shutdown...");
    });

    // 等待任一任务完成或接收到 Ctrl+C 信号
    tokio::select! {
        // 监听 Ctrl+C 信号

        _ = ctrl_c => {
            info!("Shutdown signal received, stopping all components...");

            // 优雅停止各个组件

            // 停止规则引擎
            if let Err(e) = engine.stop().await {
                error!("Failed to stop rule engine: {}", e);
            }


            // monitor.stop();

            // daemon.stop();

            // 等待所有任务完成
            // let _ = monitor_task.await;
            // let _ = engine_task.await;
            // let _ = daemon_task.await;

            // info!("All components stopped gracefully");
        }




        result = monitor_task => {
            match result {
                Ok(Ok(())) => info!("Monitor task completed successfully"),
                Ok(Err(e)) => error!("Monitor task failed: {}", e),
                Err(e) => error!("Monitor task panicked: {}", e),
            }
        }

        result = engine_task => {
            match result {
                Ok(Ok(())) => info!("Engine task completed successfully"),
                Ok(Err(e)) => error!("Engine task failed: {}", e),
                Err(e) => error!("Engine task panicked: {}", e),
            }
        }

        result = daemon_task => {
            match result {
                Ok(Ok(())) => info!("Daemon task completed successfully"),
                Ok(Err(e)) => error!("Daemon task failed: {}", e),
                Err(e) => error!("Daemon task panicked: {}", e),
            }
        }

    }

    Ok(())
}
