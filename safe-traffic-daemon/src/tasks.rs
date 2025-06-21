use crate::{
    controller::Firewall, daemon::TrafficDaemon, monitor::TrafficMonitor, nft::NftExecutor,
    rules::RuleEngine,
};

use dashmap::DashMap;
use log::{error, info};
use rtnetlink::new_connection;
use safe_traffic_common::{config::Config, utils::TrafficStats};
use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::signal;

/// 运行主监控逻辑
pub async fn run(cfg: Config, fw: Arc<Firewall>, executor: Arc<NftExecutor>) -> anyhow::Result<()> {
    let stats = Arc::new(DashMap::<IpAddr, TrafficStats>::new());
    let engine = Arc::new(RuleEngine::new(cfg.rules.clone(), stats.clone()));
    let (connection, handle, _messages) = new_connection()?;
    tokio::spawn(connection);

    let monitor = Arc::new(TrafficMonitor::new(
        handle,
        cfg.interface.clone(),
        stats,
        Duration::from_secs(cfg.monitor_interval.unwrap_or(1)),
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

    let fw_clone = Arc::clone(&fw);
    let engine_task = tokio::spawn(async move {
        engine_clone
            .start(
                fw_clone,
                Duration::from_secs(cfg.rule_check_interval.unwrap_or(1)),
            )
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

/*
// 如果你想要更高级的信号处理，可以使用这个版本
pub async fn run_with_advanced_signal_handling(
    cfg: Config,
    fw: Arc<Firewall>,
    executor: Arc<NftExecutor>
) -> anyhow::Result<()> {
    let stats = Arc::new(DashMap::<IpAddr, TrafficStats>::new());
    let mut engine = RuleEngine::new(cfg.rules.clone(), stats.clone());
    let (connection, handle, _messages) = new_connection()?;
    tokio::spawn(connection);

    let monitor = TrafficMonitor::new(
        handle,
        cfg.interface.clone(),
        stats,
        Duration::from_secs(cfg.monitor_interval.unwrap_or(1)),
        executor,
    );
    let daemon = TrafficDaemon::new(fw.clone());

    info!(
        "Traffic monitoring and rules engines have been started, monitoring interface: {}",
        cfg.interface
    );

    // 启动各个组件任务
    let monitor_task = tokio::spawn(monitor.start());
    let engine_task = tokio::spawn(engine.start(
        fw,
        Duration::from_secs(cfg.rule_check_interval.unwrap_or(1)),
    ));
    let daemon_task = tokio::spawn(daemon.start());

    // 更高级的信号处理，支持多种信号
    let signal_handler = tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};

            let mut sigint = signal(SignalKind::interrupt()).expect("Failed to register SIGINT handler");
            let mut sigterm = signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");

            tokio::select! {
                _ = sigint.recv() => {
                    info!("Received SIGINT (Ctrl+C), initiating graceful shutdown...");
                },
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, initiating graceful shutdown...");
                },
            }
        }

        #[cfg(not(unix))]
        {
            signal::ctrl_c().await.expect("Failed to listen for ctrl+c");
            info!("Received Ctrl+C signal, initiating graceful shutdown...");
        }
    });

    // 等待信号或任务完成
    tokio::select! {
        _ = signal_handler => {
            info!("Shutdown signal received, stopping all components...");

            // 优雅停止各个组件
            if let Err(e) = engine.stop() {
                error!("Failed to stop rule engine: {}", e);
            }

            // 等待所有任务完成，设置超时
            let shutdown_timeout = Duration::from_secs(30);

            match tokio::time::timeout(shutdown_timeout, async {
                let _ = monitor_task.await;
                let _ = engine_task.await;
                let _ = daemon_task.await;
            }).await {
                Ok(_) => info!("All components stopped gracefully"),
                Err(_) => {
                    warn!("Shutdown timeout reached, some components may not have stopped gracefully");
                }
            }
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
*/
// 如果你的其他组件（TrafficMonitor, TrafficDaemon）还没有 stop 方法，
// 你可能需要为它们添加类似的控制机制。以下是一个示例：

// 为 TrafficMonitor 添加停止功能的示例（如果需要的话）
/*
impl TrafficMonitor {
    pub fn stop(&self) -> Result<(), &'static str> {
        // 实现停止逻辑，类似于 RuleEngine
        // 例如发送停止信号到内部的控制通道
        Ok(())
    }
}
*/

// 为 TrafficDaemon 添加停止功能的示例（如果需要的话）
/*
impl TrafficDaemon {
    pub fn stop(&self) -> Result<(), &'static str> {
        // 实现停止逻辑
        Ok(())
    }
}
*/
