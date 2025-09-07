mod controller; // nftables 控制
mod daemon;
mod error;
mod monitor; // 流量监控
mod nft;
mod rules; // 规则引擎 // 日志记录
mod tasks;

use safe_traffic_common::config;

use anyhow::{Context, Result};
use clap::Parser;
use config::Config;
use env_logger::Env;
use log::info;
use std::sync::Arc;

#[derive(Parser)]
#[command(author, version, about = "Safe Server Traffic 自动限流与封禁工具")]
struct Args {
    /// 配置文件路径
    #[arg(short, long, default_value = "/etc/safe-server-traffic/default.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // 初始化日志（可通过环境变量 RUST_LOG 调节级别）
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    // 解析命令行参数
    let args = Args::parse();
    info!("Loading configuration file: {}", &args.config);
    // 读取并验证配置
    let cfg = Config::from_file(&args.config)?;
    let nft_available = crate::nft::check_nftables_available().await?;

    // 删除已存在的nft-stderr.log
    let mut temp_path: std::path::PathBuf = std::env::temp_dir();
    temp_path.push("nft-stderr.log");
    if tokio::fs::metadata(&temp_path).await.is_ok() {
        let mut backup_path = temp_path.clone();
        backup_path.set_file_name("nft-stderr-old.log");
        tokio::fs::rename(&temp_path, &backup_path)
            .await
            .with_context(|| format!("Failed to rename {:?} to {:?}", temp_path, backup_path))?;
    }

    // 创建执行器池
    let max_pool_size = cfg.executor_pool_size.unwrap_or(5);
    let max_process_age = cfg.executor_max_age_secs.unwrap_or(300);
    let max_commands_per_process = cfg.executor_max_commands.unwrap_or(100);

    let executor = Arc::new(
        nft::NftExecutor::new(
            max_pool_size,
            max_process_age,
            max_commands_per_process,
            !nft_available,
        )
        .await,
    );

    // 启动防火墙控制器
    let fw = Arc::new(controller::Firewall::new(&cfg, Arc::clone(&executor)).await?);
    // 启动流量监控与规则引擎
    tasks::run(cfg, fw.clone(), executor.clone()).await?;

    fw.cleanup().await?;

    executor.input("delete table inet traffic_monitor").await?;
    // tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    executor.cleanup().await?;
    drop(executor);

    Ok(())
}
