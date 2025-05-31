mod config; // 配置解析
mod controller; // nftables 控制
mod logger;
mod monitor; // 流量监控
mod rules; // 规则引擎 // 日志记录
mod nft;
mod error;

use clap::Parser;
use config::Config;
use env_logger::Env;
use log::info;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::RwLock;

#[derive(Parser)]
#[command(author, version, about = "Safe Server Traffic 自动限流与封禁工具")]
struct Args {
    /// 配置文件路径
    #[arg(short, long, default_value = "/etc/safe-server-traffic/default.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 初始化日志（可通过环境变量 RUST_LOG 调节级别）
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    // 解析命令行参数
    let args = Args::parse();
    info!("Loading configuration file: {}", &args.config);
    // 读取并验证配置
    let cfg = Config::from_file(&args.config)?;
    // 启动防火墙控制器
    let fw = Arc::new(RwLock::new(controller::Firewall::new(&cfg).await?));
    // 启动流量监控与规则引擎
    monitor::run(cfg, &fw).await?;
    // 等待终止信号（Ctrl+C）
    signal::ctrl_c().await?;
    info!("收到退出信号，正在清理...");
    fw.write().await.cleanup().await?;
    Ok(())
}
