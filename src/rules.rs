use crate::{config::Rule, controller::Firewall};

use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use log::{info, debug};
use std::{net::IpAddr, sync::Arc, time::Instant};

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



/// 单 IP 的滑动窗口记录
struct Window {
    /// 最近 bytes 的循环缓冲
    buffer: Vec<u64>,
    /// 缓冲当前填充位置
    pos: usize,
    /// 上次更新时间
    last_ts: DateTime<Utc>,
}

/// 规则引擎管理所有 IP 的窗口并执行动作
pub struct RuleEngine {
    rules: Vec<Rule>,
    stats: Arc<DashMap<IpAddr, TrafficStats>>,
    windows: DashMap<IpAddr, Window>,
}

impl RuleEngine {
    /// 新建实例
    pub fn new(rules: Vec<Rule>, stats: Arc<DashMap<IpAddr, TrafficStats>>) -> Self {
        RuleEngine {
            rules,
            stats,
            windows: DashMap::new(),
        }
    }

    /// 检查所有 IP 并在必要时调用防火墙控制
    pub async fn check_and_apply(&self, fw: &mut Firewall) -> anyhow::Result<()> {
        let now = Utc::now();
        // 遍历每个 IP 的最新流量
        for entry in self.stats.iter() {
            let ip = *entry.key();
            
                        
            // let bps = entry.value().tx_bytes;
            let bps = entry.value().rx_bytes;
            // 获取或创建滑动窗口
            let mut win = self.windows.entry(ip).or_insert_with(|| Window {
                buffer: vec![0; 60], // 最多支持 60 秒窗口
                pos: 0,
                last_ts: now,
            });
            // 如果超过 1 秒，推进循环缓冲
            if (now - win.last_ts).num_seconds() >= 1 {
                win.pos = (win.pos + 1) % win.buffer.len();
                let pause = win.pos.clone();
                win.buffer[pause] = bps;
                win.last_ts = now;
            }
            // 对每条规则进行检测
            for rule in &self.rules {
                if rule.is_excluded(&ip) {
                debug!("skipping excluded  IP: {}", ip);
                continue;
            }

                let window_size = rule.window_secs as usize;
                // 计算滑动窗口内总流量
                let sum: u64 = win
                    .buffer
                    .iter()
                    .cycle()
                    .skip((win.pos + win.buffer.len() - window_size) % win.buffer.len())
                    .take(window_size)
                    .sum();
                let avg_bps = sum / rule.window_secs;
                // 超过阈值 => 执行动作
                if avg_bps > rule.threshold_bps {
                    match rule.action {
                        crate::config::Action::RateLimit { kbps, burst } => {
                            info!("Limited the speed of {} to {}kbps", ip, kbps);
                            fw.limit(ip, kbps).await?;
                        }
                        crate::config::Action::Ban { seconds } => {
                            info!("Ban  {} for {} seconds", ip, seconds);
                            // let duration = Duration::seconds(seconds as i64);
                            fw.ban(ip, seconds).await?;
                            // fw.ban(ip, duration).await?;
                            // fw.ban(ip).await?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

