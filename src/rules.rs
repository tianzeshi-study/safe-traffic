use crate::{
    config::{HookType, Rule},
    controller::Firewall,
};

use futures::stream::{self, StreamExt, TryStreamExt, TryStream};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use log::{info,debug};
use std::{net::IpAddr, sync::Arc, time::Instant};

const MAX_WINDOW_BUFFER: usize = 10;

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
#[derive(Clone, Debug)]
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
    handles: DashMap<IpAddr, Vec<String>>,
    windows: DashMap<IpAddr, Window>,
}

impl RuleEngine {
    /// 新建实例
    pub fn new(rules: Vec<Rule>, stats: Arc<DashMap<IpAddr, TrafficStats>>) -> Self {
        RuleEngine {
            rules,
            stats,

            handles: DashMap::new(),
            windows: DashMap::new(),
        }
    }

    /// 检查所有 IP 并在必要时调用防火墙控制
    pub async fn check_and_apply(&self, fw_origin: Arc<Firewall>) -> anyhow::Result<()> {
        let now = Utc::now();
        // 遍历每个 IP 的最新流量
        // for entry in self.stats.iter() {
        let entries: Vec<_> = self.stats.iter()
    .map(|entry| {
    let bps = match fw_origin.hook {
                HookType::Input => entry.value().rx_bytes,
                HookType::Output => entry.value().tx_bytes,
            };
            // 获取或创建滑动窗口
            let mut win = self.windows.entry(*entry.key()).or_insert_with(|| Window {
                buffer: vec![0; MAX_WINDOW_BUFFER], // 最多支持 60 秒窗口

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
            let v = win.value().clone();
    (*entry.key(), v)
    })
    .collect();
    debug!("starting checking rule: stats entries count: {}", entries.len()); 

// 异步并发处理
stream::iter(entries)
.map(|entry| Ok::<_, anyhow::Error>(entry))
    .try_for_each_concurrent(10, |(ip, win)| {
        let fw = Arc::clone(&fw_origin);
    async move {
            // let ip = *entry.key();

            
            
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
                    dbg!(&ip, &avg_bps);
                if avg_bps > rule.threshold_bps {
                    match rule.action {
                        crate::config::Action::RateLimit { kbps, burst } => {
                            debug!("intend to limit the speed of {} to {}kbps", ip, kbps);
                            fw
                            .clone()
                            .limit(ip, kbps, burst).await?;
                        }
                        crate::config::Action::Ban { seconds } => {
                            debug!("intend to ban  {} for {} seconds", ip, seconds);

                            let rule_id = fw.ban(ip, seconds).await?;
                            self.handles
                                .entry(ip)
                                .and_modify(|vec| vec.push(rule_id.clone()))
                                .or_insert_with(|| vec![rule_id]);
                        }
                    }
                }

                self.clean_expiration_rules(rule, ip, Arc::clone(&fw)).await?;
            }
            Ok(())
    }
        })
        .await
        
    }

    // clean expiration rules
    async fn clean_expiration_rules(
        &self,
        rule: &Rule,
        ip: IpAddr,
        fw: Arc<Firewall>,
    ) -> anyhow::Result<()> {
        if let Some(ids) = self.handles.get(&ip) {
            for id in ids.clone() {
                match rule.action {
                    crate::config::Action::RateLimit { kbps, burst } => {
                        let _ = kbps;
                        let _ = burst;
                        continue;
                        // debug!("intend to unlimit the speed of {} to {}kbps", ip, kbps);
                        // fw.limit(ip, kbps, burst).await?;
                    }
                    crate::config::Action::Ban { seconds } => {
                        if fw.is_expiration(&id, seconds).await {
                            debug!("intend to unban  {} because of expiration ", ip);
                            fw.unban(&id).await?;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
