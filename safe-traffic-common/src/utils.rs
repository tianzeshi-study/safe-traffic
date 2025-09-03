use crate::config::Action;

use chrono::{DateTime, Utc};
use log::debug;
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};
use tokio::sync::{mpsc, Mutex, Notify};

/// 控制信号枚举
#[derive(Debug, Clone)]
pub enum ControlSignal {
    Pause,
    Resume,
    Stop,
}

/// 运行状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    Running,
    Paused,
    Stopped,
}

pub struct SignalController {
    // 控制信号
    pub control_tx: Arc<Mutex<Option<mpsc::UnboundedSender<ControlSignal>>>>,
    // 运行状态
    pub state: Arc<AtomicBool>, // true = running, false = paused
    // 停止信号
    pub stop_flag: Arc<AtomicBool>,
    // 暂停/恢复通知
    pub resume_notify: Arc<Notify>,
}
impl Default for SignalController {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalController {
    pub fn new() -> Self {
        Self {
            control_tx: Arc::new(Mutex::new(None)),
            state: Arc::new(AtomicBool::new(true)), // 默认运行状态
            stop_flag: Arc::new(AtomicBool::new(false)),
            resume_notify: Arc::new(Notify::new()),
        }
    }
    /// 获取当前运行状态
    pub async fn get_state(&self) -> RunState {
        if self.stop_flag.load(Ordering::Relaxed) {
            RunState::Stopped
        } else if self.state.load(Ordering::Relaxed) {
            RunState::Running
        } else {
            RunState::Paused
        }
    }

    /// 暂停执行
    pub async fn pause(&self) -> Result<(), &'static str> {
        if self.stop_flag.load(Ordering::Relaxed) {
            return Err("Engine is already stopped");
        }
        let guard = self.control_tx.lock().await;

        if let Some(tx) = (*guard).clone() {
            tx.send(ControlSignal::Pause)
                .map_err(|_| "Failed to send pause signal")?;
            debug!("RuleEngine pause signal sent");
        } else {
            return Err("Engine is not running");
        }
        Ok(())
    }

    /// 恢复执行
    pub async fn resume(&self) -> Result<(), &'static str> {
        if self.stop_flag.load(Ordering::Relaxed) {
            return Err("Engine is already stopped");
        }

        if let Some(tx) = (*self.control_tx.lock().await).clone() {
            tx.send(ControlSignal::Resume)
                .map_err(|_| "Failed to send resume signal")?;
            debug!("RuleEngine resume signal sent");
        } else {
            return Err("Engine is not running");
        }
        Ok(())
    }

    /// 优雅停止
    pub async fn stop(&self) -> Result<(), &'static str> {
        if let Some(tx) = (*self.control_tx.lock().await).clone() {
            tx.send(ControlSignal::Stop)
                .map_err(|_| "Failed to send stop signal")?;
            debug!("RuleEngine stop signal sent");
        } else {
            return Err("Engine is not running");
        }
        Ok(())
    }
}

/// 流量统计结构体
#[derive(Debug, Clone)]
pub struct TrafficStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_delta: u64,
    pub tx_delta: u64,
    pub last_updated: Instant,
    pub counter_handles: Option<(String, String)>,
}

impl Default for TrafficStats {
    fn default() -> Self {
        Self {
            rx_bytes: 0,
            tx_bytes: 0,
            rx_delta: 0,
            tx_delta: 0,
            last_updated: Instant::now(),
            counter_handles: None,
        }
    }
}

/// 防火墙规则信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: String,
    pub ip: IpAddr,
    pub rule_type: Action,
    pub created_at: DateTime<Utc>,
    pub handle: Vec<String>,
}
