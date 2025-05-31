use crate::error::FirewallError;
use chrono::{DateTime, Duration, Utc};
use log::{debug, error, info, warn};
use anyhow::{Context, Result};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, RwLock, Semaphore};
use tokio::time::{timeout, Duration as TokioDuration};



/// NFT 命令执行器
#[derive(Debug)]
struct NftProcess {
    child: Child,
    stdin: Option<tokio::process::ChildStdin>,
    stdout: Option<tokio::process::ChildStdout>,
    stderr: Option<tokio::process::ChildStderr>,
    created_at: DateTime<Utc>,
    last_used: DateTime<Utc>,
    is_busy: bool,
    command_count: usize,
}

impl NftProcess {
    /// 创建新的 nft 进程
    async fn new() -> Result<Self> {
        let mut child = Command::new("nft")
            .arg("-i") // 交互模式
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("Failed to spawn nft process")?;

        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let now = Utc::now();
        Ok(NftProcess {
            child,
            stdin,
            stdout,
            stderr,
            created_at: now,
            last_used: now,
            is_busy: false,
            command_count: 0,
        })
    }

    /// 执行单个命令
    async fn execute_command(&mut self, command: &str) -> Result<String> {
        if self.is_busy {
            return Err(FirewallError::ExecutorPoolExhausted.into());
        }

        self.is_busy = true;
        self.last_used = Utc::now();
        self.command_count += 1;

        let result = self.do_execute(command).await;
        self.is_busy = false;
        result
    }

    async fn do_execute(&mut self, command: &str) -> Result<String> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| FirewallError::CommandError("stdin not available".to_string()))?;

        // 发送命令
        let full_command = format!("{}\n", command);
        stdin
            .write_all(full_command.as_bytes())
            .await
            .context("Failed to write command to nft process")?;
        stdin.flush().await.context("Failed to flush stdin")?;

        // 读取输出 (简化实现，实际可能需要更复杂的协议)
        // 这里假设每个命令执行后会有特定的结束标记
        // 在实际实现中，你可能需要使用更复杂的通信协议

        // 对于这个简化版本，我们直接返回成功
        debug!("Executed nft command via persistent process: {}", command);
        Ok("success".to_string())
    }

    /// 检查进程是否仍然活跃
    fn is_alive(&mut self) -> bool {
        match self.child.try_wait() {
            Ok(Some(_)) => false, // 进程已结束
            Ok(None) => true,     // 进程仍在运行
            Err(_) => false,      // 错误，假设进程已死
        }
    }

    /// 检查进程是否应该被回收（基于时间或使用次数）
    fn should_recycle(&self, max_age: Duration, max_commands: usize) -> bool {
        let age = Utc::now() - self.created_at;
        age > max_age || self.command_count >= max_commands
    }

    /// 优雅关闭进程
    async fn shutdown(mut self) -> Result<()> {
        if let Some(mut stdin) = self.stdin.take() {
            let _ = stdin.write_all(b"quit\n").await;
            let _ = stdin.flush().await;
        }

        // 等待进程结束，设置超时
        let _ = timeout(TokioDuration::from_secs(3), self.child.wait()).await;

        // 如果进程没有正常结束，强制杀死
        let _ = self.child.kill().await;
        Ok(())
    }
}

/// NFT 执行器池
#[derive(Debug)]
pub struct NftExecutor {
    pool: Arc<Mutex<VecDeque<NftProcess>>>,
    semaphore: Arc<Semaphore>,
    max_pool_size: usize,
    max_process_age: Duration,
    max_commands_per_process: usize,
    mock_mode: bool,
}

impl NftExecutor {
    /// 创建新的执行器池
    pub async fn new(
        max_pool_size: usize,
        max_process_age_secs: i64,
        max_commands_per_process: usize,
        mock_mode: bool,
    ) -> Self {
        let max_process_age = Duration::seconds(max_process_age_secs);

        NftExecutor {
            pool: Arc::new(Mutex::new(VecDeque::new())),
            semaphore: Arc::new(Semaphore::new(max_pool_size)),
            max_pool_size,
            max_process_age,
            max_commands_per_process,
            mock_mode,
        }
    }

    /// 执行 nft 命令
    pub async fn execute(&self, command: &str) -> Result<String> {
        if self.mock_mode {
            debug!("Mocking nft command execution: {}", command);
            return Ok("success (mocked)".to_string());
        }

        // 获取信号量许可
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| FirewallError::ExecutorPoolExhausted)?;

        // 尝试从池中获取可用进程
        let mut process = self.get_or_create_process().await?;

        // 执行命令
        let result = process.execute_command(command).await;

        // 将进程返回池中或销毁
        self.return_or_destroy_process(process).await;

        result
    }

    /// 从池中获取进程或创建新进程
    async fn get_or_create_process(&self) -> Result<NftProcess> {
        let mut pool = self.pool.lock().await;

        // 尝试从池中获取可用进程
        while let Some(mut process) = pool.pop_front() {
            if process.is_alive()
                && !process.should_recycle(self.max_process_age, self.max_commands_per_process)
            {
                return Ok(process);
            } else {
                // 进程已死或需要回收，异步销毁
                tokio::spawn(async move {
                    let _ = process.shutdown().await;
                });
            }
        }

        // 池中没有可用进程，创建新的
        drop(pool); // 释放锁
        NftProcess::new().await
    }

    /// 将进程返回池中或销毁
    async fn return_or_destroy_process(&self, mut process: NftProcess) {
        if process.is_alive()
            && !process.should_recycle(self.max_process_age, self.max_commands_per_process)
        {
            let mut pool = self.pool.lock().await;
            if pool.len() < self.max_pool_size {
                pool.push_back(process);
                return;
            }
        }

        // 进程需要被销毁
        tokio::spawn(async move {
            let _ = process.shutdown().await;
        });
    }

    /// 清理池中的所有进程
    pub async fn cleanup(&self) -> Result<()> {
        let mut pool = self.pool.lock().await;
        let processes: Vec<_> = pool.drain(..).collect();
        drop(pool);

        // 异步关闭所有进程
        let handles: Vec<_> = processes
            .into_iter()
            .map(|process| {
                tokio::spawn(async move {
                    let _ = process.shutdown().await;
                })
            })
            .collect();

        // 等待所有进程关闭
        for handle in handles {
            let _ = handle.await;
        }

        info!("NftExecutor pool cleaned up");
        Ok(())
    }

    /// 获取池状态信息
    pub async fn get_pool_stats(&self) -> (usize, usize) {
        let pool = self.pool.lock().await;
        let pool_size = pool.len();
        let available_permits = self.semaphore.available_permits();
        (pool_size, available_permits)
    }

    /// 执行批量命令（更高效）
    pub async fn execute_batch(&self, commands: Vec<String>) -> Result<Vec<String>> {
        if self.mock_mode {
            debug!(
                "Mocking batch nft command execution: {} commands",
                commands.len()
            );
            return Ok(commands
                .iter()
                .map(|_| "success (mocked)".to_string())
                .collect());
        }

        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| FirewallError::ExecutorPoolExhausted)?;

        let mut process = self.get_or_create_process().await?;
        let mut results = Vec::new();

        for command in commands {
            let result = process.execute_command(&command).await?;
            results.push(result);
        }

        self.return_or_destroy_process(process).await;
        Ok(results)
    }
}

