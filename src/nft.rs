use crate::error::FirewallError;
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use log::{debug, error, info, warn};
use std::{collections::VecDeque, fs::OpenOptions, process::Stdio, sync::Arc};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{timeout, Duration as TokioDuration};

#[derive(Debug)]
struct NftProcess {
    child: Child,
    stdin: Option<tokio::process::ChildStdin>,
    stdout_reader: Option<BufReader<tokio::process::ChildStdout>>,
    stderr_reader: Option<BufReader<tokio::process::ChildStderr>>,
    created_at: DateTime<Utc>,
    last_used: DateTime<Utc>,
    is_busy: bool,
    command_count: usize,
}

#[derive(Debug, thiserror::Error)]
enum NftError {
    #[error("Process not available: {0}")]
    ProcessNotAvailable(String),
    #[error("Command execution failed: {0}")]
    CommandFailed(String),
    #[error("Process communication error: {0}")]
    CommunicationError(String),
    #[error("Timeout waiting for command response")]
    Timeout,
}

impl NftProcess {
    /// 创建新的 nft 进程
    async fn new() -> Result<Self> {
        let err_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("nft-stderr.log")
            .context("open log file fail")?;

        let mut child = Command::new("nft")
            .args(["-a", "-e", "-i", "-j"]) // 交互模式
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // .stderr(Stdio::piped())
            .stderr(Stdio::from(err_file))
            .kill_on_drop(true)
            .spawn()
            .context("Failed to spawn nft process")?;

        let stdin = child.stdin.take();
        let stdout = child.stdout.take().map(BufReader::new);
        let stderr = child.stderr.take().map(BufReader::new);

        let now = Utc::now();
        let mut process = NftProcess {
            child,
            stdin,
            stdout_reader: stdout,
            stderr_reader: stderr,
            created_at: now,
            last_used: now,
            is_busy: false,
            command_count: 0,
        };

        // 等待 nft 进程初始化完成
        process.wait_for_ready().await?;

        Ok(process)
    }

    /// 等待 nft 进程准备就绪
    async fn wait_for_ready(&mut self) -> Result<()> {
        // 发送一个简单的命令来测试进程是否准备就绪
        let test_result = timeout(
            TokioDuration::from_secs(10),
            self.do_execute_internal("list tables"),
        )
        .await;

        match test_result {
            Ok(Ok(_)) => {
                debug!("NFT process is ready");
                Ok(())
            }
            Ok(Err(e)) => {
                error!("NFT process initialization failed: {}", e);
                Err(e)
            }
            Err(e) => {
                error!("NFT process initialization timeout: {}", e);
                Err(NftError::Timeout.into())
            }
        }
    }

    /// 执行单个命令
    async fn execute_command(&mut self, command: &str) -> Result<String> {
        if self.is_busy {
            return Err(NftError::ProcessNotAvailable("Process is busy".to_string()).into());
        }

        if !self.is_alive() {
            return Err(NftError::ProcessNotAvailable("Process is not alive".to_string()).into());
        }

        self.is_busy = true;
        self.last_used = Utc::now();
        self.command_count += 1;

        // 设置命令执行超时
        let result = timeout(
            TokioDuration::from_secs(10),
            self.do_execute_internal(command),
        )
        .await;

        self.is_busy = false;

        match result {
            Ok(Ok(output)) => {
                debug!("Successfully executed nft command: {}", command);
                Ok(output)
            }
            Ok(Err(e)) => {
                error!("NFT command failed: {} - Error: {}", command, e);
                Err(e)
            }
            Err(_) => {
                error!("NFT command timeout: {}", command);
                Err(NftError::Timeout.into())
            }
        }
    }

    /// 内部执行命令的实现
    async fn do_execute_internal(&mut self, command: &str) -> Result<String> {
        // let stdin = self.stdin.as_mut()
        // .ok_or_else(|| NftError::ProcessNotAvailable("stdin not available".to_string()))?;
        // let stdout_reader = self.stdout_reader.as_mut()
        // .ok_or_else(|| NftError::ProcessNotAvailable("stdout not available".to_string()))?;

        // let stderr_reader = self.stderr_reader.as_mut()
        // .ok_or_else(|| NftError::ProcessNotAvailable("stderr not available".to_string()))?;
        let full_command = format!("{}\n", command);

        // 发送命令
        let _b = self
            .stdin
            .as_mut()
            .ok_or_else(|| NftError::ProcessNotAvailable("stdin not available".to_string()))?
            .write(full_command.as_bytes())
            .await
            .context("Failed to write command to nft process")?;

        self.stdin
            .as_mut()
            .ok_or_else(|| NftError::ProcessNotAvailable("stdin not available".to_string()))?
            .flush()
            .await
            .context("Failed to flush stdin")?;

        let mut out_content = String::new();
        let _r = self
            .stdout_reader
            .as_mut()
            .ok_or_else(|| NftError::ProcessNotAvailable("stdout not available".to_string()))?
            .read_line(&mut out_content)
            .await
            .context("Failed to read line")?;

        Ok(out_content)
    }

    pub async fn do_input(&mut self, command: &str) -> Result<()> {
        let full_command = format!("{}\n", command);

        // 发送命令
        let _b = self
            .stdin
            .as_mut()
            .ok_or_else(|| NftError::ProcessNotAvailable("stdin not available".to_string()))?
            .write(full_command.as_bytes())
            .await
            .context("Failed to write command to nft process")?;

        self.stdin
            .as_mut()
            .ok_or_else(|| NftError::ProcessNotAvailable("stdin not available".to_string()))?
            .flush()
            .await
            .context("Failed to flush stdin")?;

        Ok(())
    }

    /// 执行批量命令
    async fn execute_batch(&mut self, commands: &[&str]) -> Result<Vec<String>> {
        let mut results = Vec::with_capacity(commands.len());

        for (i, command) in commands.iter().enumerate() {
            match self.execute_command(command).await {
                Ok(output) => results.push(output),
                Err(e) => {
                    error!("Batch command {} failed: {} - Error: {}", i, command, e);
                    return Err(e);
                }
            }
        }

        Ok(results)
    }

    /// 检查进程是否仍然活跃
    fn is_alive(&mut self) -> bool {
        match self.child.try_wait() {
            Ok(Some(status)) => {
                warn!("NFT process exited with status: {:?}", status);
                false
            }
            Ok(None) => true, // 进程仍在运行
            Err(e) => {
                error!("Error checking process status: {}", e);
                false
            }
        }
    }

    /// 检查进程是否应该被回收
    fn should_recycle(&self, max_age: Duration, max_commands: usize) -> bool {
        let age = Utc::now() - self.created_at;
        // let should_recycle = age > chrono::Duration::from_std(max_age).unwrap_or_default()
        let should_recycle = age > max_age || self.command_count >= max_commands;

        if should_recycle {
            debug!(
                "Process should be recycled: age={:?}, commands={}",
                age, self.command_count
            );
        }

        should_recycle
    }

    /// 获取进程统计信息
    fn get_stats(&self) -> ProcessStats {
        ProcessStats {
            created_at: self.created_at,
            last_used: self.last_used,
            command_count: self.command_count,
            age: Utc::now() - self.created_at,
            is_busy: self.is_busy,
        }
    }

    /// 优雅关闭进程

    async fn shutdown(mut self) -> Result<()> {
        debug!(
            "Shutting down NFT process (commands executed: {})",
            self.command_count
        );

        // 尝试发送退出命令
        self.do_input("quit").await.context("fail to write quit")?;

        // self.do_input("quit")
        // .await
        // .context("fail to write quit")?;

        // let timer = tokio::time::Instant::now();
        // let result = self.child.wait().await.unwrap();
        // let duration = timer.elapsed();

        // 等待进程结束，设置超时
        let wait_result = timeout(TokioDuration::from_secs(5), self.child.wait()).await;

        match wait_result {
            Ok(Ok(status)) => {
                debug!("NFT process exited gracefully with status: {:?}", status);
            }
            Ok(Err(e)) => {
                warn!("Error waiting for NFT process: {}", e);
            }
            Err(e) => {
                debug!("NFT process shutdown timeout, forcing kill, detail: {}", e);
                self.child.kill().await?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
struct ProcessStats {
    created_at: DateTime<Utc>,
    last_used: DateTime<Utc>,
    command_count: usize,
    age: chrono::Duration,
    is_busy: bool,
}

// NFT 执行器池
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
    /// execute command without output  
    pub async fn input(&self, command: &str) -> Result<()> {
        if self.mock_mode {
            debug!("Mocking nft command execution: {}", command);
            return Ok(());
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
        let result = process.do_input(command).await;

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

pub async fn check_nftables_available() -> Result<bool> {
    match Command::new("nft")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
    {
        Ok(status) => {
            if status.success() {
                // 检查是否有权限
                match Command::new("nft")
                    .args(&["list", "tables"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .await
                {
                    Ok(status) => Ok(status.success()),
                    Err(_) => Ok(false),
                }
            } else {
                Ok(false)
            }
        }
        Err(_) => Ok(false),
    }
}
