use thiserror::Error;

#[derive(Error, Debug)]
pub enum FirewallError {
    #[error("Command execution failed: {0}")]
    CommandError(String),
    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),
    #[error("Rule not found: {0}")]
    RuleNotFound(String),
    #[error("NFTables not available")]
    NftablesNotAvailable,
    #[error("Permission denied - root privileges required")]
    PermissionDenied,
    #[error("Executor pool exhausted")]
    ExecutorPoolExhausted,
    #[error("Command timeout")]
    CommandTimeout,
}

