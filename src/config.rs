use serde::Deserialize;
use std::{collections::HashSet, fs, net::IpAddr, path::Path, fmt};

/// hook type , input or output 
#[derive(Deserialize, Debug, Clone)]
pub enum  HookType {
    Input,
    Output,
}

/// family type , ipV4 ,  ipV6  or both(inet)
#[derive(Deserialize, Debug, Clone)]
pub enum  FamilyType {
    Ip4,
    Ip6,
    Inet
}


impl fmt::Display for HookType {
    /// fmt 方法中返回 fmt::Result，
/// 方便链式调用 write! 等宏
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 先 match 出对应的字符串 slice
        let s: &str = match self {
            HookType::Input  => "input",
            HookType::Output => "output",
        };
        // 将字符串写入 f
        write!(f, "{}", s)
    }
}

impl fmt::Display for FamilyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: &str = match self {
            FamilyType::Ip4  => "ip4",
            FamilyType::Ip6  => "ip6",
            FamilyType::Inet => "inet",
        };
        write!(f, "{}", s)
    }
}



/// 单条规则动作类型：限速或封禁
#[derive(Deserialize, Debug, Clone)]
pub enum Action {
    /// 限速模式，参数：kbit/s
    RateLimit { kbps: u64, burst: Option<u64> },
    /// 封禁模式，参数：秒
    Ban { seconds: u64 },
}

/// 单条流量规则
#[derive(Deserialize, Debug, Clone)]
pub struct Rule {
    /// 滑动窗口时长，秒
    pub window_secs: u64,
    /// 阈值，字节/秒
    pub threshold_bps: u64,
    /// 触发动作
    pub action: Action,
    excluded_ips: Option<HashSet<IpAddr>>,
}

impl Rule {
    pub fn is_excluded(&self, ip: &IpAddr) -> bool {
        if let Some(excluded_ips) = &self.excluded_ips {
            excluded_ips.contains(ip)
        } else {
            false
        }
    }
}

/// 全局配置
#[derive(Deserialize, Debug)]
pub struct Config {
    pub family: Option<FamilyType>,
    pub table_name: Option<String>,
    pub chain_name: Option<String>,
    pub hook: Option<HookType>,
    pub priority: Option<i64>,
    /// 主网卡名称
    pub interface: String,
    /// 规则列表
    pub rules: Vec<Rule>,
    /// 日志保留路径
    pub log_path: Option<String>,
    pub monitor_interval: Option<u64>, // 监控间隔（秒）
    pub rule_check_interval: Option<u64>,
    pub executor_pool_size: Option<usize>,    // 默认 5
    pub executor_max_age_secs: Option<i64>,   // 默认 300 秒
    pub executor_max_commands: Option<usize>, // 默认 100 条命令
}


impl Config {
    /// 从文件加载配置
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        // 读取 TOML 文本
        let text = fs::read_to_string(path)?;
        // 解析为 Config 结构
        let cfg: Config = toml::from_str(&text)?;

        Ok(cfg)
    }
}




#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::{fs, io::Write};
    use tempfile::NamedTempFile;
    use toml;

    #[test]
    fn test_action_rate_limit_deserialize() {
        let s = r#"{ RateLimit = { kbps = 200 } }"#;
        // Wrap in a table to match Action::RateLimit structure
        let action: Action = toml::from_str(&s).unwrap();
        match action {
            Action::RateLimit { kbps } => assert_eq!(kbps, 200),
            _ => panic!("Expected RateLimit variant"),
        }
    }

    #[test]
    fn test_action_ban_deserialize() {
        // 必须一行，Ban = { … }，不能有前导换行
        let s = r#"{ Ban = { seconds = 456 } }"#;
        let action: Action = toml::from_str(s).unwrap();
        match action {
            Action::Ban { seconds } => assert_eq!(seconds, 456),
            _ => panic!("Expected Ban variant"),
        }
    }

    #[test]
    fn test_rule_deserialize() {
        let toml_str = r#"
            window_secs = 30
            threshold_bps = 1000
            action = { RateLimit = { kbps = 200 } }
        "#;
        let rule: Rule = toml::from_str(toml_str).unwrap();
        assert_eq!(rule.window_secs, 30);
        assert_eq!(rule.threshold_bps, 1000);
        match rule.action {
            Action::RateLimit { kbps } => assert_eq!(kbps, 200),
            _ => panic!("Expected RateLimit action"),
        }
    }

    #[test]
    fn test_config_from_str_and_file() {
        // Prepare a minimal TOML config
        let toml_content = r#"
            table_name = "tbl"
            chain_name = "chain"
            family = "ipv4"
            interface = "eth0"
            log_path = "/var/log/app.log"

            [[rules]]
            window_secs = 10
            threshold_bps = 500
            action = { Ban = { seconds = 60 } }

            [[rules]]
            window_secs = 20
            threshold_bps = 1500
            action = { RateLimit = { kbps = 300 } }
        "#;

        // Test toml::from_str directly
        let cfg: Config = toml::from_str(toml_content).unwrap();
        assert_eq!(cfg.table_name.as_deref(), Some("tbl"));
        assert_eq!(cfg.chain_name.as_deref(), Some("chain"));
        assert_eq!(cfg.family.as_deref(), Some("ipv4"));
        assert_eq!(cfg.interface, "eth0");
        assert_eq!(cfg.log_path, "/var/log/app.log");
        assert_eq!(cfg.rules.len(), 2);
        // First rule check
        let r0 = &cfg.rules[0];
        assert_eq!(r0.window_secs, 10);
        assert_eq!(r0.threshold_bps, 500);
        match r0.action {
            Action::Ban { seconds } => assert_eq!(seconds, 60),
            _ => panic!("Expected Ban action"),
        }
        // Second rule check
        let r1 = &cfg.rules[1];
        assert_eq!(r1.window_secs, 20);
        assert_eq!(r1.threshold_bps, 1500);
        match r1.action {
            Action::RateLimit { kbps } => assert_eq!(kbps, 300),
            _ => panic!("Expected RateLimit action"),
        }

        // Now test Config::from_file
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(tmpfile, "{}", toml_content).unwrap();
        let path = tmpfile.path();
        let cfg2 = Config::from_file(path).unwrap();
        assert_eq!(cfg2.interface, "eth0");
        assert_eq!(cfg2.rules.len(), 2);
    }

    #[test]
    fn test_from_file_error_nonexistent() {
        let result = Config::from_file("nonexistent.toml");
        assert!(result.is_err());
    }
}
