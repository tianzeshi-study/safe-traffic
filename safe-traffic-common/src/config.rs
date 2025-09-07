use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fmt, fs,
    hash::{Hash, Hasher},
    net::IpAddr,
    path::Path,
};

/// hook type , input or output
#[derive(Deserialize, Debug, Clone)]
pub enum HookType {
    Input,
    Output,
}

/// family type , ipV4 ,  ipV6  or both(inet)
#[derive(Deserialize, Debug, Clone)]
pub enum FamilyType {
    Ip4,
    Ip6,
    Inet,
}

#[derive(Deserialize, Debug, Clone)]
pub enum PolicyType {
    Accept,
    Drop,
    Reject,
    Continue,
    Log,
    Count,
}

impl fmt::Display for PolicyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // match 出对应的 nft 关键字
        let s: &str = match self {
            PolicyType::Accept => "accept",
            PolicyType::Drop => "drop",
            PolicyType::Reject => "reject",
            PolicyType::Continue => "continue",
            PolicyType::Log => "log",
            PolicyType::Count => "count",
        };
        write!(f, "{}", s)
    }
}

impl fmt::Display for HookType {
    /// fmt 方法中返回 fmt::Result，
    /// 方便链式调用 write! 等宏
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 先 match 出对应的字符串 slice
        let s: &str = match self {
            HookType::Input => "input",
            HookType::Output => "output",
        };
        // 将字符串写入 f
        write!(f, "{}", s)
    }
}

impl fmt::Display for FamilyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: &str = match self {
            FamilyType::Ip4 => "ip4",
            FamilyType::Ip6 => "ip6",
            FamilyType::Inet => "inet",
        };
        write!(f, "{}", s)
    }
}

/// 单条规则动作类型：限速或封禁
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum Action {
    /// 限速模式，参数：kbit/s
    RateLimit {
        kbps: u64,
        burst: Option<u64>,
        seconds: Option<u64>,
    },
    /// 封禁模式，参数：秒
    Ban { seconds: Option<u64> },
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Action::Ban { seconds } => {
                if let Some(seconds) = seconds {
                    format!("ban {}s", seconds)
                } else {
                    "ban infinity".to_string()
                }
            }
            Action::RateLimit {
                kbps,
                burst,
                seconds,
            } => {
                let seconds: String = if let Some(seconds) = seconds {
                    format!("for {} s", seconds)
                } else {
                    "infinity".to_string()
                };
                if let Some(burst) = burst {
                    format!(
                        "RateLimit {} kbytes/second burst {} kbytes {}",
                        kbps, burst, seconds
                    )
                } else {
                    format!("RateLimit {}kbps  {}", kbps, seconds)
                }
            }
        };
        write!(f, "{}", s)
    }
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
    pub excluded_ips: Option<HashSet<IpAddr>>,
}

impl Default for Rule {
    fn default() -> Self {
        Rule {
            window_secs: 10,
            threshold_bps: u64::MAX,
            action: Action::Ban { seconds: None },
            excluded_ips: None,
        }
    }
}

impl PartialEq for Rule {
    fn eq(&self, other: &Self) -> bool {
        self.window_secs == other.window_secs
            && self.threshold_bps == other.threshold_bps
            && self.action == other.action
    }
}

impl Eq for Rule {}

// 手动实现 Hash（忽略 excluded_ips）
impl Hash for Rule {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.window_secs.hash(state);
        self.threshold_bps.hash(state);
        self.action.hash(state);
    }
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
    pub policy: Option<PolicyType>,
    /// 主网卡名称
    pub interface: String,

    pub check_interval: Option<u64>,
    pub executor_pool_size: Option<usize>,    // 默认 5
    pub executor_max_age_secs: Option<i64>,   // 默认 300 秒
    pub executor_max_commands: Option<usize>, // 默认 100 条命令
    /// 规则列表
    pub rules: HashSet<Rule>,
    pub global_exclude: Option<HashSet<IpAddr>>,
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
    use std::net::Ipv4Addr;

    #[test]
    fn test_enum_display() {
        assert_eq!(format!("{}", HookType::Input), "input");
        assert_eq!(format!("{}", FamilyType::Ip4), "ip4");
        assert_eq!(format!("{}", PolicyType::Accept), "accept");
    }

    #[test]
    fn test_action_display() {
        let ban = Action::Ban { seconds: Some(60) };
        assert_eq!(format!("{}", ban), "ban 60s");

        let rate_limit = Action::RateLimit {
            kbps: 100,
            burst: None,
            seconds: Some(30),
        };
        assert_eq!(format!("{}", rate_limit), "RateLimit 100kbps  for 30 s");
    }

    #[test]
    fn test_rule_default() {
        let rule = Rule::default();
        assert_eq!(rule.window_secs, 10);
        assert_eq!(rule.threshold_bps, u64::MAX);
        assert_eq!(rule.action, Action::Ban { seconds: None });
    }

    #[test]
    fn test_rule_equality() {
        let rule1 = Rule {
            window_secs: 10,
            threshold_bps: 1000,
            action: Action::Ban { seconds: Some(60) },
            excluded_ips: None,
        };
        let rule2 = Rule {
            window_secs: 10,
            threshold_bps: 1000,
            action: Action::Ban { seconds: Some(60) },
            excluded_ips: Some(HashSet::new()),
        };
        assert_eq!(rule1, rule2); // excluded_ips 被忽略
    }

    #[test]
    fn test_rule_is_excluded() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let mut excluded_set = HashSet::new();
        excluded_set.insert(ip);

        let rule = Rule {
            excluded_ips: Some(excluded_set),
            ..Rule::default()
        };

        assert!(rule.is_excluded(&ip));
        assert!(!rule.is_excluded(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));

        let rule_no_exclude = Rule::default();
        assert!(!rule_no_exclude.is_excluded(&ip));
    }

    #[test]
    fn test_config_from_invalid_file() {
        let result = Config::from_file("nonexistent.toml");
        assert!(result.is_err());
    }
}
