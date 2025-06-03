use  serde::Deserialize;

/// NFT JSON 输出结构体
#[derive(Debug, Deserialize)]
struct NftJsonOutput {
    nftables: Vec<NftObject>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum NftObject {
    Chain(ChainObject),
    Rule(RuleObject),
    Add(AddObject),
    Other(serde_json::Value),
}

#[derive(Debug, Deserialize)]
struct ChainObject {
    chain: Chain,
}

#[derive(Debug, Deserialize)]
struct Chain {
    family: String,
    table: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct RuleObject {
    rule: Rule,
}

impl  RuleObject {
    async fn get_rule(&self) -> &Rule {
        &self
        .rule
    }
}


#[derive(Debug, Deserialize)]
struct Rule {
    family: String,
    table: String,
    chain: String,
    handle: Option<u64>,
    expr: Option<Vec<Expression>>,
}

impl  Rule {
    pub async fn get_handle(&self) -> Option<u64> {
        self.handle
    }
}

#[derive(Debug, Deserialize)]
pub struct AddObject {
    add: RuleObject,
}

impl  AddObject {
    pub async fn get_add(&self) -> &RuleObject {
        &self.add
    }
    pub async fn get_handle(&self) -> Option<u64> {
        self
        .get_add()
        .await
        .get_rule()
        .await
        .get_handle()
        .await
    }
}


#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Expression {
    Match(MatchExpr),
    Counter(CounterExpr),
    Accept(AcceptExpr),
    Other(serde_json::Value),
}

#[derive(Debug, Deserialize)]
struct MatchExpr {
    r#match: Match,
}

#[derive(Debug, Deserialize)]
struct Match {
    op: String,
    left: serde_json::Value,
    right: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct CounterExpr {
    counter: Counter,
}

#[derive(Debug, Deserialize)]
struct Counter {
    packets: u64,
    bytes: u64,
}

#[derive(Debug, Deserialize)]
struct AcceptExpr {
    accept: Option<serde_json::Value>,
}



pub async fn parse_output(json_output: &str) -> anyhow::Result<Vec<NftObject>> {
        let nft_data: NftJsonOutput = serde_json::from_str(json_output)
            .map_err(|e| anyhow::anyhow!("parser error  : {}, \n fail to parse {}", e, json_output))?;

    Ok(nft_data.nftables)
}
    

/*
async fn parse_nft_json_output(
        json_output: &str,
        ip_stats: &mut HashMap<IpAddr, IpTrafficStats>,
        direction: &str,
    ) -> anyhow::Result<()> {
        let nft_data: NftJsonOutput = serde_json::from_str(json_output)
            .map_err(|e| anyhow::anyhow!("解析 NFT JSON 失败: {}", e))?;

        for obj in nft_data.nftables {
            if let NftObject::Rule(rule_obj) = obj {
                if let Some(expr_list) = &rule_obj.rule.expr {
                    // 查找匹配的IP地址和对应的计数器
                    let mut ip_addr: Option<IpAddr> = None;
                    let mut counter_info: Option<(u64, u64)> = None;

                    for expr in expr_list {
                        match expr {
                            Expression::Match(match_expr) => {
                                ip_addr = self.extract_ip_from_match(match_expr, direction);
                            }
                            Expression::Counter(counter_expr) => {
                                counter_info = Some((
                                    counter_expr.counter.packets,
                                    counter_expr.counter.bytes,
                                ));
                            }
                            _ => {}
                        }
                    }

                    // 如果找到了IP和计数器信息，更新统计
                    if let (Some(ip), Some((packets, bytes))) = (ip_addr, counter_info) {
                        let entry = ip_stats.entry(ip).or_insert_with(|| IpTrafficStats {
                            ip,
                            rx_bytes: 0,
                            tx_bytes: 0,
                            rx_packets: 0,
                            tx_packets: 0,
                            last_updated: Instant::now(),
                        });

                        if direction == "input" {
                            entry.rx_bytes += bytes;
                            entry.rx_packets += packets;
                        } else {
                            entry.tx_bytes += bytes;
                            entry.tx_packets += packets;
                        }
                    }
                }
            }
        }

        Ok(())
    }
    */