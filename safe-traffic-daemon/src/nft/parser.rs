use serde::Deserialize;

/// NFT JSON 输出结构体
#[derive(Debug, Deserialize)]
pub struct NftJsonOutput {
    pub nftables: Vec<NftObject>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum NftObject {
    #[allow(dead_code)]
    Chain(ChainObject),
    Rule(RuleObject),
    Add(AddObject),
    Other(serde_json::Value),
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ChainObject {
    chain: Chain,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct Chain {
    family: String,
    table: String,
    name: String,
}

#[derive(Debug, Deserialize)]
pub struct RuleObject {
    pub rule: Rule,
}

impl RuleObject {
    async fn get_rule(&self) -> &Rule {
        &self.rule
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct Rule {
    family: String,
    table: String,
    chain: String,
    handle: Option<u64>,
    pub expr: Option<Vec<Expression>>,
}

impl Rule {
    pub async fn get_handle(&self) -> Option<u64> {
        self.handle
    }
}

#[derive(Debug, Deserialize)]
pub struct AddObject {
    add: RuleObject,
}

impl AddObject {
    pub async fn get_add(&self) -> &RuleObject {
        &self.add
    }
    pub async fn get_handle(&self) -> Option<u64> {
        self.get_add().await.get_rule().await.get_handle().await
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Expression {
    Match(MatchExpr),
    Counter(CounterExpr),
    #[allow(dead_code)]
    Accept(AcceptExpr),
    #[allow(dead_code)]
    Other(serde_json::Value),
}

#[derive(Debug, Deserialize)]
pub struct MatchExpr {
    pub r#match: Match,
}

#[derive(Debug, Deserialize)]
pub struct Match {
    #[allow(dead_code)]
    op: String,
    pub left: serde_json::Value,
    pub right: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct CounterExpr {
    pub counter: Counter,
}

#[derive(Debug, Deserialize)]
pub struct Counter {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Deserialize)]
pub struct AcceptExpr {
    #[allow(dead_code)]
    accept: Option<serde_json::Value>,
}

pub async fn parse_output(json_output: &str) -> anyhow::Result<Vec<NftObject>> {
    let nft_data: NftJsonOutput = serde_json::from_str(json_output)
        .map_err(|e| anyhow::anyhow!("parser error  : {}, \n fail to parse {}", e, json_output))?;

    Ok(nft_data.nftables)
}
