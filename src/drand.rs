use serde::{Deserialize, Serialize};
use std::vec::Vec;
use reqwest::Error;

#[derive(Serialize, Deserialize, Debug)]
pub struct ChainInfoMetadata {
    #[serde(alias = "beaconID")]
    beacon_id: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ChainInfo {
    public_key: String,
    period: u8,
    genesis_time: i64,
    hash: String,
    #[serde(alias = "groupHash")]
    group_hash: String,
    #[serde(alias = "schemeID")]
    scheme_id: String,
    metadata: ChainInfoMetadata,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChainRound {
    round: i64,
    randomness: String,
    signature: String,
    #[serde(default)]
    previous_signature: String,
}

#[allow(unused)]
pub async fn get_chains() -> Result<Vec<String>, Error> {
    let resp = reqwest::get("https://api.drand.sh/chains").await?;
    println!("Status: {}", resp.status());

    resp.json().await
}

#[allow(unused)]
pub async fn get_chains_info(chain: &String) -> Result<ChainInfo, Error> {
    reqwest::get(format!("https://api.drand.sh/{}/info", chain))
        .await?
        .json::<ChainInfo>()
        .await
}

#[allow(unused)]
pub async fn get_chain_round(chain: &String, round: &str) -> Result<ChainRound, Error> {
    reqwest::get(format!("https://api.drand.sh/{}/public/{}", chain, round))
        .await?
        .json::<ChainRound>()
        .await
}
