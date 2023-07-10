mod key_share;
mod primitives;
mod drand;

use key_share::*;
use primitives::*;
use drand::*;

#[allow(unused)]
#[allow(dead_code)]

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let k = key_share_gen();
    let b = verf_key_share(&k);

    let mut k_vec: Vec<KeyShare> = Vec::new();
    k_vec.push(k);

    let mpk = mpk_aggregation(&k_vec);

    //let msk = msk_aggregation();

    let chains_resp = getChains().await?;
    println!("Body:\n{:#?}\n", chains_resp);

    for chain in chains_resp {
        let chain_info = getChainsInfo(&chain).await?;
        println!("{:#?}\n", chain_info);

        let mut last_chain_round = getChainRound(&chain, "latest").await?;
        println!("{:#?}\n", last_chain_round);

        let mut last_chain_round = getChainRound(&chain, "1865295").await?;
        println!("{:#?}\n", last_chain_round);
    }

    Ok(())
}
