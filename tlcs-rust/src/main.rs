mod key_share;
mod primitives;
mod drand;

use key_share::*;
use primitives::*;
use drand::*;

#[allow(unused)]
#[allow(dead_code)]

#[tokio::main]
fn main(){
    let k = key_share_gen();
    let b = verf_key_share(&k);

    let mut k_vec: Vec<KeyShare> = Vec::new();
    k_vec.push(k);

    let mpk = mpk_aggregation(&k_vec);

    let sk_t = todo!(); // published by the LoE

    let msk = msk_aggregation(&sk_t , &k_vec);
    
}
