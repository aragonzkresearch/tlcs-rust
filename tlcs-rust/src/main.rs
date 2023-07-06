mod primitives;
mod key_share;

use primitives::*;
use key_share::*;


#[allow(unused)]
#[allow(dead_code)]

fn main() {
    let k = key_share_gen();
    let b = verf_key_share(&k);

    let mut k_vec : Vec<KeyShare> = Vec::new();
    k_vec.push(k);


    let mpk = mpk_aggregation(&k_vec);

    //let msk = msk_aggregation();

}
