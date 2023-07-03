mod primitives;
mod key_share;

use primitives::*;
use key_share::*;

#[allow(unused)]
#[allow(dead_code)]


fn main(){
    let k = key_share_gen();
    println!("the key = {:?}",k);

}
