mod hashes;
mod key_share;
mod primitives;
mod key_share_stored;
mod bls_verify;

use std::ops::Mul;
use crate::hashes::*;
use crate::bls_verify::*;
use crate::key_share::*;
use crate::primitives::*;
use crate::key_share_stored::*;


use ark_bls12_381::{
    Bls12_381, g1, g2, Fr as F_bls,
    G1Affine as G1Affine_bls, G2Affine as G2Affine_bls,
    G1Projective as G1Projective_bls, G2Projective as G2Projective_bls,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_bn254::{Bn254, Fr as Fr_bn, G1Affine as G1Affine_bn, G2Affine as G2Affine_bn, G1Projective as G1Projective_bn, G2Projective as G2Projective_bn, G2Affine};

use ark_ec::{pairing::Pairing, Group, CurveGroup,AffineRepr};

// retrieved from https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/public/2
const LOE_PUBLIC_KEY: &str = "a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e";
const SIGNATURE: &str = "9544ddce2fdbe8688d6f5b4f98eed5d63eee3902e7e162050ac0f45905a55657714880adabe3c3096b92767d886567d0";
const ROUND : u64 = 1;
const SECURITY_PARAM : usize = 2;
const SCHEME: &str = "BJJ";

fn make_secret_key_work() {
    let mut all_participant_data: Vec<Vec<u8>> = vec![];
    all_participant_data.push(keyshare_generate(
        LOE_PUBLIC_KEY.into(),
        ROUND,
        SCHEME.to_string(),
        SECURITY_PARAM
    ));
    all_participant_data.push(keyshare_generate(
        LOE_PUBLIC_KEY.into(),
        ROUND,
        SCHEME.to_string(),
        SECURITY_PARAM
    ));

    let secret_key = make_secret_key(ROUND, SCHEME.to_string(), SIGNATURE.to_string(), all_participant_data);
    println!("len_secret key BYTE = {:?}", secret_key);
    let vec_secret_key = hex::encode(secret_key);
    println!("len_secret key BYTE = {:?}", vec_secret_key);
    let f = str_to_field::<Fr_bn>(&vec_secret_key);
    println!("msk = {}", f);
    println!("vec_secret_key {} ",vec_secret_key.len());
    assert!(true);

    let f_byte = serialize_compressed_f::<Fr_bn>(&f);
    println!("f_byte = {:?}, len = {:?}", f_byte, f_byte.len());




}

fn main() {
    println!("Start!!");

    let mut rng = ark_std::test_rng();

    type TLCS_Key_Share = KeyShare<Bn254>;
    let mut all_key_share : Vec<TLCS_Key_Share> = Vec::new();
    for i in 0..2{
        println!(" key {}",i);
        let ks= TLCS_Key_Share::key_share_gen(&mut rng, &LOE_PUBLIC_KEY, ROUND, SECURITY_PARAM );
        let verified = TLCS_Key_Share::key_share_verify(&LOE_PUBLIC_KEY,&ks, ROUND,SECURITY_PARAM);
        if verified {
            all_key_share.push(ks);
        } else{
            println!("verified = {}", verified);
        }
    }
    let pk = &all_key_share[0].pk + &all_key_share[1].pk;

    let sk_round = str_to_group::<G1Projective_bls>(SIGNATURE).unwrap().into_affine();
    println!("sk_round = {}", sk_round);
    let msk = TLCS_Key_Share::msk_aggregation(&sk_round, &all_key_share);
    println!("msk = {}", msk);

    //assert!(msk.len() == 32);
    let mpk = TLCS_Key_Share::mpk_aggregation(&all_key_share);
    let g = G1Projective_bn::generator();
    let mpk_test = g.mul(&msk);
    if mpk == mpk_test {
    println!(" you are the best");
    }else{
        println!("let's try again");
        println!("mpk = {}", mpk.into_affine());
        println!("mpk = {}", mpk_test.into_affine());
        println!("pk = {}", pk.into_affine());


    }
    let mut msk_bytes = Vec::new();
    msk.serialize_compressed(&mut msk_bytes).unwrap();
    println!("step 4.4 msk_bytes ={:?} ", msk_bytes);
    println!(" msk_len ={}", msk_bytes.len());
    make_secret_key_work();
}
#[cfg(test)]
mod tests{
    use super::*;

    #[test]
    fn aggregation_is_correct(){
        println!("Start!!");

        let mut rng = ark_std::test_rng();

        type TLCS_Key_Share = KeyShare<Bn254>;
        let mut all_key_share : Vec<TLCS_Key_Share> = Vec::new();
        for i in 0..2{
            let ks= TLCS_Key_Share::key_share_gen(&mut rng, &LOE_PUBLIC_KEY, ROUND, SECURITY_PARAM );
            let verified = TLCS_Key_Share::key_share_verify(&LOE_PUBLIC_KEY,&ks, ROUND,SECURITY_PARAM);
            if verified {
                all_key_share.push(ks);
            } else{
                println!("verified = {}", verified);
            }
        }
        let pk = &all_key_share[0].pk + &all_key_share[1].pk;
        let sk_round = str_to_group::<G1Projective_bls>(SIGNATURE).unwrap().into_affine();
        //println!("sk_round = {}", sk_round);
        let msk = TLCS_Key_Share::msk_aggregation(&sk_round, &all_key_share);
        let mpk = TLCS_Key_Share::mpk_aggregation(&all_key_share);
        let g = G1Projective_bn::generator();
        let mpk_test = g.mul(&msk);
        assert_eq!(mpk,mpk_test);
    }


}
