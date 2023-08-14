use ark_bls12_381::{g1, g2, Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    bls12::Bls12,
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    models::short_weierstrass,
    pairing::Pairing,
    pairing::PairingOutput,
    AffineRepr, CurveGroup, Group,
};
use ark_ff::Field;
use ark_ff::UniformRand;
use ark_ff::{field_hashers::DefaultFieldHasher, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::rand::Rng;

use anyhow::{anyhow, Result};
use hex_literal::hex;
use sha2::{Digest, Sha256};
use std::ops::Neg;
use std::ptr::hash;

pub const G1_DOMAIN: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
pub const G2_DOMAIN: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

pub fn hash_loe_g1(dst: &[u8], msg: &[u8]) -> G1Affine {
    let mapper = MapToCurveBasedHasher::<
        short_weierstrass::Projective<g1::Config>,
        DefaultFieldHasher<sha2::Sha256, 128>,
        WBMap<g1::Config>,
    >::new(dst)
    .map_err(|_| anyhow!("cannot initialise mapper for sha2 to BLS12-381 G1"))
    .unwrap();
    let hash_on_curve = G1Projective::from(
        mapper
            .hash(msg)
            .map_err(|_| anyhow!("hash cannot be mapped to G1"))
            .unwrap(),
    )
    .into_affine();
    return hash_on_curve;
}

pub fn hash_loe_g2(dst: &[u8], msg: &[u8]) -> G2Affine {
    let mapper = MapToCurveBasedHasher::<
        short_weierstrass::Projective<g2::Config>,
        DefaultFieldHasher<sha2::Sha256, 128>,
        WBMap<g2::Config>,
    >::new(dst)
    .map_err(|_| anyhow!("cannot initialise mapper for sha2 to BLS12-381 G2"))
    .unwrap();
    let hash_on_curve = G2Projective::from(
        mapper
            .hash(msg)
            .map_err(|_| anyhow!("hash cannot be mapped to G2"))
            .unwrap(),
    )
    .into_affine();
    return hash_on_curve;
}

fn str_to_group_1(g_str: &str) -> G1Affine {
    let g_bytes = hex::decode(g_str).unwrap();
    let g = G1Affine::deserialize_compressed(&*g_bytes).unwrap();
    return g;
}

fn str_to_group_2(g_str: &str) -> G2Affine {
    let g_bytes = hex::decode(g_str).unwrap();
    let g = G2Affine::deserialize_compressed(&*g_bytes).unwrap();
    return g;
}

fn round_to_bytes(round: u64) -> [u8; 8] {
    round.to_be_bytes()
}

fn fast_pairing_equality(p: &G1Affine, q: &G2Affine, r: &G1Affine, s: &G2Affine) -> bool {
    let minus_p = p.neg();
    // "some number of (G1, G2) pairs" are the inputs of the miller loop
    let looped = Bls12::<ark_bls12_381::Config>::multi_miller_loop([minus_p, *r], [*q, *s]);
    let value = Bls12::final_exponentiation(looped);
    value.unwrap().is_zero()
}

fn message(current_round: u64, prev_sig: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::default();
    hasher.update(prev_sig);
    hasher.update(round_to_bytes(current_round));
    hasher.finalize().to_vec()
}

fn concatinate_str(current_round: u64, prev_sig: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::default();
    hasher.update(prev_sig);
    hasher.update(round_to_bytes(current_round));
    hasher.finalize().to_vec()
}

fn str_to_byte(g_str: &str) -> Vec<u8> {
    hex::decode(g_str).unwrap()
}

fn main() {
    /// Public key League of Entropy Mainnet (curl -sS https://drand.cloudflare.com/info)
   // let  pk : [u8; 48] = hex!("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31");
    let pk = "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31";
    let pk_affine_1 = str_to_group_1(&pk); //G2Affine::deserialize_compressed(&*pk_bytes).unwrap();
    println!("pk_affine_2 = {}", pk_affine_1);

    let signature = "82f5d3d2de4db19d40a6980e8aa37842a0e55d1df06bd68bddc8d60002e8e959eb9cfa368b3c1b77d18f02a54fe047b80f0989315f83b12a74fd8679c4f12aae86eaf6ab5690b34f1fddd50ee3cc6f6cdf59e95526d5a5d82aaa84fa6f181e42";
    let signature_affin_2 = str_to_group_2(&signature);
    // let sig_bytes = hex::decode(signature).unwrap();
    //let signature_affin_1 = G1Affine::deserialize_compressed(&*sig_bytes).unwrap();
    println!("signature = {}", signature_affin_2);
    let round: u64 = 72785;

    let previous_signature = "a609e19a03c2fcc559e8dae14900aaefe517cb55c840f6e69bc8e4f66c8d18e8a609685d9917efbfb0c37f058c2de88f13d297c7e19e0ab24813079efe57a182554ff054c7638153f9b26a60e7111f71a0ff63d9571704905d3ca6df0b031747";

    let my_message = message(round, &str_to_byte(&previous_signature));

    let messag_from_noislab: [u8; 32] = [
        77, 186, 10, 199, 207, 37, 117, 214, 254, 49, 204, 31, 162, 140, 76, 36, 153, 126, 2, 102,
        94, 65, 118, 9, 37, 164, 36, 32, 219, 169, 57, 184,
    ];
    if my_message == messag_from_noislab {
        println!("TRUE");
    } else {
        println!("FALSE");
    }

    /*
    {"round":30,
    "randomness":"f29dac129099b170cf44d973ee338bc90e24946e410791269b374376efc27f85",
    "signature":"84935a794779bf9a5b763972738728a05aceb8c388a9f5142446d064f722a972c3ff8ecc7d6ea1ba84bc19656499fed9130dd0c42603e1e1dfe3a47cace2741cf1096dd000f0b9b58d880df76fd739ad99797116f0d40217c77274eb6e94b236",
    "previous_signature":"996ed8703262191c4105266b59d073b565317a47b3be71c51d5c0e8d3372422784b43cfe6d211f207f9d30570db323d5074df080fed6bbf6143496b2350d88bf07e0b64298d9673af4d94d83f550986b6725aaaf793ad3670aa58eae5573a9f0"}
     */
    let pk = "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31";
    let round = 30;

    //                    868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31
    let pk_affine_1 = str_to_group_1(&pk); //G2Affine::deserialize_compressed(&*pk_bytes).unwrap();
    println!("pk_affine_2 = {}", pk_affine_1);

    let signature = "84935a794779bf9a5b763972738728a05aceb8c388a9f5142446d064f722a972c3ff8ecc7d6ea1ba84bc19656499fed9130dd0c42603e1e1dfe3a47cace2741cf1096dd000f0b9b58d880df76fd739ad99797116f0d40217c77274eb6e94b236";
    let signature_affin_2 = str_to_group_2(&signature);
    // let sig_bytes = hex::decode(signature).unwrap();
    //let signature_affin_1 = G1Affine::deserialize_compressed(&*sig_bytes).unwrap();
    println!("signature = {}", signature_affin_2);
    let previous_signature = "996ed8703262191c4105266b59d073b565317a47b3be71c51d5c0e8d3372422784b43cfe6d211f207f9d30570db323d5074df080fed6bbf6143496b2350d88bf07e0b64298d9673af4d94d83f550986b6725aaaf793ad3670aa58eae5573a9f0";
    let my_message = message(round, &str_to_byte(&previous_signature));

    //let messag_from_noislab: [u8;32] =  [77, 186, 10, 199, 207, 37, 117, 214, 254, 49, 204, 31, 162, 140, 76, 36, 153, 126, 2, 102, 94, 65, 118, 9, 37, 164, 36, 32, 219, 169, 57, 184];
    let mut hash_on_curve_1 = hash_to_curve_1(G1_DOMAIN, &my_message);
    let mut hash_on_curve_2 = hash_to_curve_2(G2_DOMAIN, &my_message);
    println!("hash_1  = {}", hash_on_curve_1);
    println!("hash_2  = {}", hash_on_curve_2);

    let left_hand = Bls12_381::pairing(G1Affine::generator(), &signature_affin_2);
    let right_hand = Bls12_381::pairing(&pk_affine_1, &hash_on_curve_2);
    println!("left_hand = {}", left_hand);
    println!("right_hand = {}", right_hand);
    if left_hand == right_hand {
        println!("2. true");
    } else {
        println!("2. false");
    }

    /*



       //let msg = hex!("8b676484b5fb1f37f9ec5c413d7d29883504e5b669f604a1ce68b3388e9ae3d9");


        println!("hash  = {}", hash_on_curve_1);
       let mut hash_on_curve_2 = hash_to_curve_2(G2_DOMAIN, &msg);
       println!("hash  = {}", hash_on_curve_2);
       let result = fast_pairing_equality(&hash_on_curve_1, &pk_affine_2, );


       let left_hand = Bls12_381::pairing(&hash_1, &pk_affine_2);
       let right_hand = Bls12_381::pairing(&signature_affin_1,  &pk_affine_2);
       println!("left_hand = {}", left_hand);
       println!("right_hand = {}", right_hand);
       if left_hand== right_hand{
           println!("true");
       } else{
           println!("false");
       }
       let mut result = fast_pairing_equality(&hash_1, &pk_affine_2, &signature_affin_1,&G2Affine::generator());
       result = fast_pairing_equality(&hash_1, &pk_affine_2, &hash_1, &pk_affine_2);
       println!("result = {}", result);

    */
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_hash() {
        println!("Hello!");
        let pk_str = "868f005eb8e6e4sca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31";
        let signature_str = "82f5d3d2de4db19d40a6980e8aa37842a0e55d1df06bd68bddc8d60002e8e959eb9cfa368b3c1b77d18f02a54fe047b80f0989315f83b12a74fd8679c4f12aae86eaf6ab5690b34f1fddd50ee3cc6f6cdf59e95526d5a5d82aaa84fa6f181e42";
        let round_str: u64 = 72785;
        let randomness_str = "8b676484b5fb1f37f9ec5c413d7d29883504e5b669f604a1ce68b3388e9ae3d9";
        /// Public key League of Entropy Mainnet (curl -sS https://drand.cloudflare.com/info)
        let  pk : [u8; 48] = hex!("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31");
        let signature = hex!("82f5d3d2de4db19d40a6980e8aa37842a0e55d1df06bd68bddc8d60002e8e959eb9cfa368b3c1b77d18f02a54fe047b80f0989315f83b12a74fd8679c4f12aae86eaf6ab5690b34f1fddd50ee3cc6f6cdf59e95526d5a5d82aaa84fa6f181e42");
        let msg = hex!("8b676484b5fb1f37f9ec5c413d7d29883504e5b669f604a1ce68b3388e9ae3d9");
        let messag_from_noislab: [u8; 32] = [
            77, 186, 10, 199, 207, 37, 117, 214, 254, 49, 204, 31, 162, 140, 76, 36, 153, 126, 2,
            102, 94, 65, 118, 9, 37, 164, 36, 32, 219, 169, 57, 184,
        ];

        let mut hash_on_curve_1 = hash_to_curve_1(G1_DOMAIN, &messag_from_noislab);
        println!("hash  = {}", hash_on_curve_1);
        let mut hash_on_curve_2 = hash_to_curve_2(G2_DOMAIN, &msg);
        println!("hash  = {}", hash_on_curve_2);
    }
}
