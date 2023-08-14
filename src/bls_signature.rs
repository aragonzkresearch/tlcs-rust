use crate::primitives::*;

use anyhow::{anyhow, Result};
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
use hex::ToHex;
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

pub fn str_to_group_1(g_str: &str) -> G1Affine {
    let g_bytes = hex::decode(g_str).unwrap();
    let g = G1Affine::deserialize_compressed(&*g_bytes).unwrap();
    return g;
}

pub fn str_to_group_2(g_str: &str) -> G2Affine {
    let g_bytes = hex::decode(g_str).unwrap();
    let g = G2Affine::deserialize_compressed(&*g_bytes).unwrap();
    return g;
}

pub fn round_to_bytes(round: u64) -> [u8; 8] {
    round.to_be_bytes()
}

pub fn concatinate_str(current_round: u64, previous_signature: &str) -> String {
    let mut hasher = Sha256::default();
    hasher.update(str_to_byte(previous_signature));
    hasher.update(round_to_bytes(current_round));
    return hasher.finalize().encode_hex();
}

pub fn str_to_byte(g_str: &str) -> Vec<u8> {
    hex::decode(g_str).unwrap()
}

pub fn bls_verify_1(pk: &str, message: &str, signature: &str) -> bool {
    let pk_affine_1 = str_to_group_1(pk); //G2Affine::deserialize_compressed(&*pk_bytes).unwrap();
    let signature_affine_2 = str_to_group_2(signature);
    let mut hash_on_curve_2 = hash_loe_g2(G2_DOMAIN, &str_to_byte(&message));

    let left_hand = Bls12_381::pairing(G1Affine::generator(), &signature_affine_2);
    let right_hand = Bls12_381::pairing(&pk_affine_1, &hash_on_curve_2);
    return left_hand == right_hand;
}
pub fn bls_verify_2(pk: &str, message: &str, signature: &str) -> bool {
    let pk_affine_2 = str_to_group_2(pk); //G2Affine::deserialize_compressed(&*pk_bytes).unwrap();
    let signature_affine_1 = str_to_group_1(signature);
    let mut hash_on_curve_1 = hash_loe_g1(G1_DOMAIN, &str_to_byte(&message));
    let left_hand = Bls12_381::pairing(&signature_affine_1, G2Affine::generator());
    let right_hand = Bls12_381::pairing(&hash_on_curve_1, &pk_affine_2);
    return left_hand == right_hand;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn bls_verify_test() {
        let pk = "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31";
        let signature = "84935a794779bf9a5b763972738728a05aceb8c388a9f5142446d064f722a972c3ff8ecc7d6ea1ba84bc19656499fed9130dd0c42603e1e1dfe3a47cace2741cf1096dd000f0b9b58d880df76fd739ad99797116f0d40217c77274eb6e94b236";
        let previous_signature = "996ed8703262191c4105266b59d073b565317a47b3be71c51d5c0e8d3372422784b43cfe6d211f207f9d30570db323d5074df080fed6bbf6143496b2350d88bf07e0b64298d9673af4d94d83f550986b6725aaaf793ad3670aa58eae5573a9f0";
        let round = 30;

        let pk_affine_1 = str_to_group_1(&pk); //G2Affine::deserialize_compressed(&*pk_bytes).unwrap();

        let signature_affin_2 = str_to_group_2(&signature);
        let my_message = concatinate_str(round, &previous_signature);

        let mut hash_on_curve_1 = hash_loe_g1(G1_DOMAIN, &str_to_byte(&my_message));
        let mut hash_on_curve_2 = hash_loe_g2(G2_DOMAIN, &str_to_byte(&my_message));

        let left_hand = Bls12_381::pairing(G1Affine::generator(), &signature_affin_2);
        let right_hand = Bls12_381::pairing(&pk_affine_1, &hash_on_curve_2);
        let bls_result = bls_verify_1(
            &pk,
            &concatinate_str(round, &previous_signature),
            &signature,
        );
        println!("Ultimate bls is  {}", bls_result);
        assert_eq!(bls_result, true);
        assert!(bls_result);
    }

    #[test]
    fn conver_to_byte_test() {
        let round: u64 = 72785;
        let previous_signature = "a609e19a03c2fcc559e8dae14900aaefe517cb55c840f6e69bc8e4f66c8d18e8a609685d9917efbfb0c37f058c2de88f13d297c7e19e0ab24813079efe57a182554ff054c7638153f9b26a60e7111f71a0ff63d9571704905d3ca6df0b031747";
        let message = concatinate_str(round, &previous_signature);
        let expected_messag: [u8; 32] = [
            77, 186, 10, 199, 207, 37, 117, 214, 254, 49, 204, 31, 162, 140, 76, 36, 153, 126, 2,
            102, 94, 65, 118, 9, 37, 164, 36, 32, 219, 169, 57, 184,
        ];
        assert_eq!(str_to_byte(&message), expected_messag);
    }
}
