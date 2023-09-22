//use primitives::*;
use crate::primitives::*;

use anyhow::anyhow;
use ark_bls12_381::{
    g1,
    g2,
    //g2::Config as G2Config,
    G1Affine as G1Affine_bls,
    //g1, g1::Config as G1Config, g2, g2::Config as G2Config, G1Affine as G1Affine_bls,
    G1Projective as G1Projective_bls,
    G2Affine as G2Affine_bls,
    G2Projective as G2Projective_bls,
};

use ark_ec::{
    hashing::{
        curve_maps::wb::WBMap,
        map_to_curve_hasher::MapToCurveBasedHasher,
        HashToCurve,
        //HashToCurveError,
    },
    models::short_weierstrass,
    //models::short_weierstrass::Projective,
    pairing::Pairing,
    pairing::PairingOutput,
    //AffineRepr,
    CurveGroup,
};

//use ark_bn254::{G1Projective, G2Affine as G2Affine_bn, G2Projective as G2Projective_bn};

use ark_ff::field_hashers::DefaultFieldHasher;
//use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_serialize::CanonicalSerialize;
//use ark_std::rand::Rng;
//use hex::ToHex;
//use sha2::{Digest, Sha256};

use bit_vec::BitVec;
use sha2::{Digest, Sha256};

pub const G1_DOMAIN: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
//pub const G2_DOMAIN: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
//
// 1
pub fn hash_loe_g1(msg: &[u8]) -> G1Affine_bls {
    let mapper = MapToCurveBasedHasher::<
        short_weierstrass::Projective<g1::Config>,
        DefaultFieldHasher<sha2::Sha256, 128>,
        WBMap<g1::Config>,
    >::new(G1_DOMAIN)
    .map_err(|_| anyhow!("cannot initialise mapper for sha2 to BLS12-381 G1"))
    .unwrap();
    let hash_on_curve = G1Projective_bls::from(
        mapper
            .hash(msg)
            .map_err(|_| anyhow!("hash cannot be mapped to G1"))
            .unwrap(),
    )
    .into_affine();
    return hash_on_curve;
}
#[allow(unused)]
pub fn hash_loe_g2(msg: &[u8]) -> G2Affine_bls {
    let mapper = MapToCurveBasedHasher::<
        short_weierstrass::Projective<g2::Config>,
        DefaultFieldHasher<sha2::Sha256, 128>,
        WBMap<g2::Config>,
    >::new(G1_DOMAIN)
    .map_err(|_| anyhow!("cannot initialise mapper for sha2 to BLS12-381 G2"))
    .unwrap();
    let hash_on_curve = G2Projective_bls::from(
        mapper
            .hash(msg)
            .map_err(|_| anyhow!("hash cannot be mapped to G2"))
            .unwrap(),
    )
    .into_affine();
    return hash_on_curve;
}

#[allow(unused)]
pub fn hash_1<E: Pairing>(g_target: PairingOutput<E>) -> Vec<u8> {
    let mut compressed_bytes = Vec::new();
    g_target
        .serialize_compressed(&mut compressed_bytes)
        .unwrap();

    let mut hasher = Sha256::new();
    hasher.update(compressed_bytes);
    let result = hasher.finalize();
    let mut fixed_size_u8 = [0; 32];
    fixed_size_u8.copy_from_slice(result.as_ref());
    fixed_size_u8.to_vec()
}
#[allow(unused)]
pub fn hash_2<E: Pairing>(
    pk: &E::G1,
    pk_0_vec: &Vec<E::G1>,
    pk_1_vec: &Vec<E::G1>,
    t_0: &Vec<G2Projective_bls>,
    t_1: &Vec<G2Projective_bls>,
    y_0: &Vec<Vec<u8>>,
    y_1: &Vec<Vec<u8>>,
) -> bit_vec::BitVec {
    let mut hasher = Sha256::new();
    let mut compressed_bytes = Vec::new();

    pk.serialize_compressed(&mut compressed_bytes).unwrap();
    hasher.update(compressed_bytes);

    let mut compressed_bytes = Vec::new();
    pk_0_vec
        .serialize_compressed(&mut compressed_bytes)
        .unwrap();
    hasher.update(compressed_bytes);

    let mut compressed_bytes = Vec::new();
    pk_1_vec
        .serialize_compressed(&mut compressed_bytes)
        .unwrap();
    hasher.update(compressed_bytes);

    let mut compressed_bytes = Vec::new();
    t_0.serialize_compressed(&mut compressed_bytes).unwrap();
    hasher.update(compressed_bytes);

    let mut compressed_bytes = Vec::new();
    t_1.serialize_compressed(&mut compressed_bytes).unwrap();
    hasher.update(compressed_bytes);

    let mut compressed_bytes = Vec::new();
    y_0.serialize_compressed(&mut compressed_bytes).unwrap();

    hasher.update(compressed_bytes);

    let mut compressed_bytes = Vec::new();
    y_1.serialize_compressed(&mut compressed_bytes).unwrap();
    hasher.update(compressed_bytes);

    let result = hasher.finalize();
    BitVec::from_bytes(&result)
}

pub fn message(current_round: u64) -> Vec<u8> {
    let mut hasher = Sha256::default();
    hasher.update(round_to_bytes(current_round));
    return hasher.finalize().to_vec();
}
