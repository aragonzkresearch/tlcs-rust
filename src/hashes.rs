
//use primitives::*;
use crate::primitives::*;

use anyhow::{anyhow, Result};
use ark_bls12_381::{
    Bls12_381, g1, g2, Fr as F_bls,
    G1Affine as G1Affine_bls, G2Affine as G2Affine_bls,
    G1Projective as G1Projective_bls, G2Projective as G2Projective_bls,
};

use ark_ec::{
    bls12::Bls12,
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    models::short_weierstrass,
    pairing::Pairing,
    pairing::PairingOutput,
    AffineRepr, CurveGroup, Group,
};
use ark_bn254::{Bn254, Fr as Fr_bn, G1Affine as G1Affine_bn,  G2Affine as G2Affine_bn,
                G1Projective as G1Projective_bn, G2Projective as G2Projective_bn};

//use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ff::Field;
use ark_ff::UniformRand;
use ark_ff::{field_hashers::DefaultFieldHasher, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::rand::Rng;
use hex::ToHex;
//use sha2::{Digest, Sha256};
use std::ops::Neg;
use std::ptr::hash;
use sha2::{Digest, Sha256};
use bit_vec::BitVec;

pub const G1_DOMAIN: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
pub const G2_DOMAIN: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

pub fn hash_loe_g1( msg: &[u8]) -> G1Affine_bls {
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

pub fn hash_loe_g2( msg: &[u8]) -> G2Affine_bls {
    let mapper = MapToCurveBasedHasher::<
        short_weierstrass::Projective<g2::Config>,
        DefaultFieldHasher<sha2::Sha256, 128>,
        WBMap<g2::Config>,
    >::new(G2_DOMAIN)
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
/*
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
 */
/*
pub fn hash_loe_g2<E : Pairing>(dst: &[u8], msg: &[u8]) -> E::G2Affine
    where <E as Pairing>::G2Prepared: From<ark_ec::short_weierstrass::Affine<ark_bls12_381::g2::Config>>,
          <E as Pairing>::G2Affine: From<<E as Pairing>::G2Prepared>
{
    let mapper = MapToCurveBasedHasher::<
        short_weierstrass::Projective<g2::Config>,
        DefaultFieldHasher<sha2::Sha256, 128>,
        WBMap<g2::Config>,
    >::new(dst)
        .map_err(|_| anyhow!("cannot initialise mapper for sha2 to BLS12-381 G2"))
        .unwrap();
    let hash_on_curve = E::G2Prepared::from(
        mapper
            .hash(msg)
            .map_err(|_| anyhow!("hash cannot be mapped to G2"))
            .unwrap(),
    ).into();
    return hash_on_curve;
}


 */

pub fn hash_1<E : Pairing>(
    g_target: PairingOutput<E>
) -> Vec<u8> {
    let mut uncompressed_bytes = Vec::new();
    g_target
        .serialize_uncompressed(&mut uncompressed_bytes)
        .unwrap();

    let mut hasher = Sha256::new();
    hasher.update(uncompressed_bytes);
    let result = hasher.finalize();
    let mut fixed_size_u8 = [0; 32];
    fixed_size_u8.copy_from_slice(result.as_ref());
    fixed_size_u8.to_vec()
}

pub fn hash_2<E : Pairing>(
              pk: &E::G1, pk_0_vec: &Vec<E::G1>,
              pk_1_vec : &Vec<E::G1>,
              t_0: &Vec<G2Projective_bls>,
              t_1: &Vec<G2Projective_bls>,
              y_0: &Vec<Vec<u8>>,
              y_1: &Vec<Vec<u8>>
) -> bit_vec::BitVec {
    let mut hasher = Sha256::new();
    //hasher.update(party.to_be_bytes());

    let mut uncompressed_bytes = Vec::new();

    pk.serialize_uncompressed(&mut uncompressed_bytes).unwrap();
    hasher.update(uncompressed_bytes);

    let mut uncompressed_bytes = Vec::new();
    pk_0_vec.serialize_uncompressed(&mut uncompressed_bytes).unwrap();
    hasher.update(uncompressed_bytes);

    let mut uncompressed_bytes = Vec::new();
    pk_1_vec.serialize_uncompressed(&mut uncompressed_bytes).unwrap();
    hasher.update(uncompressed_bytes);

    let mut uncompressed_bytes = Vec::new();
    t_0.serialize_uncompressed(&mut uncompressed_bytes).unwrap();
    hasher.update(uncompressed_bytes);

    let mut uncompressed_bytes = Vec::new();
    t_1.serialize_uncompressed(&mut uncompressed_bytes).unwrap();
    hasher.update(uncompressed_bytes);

    let mut uncompressed_bytes = Vec::new();
    y_0.serialize_uncompressed(&mut uncompressed_bytes).unwrap();

    hasher.update(uncompressed_bytes);

    let mut uncompressed_bytes = Vec::new();
    y_1.serialize_uncompressed(&mut uncompressed_bytes).unwrap();
    hasher.update(uncompressed_bytes);

    let result = hasher.finalize();
    BitVec::from_bytes(&result)
}
pub fn concatinate_str(current_round: u64, previous_signature: &str) -> String {
    let mut hasher = Sha256::default();
    hasher.update(str_to_byte(previous_signature));
    hasher.update(round_to_bytes(current_round));
    return hasher.finalize().encode_hex();
}
