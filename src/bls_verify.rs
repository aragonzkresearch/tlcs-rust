use crate::hashes::*;
use crate::primitives::*;

#[allow(unused)]
#[allow(dead_code)]
use ark_bls12_381::{
    g1, g2, Bls12_381, Fr as F_bls, G1Affine as G1Affine_bls, G1Projective as G1Projective_bls,
    G2Affine as G2Affine_bls, G2Projective as G2Projective_bls,
};
use ark_ec::AffineRepr;
use ark_ec::{pairing::Pairing, CurveGroup};
//use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
//use ark_std::io::Read;
//use ark_std::{ops::Mul, rand::Rng, UniformRand, Zero};

//use hex::ToHex;
//use sha2::{Digest, Sha256};

use sha2::{Digest, Sha256};
//use bit_vec::BitVec;

#[allow(unused)]
pub fn bls_verify_1(pk: &str, message: &[u8], signature: &str) -> bool {
    let pk_affine_1 = str_to_group::<G1Projective_bls>(pk).unwrap().into_affine();
    let signature_affine_2 = str_to_group::<G2Projective_bls>(signature)
        .unwrap()
        .into_affine();
    let mut hash_on_curve_2 = hash_loe_g2(message);

    let left_hand = Bls12_381::pairing(G1Affine_bls::generator(), &signature_affine_2);
    let right_hand = Bls12_381::pairing(&pk_affine_1, &hash_on_curve_2);
    return left_hand == right_hand;
}

#[allow(unused)]
pub fn bls_verify_2(pk: &str, message: &[u8], signature: &str) -> bool {
    let pk_affine_2 = str_to_group::<G2Projective_bls>(pk).unwrap().into_affine();
    let signature_affine_1 = str_to_group::<G1Projective_bls>(signature)
        .unwrap()
        .into_affine();
    let mut hash_on_curve_1 = hash_loe_g1(message);

    let left_hand = Bls12_381::pairing(&signature_affine_1, G2Affine_bls::generator());
    let right_hand = Bls12_381::pairing(&hash_on_curve_1, &pk_affine_2);
    return left_hand == right_hand;
}

#[allow(unused)]
pub fn concatinate(current_round: u64, previous_signature: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::default();
    hasher.update(previous_signature);
    hasher.update(round_to_bytes(current_round));
    return hasher.finalize().to_vec();
}
