use ark_bls12_381::{
    Bls12_381, g1, g2, Fr as F_L,
    G1Affine as G1Affine_L, G2Affine as G2Affine_L,
    G2Projective as G2_L, G1Projective as G1_L,
};
//use ark_bls12_381::{g1, g2, Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
//use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_bn254::Fr;

use ark_ec::pairing::PairingOutput;
use ark_ec::{pairing::Pairing, CurveGroup, Group};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use ark_std::{ops::Mul, UniformRand};

use bit_vec::BitVec;
//use sha2::{Digest, Sha256};
use hex::ToHex;


pub fn str_to_group_1(g_str: &str) -> G1Affine_L {
    let g_bytes = hex::decode(g_str).unwrap();
    let g = G1Affine_L::deserialize_compressed(&*g_bytes).unwrap();
    return g;
}

pub fn str_to_group_2(g_str: &str) -> G2Affine_L {
    let g_bytes = hex::decode(g_str).unwrap();
    let g = G2Affine_L::deserialize_compressed(&*g_bytes).unwrap();
    return g;
}

pub fn round_to_bytes(round: u64) -> [u8; 8] {
    round.to_be_bytes()
}



pub fn str_to_byte(g_str: &str) -> Vec<u8> {
    hex::decode(g_str).unwrap()
}


pub fn xor(a: &Vec<u8> , b: &Vec<u8> ) -> Vec<u8> {
    let len = a.len().max(b.len());
    let mut result = Vec::with_capacity(len);

    for i in 0..len {
        let byte_a = a.get(i).cloned().unwrap_or(0);
        let byte_b = b.get(i).cloned().unwrap_or(0);
        result.push(byte_a ^ byte_b);
    }
    return result;
}

pub fn seri_compressed_f(s: &Fr) -> Vec<u8>{
    let mut compressed_bytes = Vec::new();
    s.serialize_compressed(&mut compressed_bytes).unwrap();
    return compressed_bytes;
}
