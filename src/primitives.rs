//use ark_ec::pairing::Pairing;
//use ark_ec::pairing::PairingOutput;

//use ark_std::{ops::Mul, UniformRand};

//use bit_vec::BitVec;
//use sha2::{Digest, Sha256};
//use ark_ec::{CurveGroup, Group};
//use ark_serialize::CanonicalDeserialize;
//use ark_ec::CurveGroup;
use ark_ff::{Field, biginteger::BigInteger256 as BigInteger};
use ark_ec::{ AffineRepr, CurveGroup,Group, VariableBaseMSM};
use num_bigint::{ToBigInt,BigUint};
use std::str::FromStr;

//use hex::ToHex;
use std::fmt;
use digest::typenum::private::IsNotEqualPrivate;
//use rand::{thread_rng, Rng};
// delete for real

use num_bigint::BigInt;
#[derive(Debug)]
pub struct InvalidPoint;

impl fmt::Display for InvalidPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "The data does not map to a valid point on the curve")
    }
}
pub fn str_to_group<G: CurveGroup>(g_str: &str) -> Result<G, InvalidPoint> {
    let g_bytes = hex::decode(g_str).unwrap();
    Option::from(G::deserialize_compressed(&*g_bytes).unwrap()).ok_or(InvalidPoint)
}

//
// pub fn group_hex_rep<G: CurveGroup >(g: &G) -> (String, String) {
//     let g_affine = g.into_affine();
//     let g_x : BigInteger = g_affine.x().unwrap().into();
//     let g_y : BigInteger = g_affine.y().unwrap().into();
//      (format!("0x{:X}", g_x) , format!("0x{:X}", g_y))
// }
pub fn group_compressed<G: CurveGroup>(g: &G) -> String {
    let mut g_bytes = Vec::new();
    g.serialize_compressed(&mut g_bytes).unwrap();
    let g_hex = hex::encode(g_bytes);
    g_hex
}
pub fn field_hex_rep<F: Field >(field_element: &F) -> String {
    let f_str  = field_element.to_string();
    let f_int  : BigUint = BigUint::from_str(&f_str.as_str()).unwrap();
    format!("0x{:X}", f_int)
}

pub fn field_compressed<F: Field>(f: &F) -> String {
    let mut f_bytes = Vec::new();
    f.serialize_compressed(&mut f_bytes).unwrap();
    let f_hex = hex::encode(f_bytes);
    f_hex
}


#[allow(unused)]
pub fn byte_to_group<G: CurveGroup>(g_bytes: Vec<u8>) -> Result<G, InvalidPoint> {
    // test : NOT DONE
    Option::from(G::deserialize_compressed(&*g_bytes).unwrap()).ok_or(InvalidPoint)
}

#[allow(unused)]
pub fn group_to_hex<G: CurveGroup>(g: &G) -> String {
    let mut g_bytes = Vec::new();
    g.serialize_compressed(&mut g_bytes).unwrap();
    let g_hex = hex::encode(g_bytes);
    g_hex
}

#[allow(unused)]
pub fn group_to_byte<G: CurveGroup>(g: &G) -> Vec<u8> {
    // test : NOT DONE
    let mut g_bytes = Vec::new();
    //g.serialize_compressed(&mut g_bytes).unwrap();
    g.serialize_compressed(&mut g_bytes).unwrap();
    g_bytes
}

#[allow(unused)]
pub fn serialize_compressed_f<F: Field>(s: &F) -> Vec<u8> {
    // test : NOT DONE
    let mut compressed_bytes = Vec::new();
    s.serialize_compressed(&mut compressed_bytes).unwrap();
    compressed_bytes
}
#[allow(unused)]
pub fn round_to_bytes(round: u64) -> [u8; 8] {
    // test : NOT DONE
    round.to_be_bytes()
}
#[allow(unused)]
pub fn str_to_byte(g_str: &str) -> Vec<u8> {
    // test : NOT DONE
    hex::decode(g_str).unwrap()
}

#[allow(unused)]
pub fn str_to_field<F: Field>(f_str: &str) -> F {
    let f_bytes = hex::decode(f_str).unwrap();
    F::deserialize_compressed(&*f_bytes).unwrap()
}

#[allow(unused)]
pub fn field_to_hex<F: Field>(f: &F) -> String {
    let mut f_bytes = Vec::new();
    f.serialize_compressed(&mut f_bytes).unwrap();
    let f_hex = hex::encode(f_bytes);
    f_hex
}

///
/// Consider the case with tow different length vectors
///
pub fn xor(a: &Vec<u8>, b: &Vec<u8>) -> Vec<u8> {
    let len = a.len().max(b.len());
    let mut result = Vec::with_capacity(len);

    for i in 0..len {
        let byte_a = a.get(i).cloned().unwrap_or(0);
        let byte_b = b.get(i).cloned().unwrap_or(0);
        result.push(byte_a ^ byte_b);
    }
    result
}
