
use ark_ec::pairing::PairingOutput;
use ark_ec::{pairing::Pairing};

use ark_std::{ops::Mul, UniformRand};

//use bit_vec::BitVec;
//use sha2::{Digest, Sha256};
use ark_ec::{CurveGroup, Group};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use hex::ToHex;
use std::fmt;
use ark_ff::Field;
use rand::{thread_rng, Rng};
// delete for real


#[derive(Debug)]
pub struct InvalidPoint;

impl fmt::Display for InvalidPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "The data does not map to a valid point on the curve")
    }
}
pub fn str_to_group<G: CurveGroup>(g_str: &str)->  Result<G, InvalidPoint>{
    let g_bytes = hex::decode(g_str).unwrap();
    Option::from(G::deserialize_compressed(&*g_bytes).unwrap()).ok_or(InvalidPoint)
}

pub fn byte_to_group<G: CurveGroup>(g_bytes: Vec<u8>)->  Result<G, InvalidPoint>{ // test : NOT DONE
    Option::from(G::deserialize_compressed(&*g_bytes).unwrap()).ok_or(InvalidPoint)
}


pub fn group_to_hex<G: CurveGroup>(g: &G) -> String{
    let mut g_bytes = Vec::new();
    g.serialize_compressed(&mut g_bytes).unwrap();
    let g_hex = hex::encode(g_bytes);
    g_hex
}

pub fn group_to_byte<G: CurveGroup>(g: &G) ->Vec<u8>{ // test : NOT DONE
    let mut g_bytes = Vec::new();
    //g.serialize_compressed(&mut g_bytes).unwrap();
    g.serialize_uncompressed(&mut g_bytes).unwrap();
    g_bytes
}


pub fn serialize_compressed_f<F: Field>(s: &F) -> Vec<u8>{ // test : NOT DONE
    let mut compressed_bytes = Vec::new();
    s.serialize_compressed(&mut compressed_bytes).unwrap();
    compressed_bytes
}


pub fn round_to_bytes(round: u64) -> [u8; 8] { // test : NOT DONE
    round.to_be_bytes()
}
pub fn str_to_byte(g_str: &str) -> Vec<u8> { // test : NOT DONE
    hex::decode(g_str).unwrap()
}
pub fn str_to_field<F : Field>(f_str : &str) -> F {
    let f_bytes = hex::decode(f_str).unwrap();
    F::deserialize_compressed(&*f_bytes).unwrap()
}

///
/// Consider the case with tow different length vectors
///
pub fn xor(a: &Vec<u8> , b: &Vec<u8> ) -> Vec<u8> {
    let len = a.len().max(b.len());
    let mut result = Vec::with_capacity(len);

    for i in 0..len {
        let byte_a = a.get(i).cloned().unwrap_or(0);
        let byte_b = b.get(i).cloned().unwrap_or(0);
        result.push(byte_a ^ byte_b);
    }
    result
}
