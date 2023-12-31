//use ark_ec::pairing::Pairing;
//use ark_ec::pairing::PairingOutput;

//use ark_std::{ops::Mul, UniformRand};

//use bit_vec::BitVec;
//use sha2::{Digest, Sha256};
//use ark_ec::{CurveGroup, Group};
//use ark_serialize::CanonicalDeserialize;
use ark_ec::{
     AffineRepr, CurveGroup,  short_weierstrass::Affine as Affine, short_weierstrass::SWCurveConfig
};
use ark_ff::Field;
//use hex::ToHex;
use std::fmt;
//use rand::{thread_rng, Rng};
// delete for real
use num_bigint::{BigUint, ParseBigIntError};
use num_integer::Integer;
use num_traits::Num;
//use ark_ed_on_bn254::{EdwardsProjective as tlcs_curve_bjj, EdwardsAffine as affin_bjj,  Fr as Fr_tlcs_bjj, EdwardsConfig};

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

#[allow(unused)]
pub fn byte_to_group<G: CurveGroup>(g_bytes: Vec<u8>) -> Result<G, InvalidPoint> {
    // test : NOT DONE
    Option::from(G::deserialize_compressed(&*g_bytes).unwrap()).ok_or(InvalidPoint)
}

#[allow(unused)]
pub fn group_compressed_format<G: CurveGroup>(g: &G) -> String {
    // println!("g= {}", g);
    let g_affine = g.into_affine();
    //println!("g_affine = {}", g_affine);
    let g_x :String = g_affine.x().unwrap().to_string();
    let g_y = g_affine.y().unwrap();
    //println!("g_x = {}", g_x);
    //println!("g_y = {}", g_y);
    let g_bignum = BigUint::from_str_radix(g_x.as_str(), 10).unwrap();
    let g_compressed = match g_y.to_string().chars().last().unwrap().to_digit(10).unwrap().is_even(){
        true  => format!("0x02{:x}", g_bignum),
        false => format!("0x03{:x}", g_bignum),
    };
    return g_compressed;
}


#[allow(unused)]
pub fn group_from_compressed<G: CurveGroup+ std::convert::From<ark_ec::short_weierstrass::Projective<<G as ark_ec::CurveGroup>::Config>>>(g_str : &str) -> G
    where <G as CurveGroup>::Config: SWCurveConfig,  <G as CurveGroup>::BaseField: From<BigUint>{
    let (g_hex_str , is_even) : (&str, bool) = match g_str {
        s if s.starts_with("0x02") || s.starts_with("0X02") => {
            (&s[4..], true)
        },
        s if s.starts_with("0x03") || s.starts_with("0X03") => {
            (&s[4..], false)
        },
        _ => ("0", false),
    };
    let g_big_int = hex_to_bignum(&g_hex_str).unwrap();
    let g_x = g_big_int.into();
    let (y_0 , y_1)  = <ark_ec::short_weierstrass::Affine<G::Config>>::get_ys_from_x_unchecked(g_x).unwrap();
    let y_is_even = y_0.to_string().chars().last().unwrap().to_digit(10).unwrap().is_even();
    let g_y = match is_even ^ y_is_even{
        true  => y_1,
        false => y_0,
    };
    let g  = <Affine<G::Config>>::new(g_x,g_y);
    return g.into_group().into();
}

#[allow(unused)]
pub fn group_to_hex<G: CurveGroup>(g: &G) -> String {
    let mut g_bytes = Vec::new();
    g.serialize_compressed(&mut g_bytes).unwrap();
    let g_hex = hex::encode(g_bytes);
    g_hex
}
#[allow(unused)]
pub fn hex_to_bignum(hex_str: &str) -> Result<BigUint, ParseBigIntError> {
    BigUint::from_str_radix(hex_str, 16)
}
#[allow(unused)]
pub fn group_to_byte<G: CurveGroup>(g: &G) -> Vec<u8> {
    // test : NOT DONE
    let mut g_bytes = Vec::new();
    //g.serialize_compressed(&mut g_bytes).unwrap();
    g.serialize_uncompressed(&mut g_bytes).unwrap();
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
