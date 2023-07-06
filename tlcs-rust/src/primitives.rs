use ark_bls12_381::{
    Bls12_381, Fr as F_L, G1Affine as G1Affine_L, G1Projective as G1, G2Affine as G2Affine_L,
    G2Projective as G2,
};
use ark_bn254::{Fr as F, G1Affine, G1Projective as G, G2Affine, G2Projective};
use ark_ec::pairing::PairingOutput;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group};
use ark_ff::{Field, PrimeField};
use ark_secp256k1::Projective;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{ops::Mul, ops::Sub, UniformRand, Zero};

use std::sync::Arc;
use bit_vec::BitVec;
use rand::Rng;
use sha2::{Digest, Sha256};


pub type Party = u64;
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

pub fn hash_L(t: u128) -> G1 {
    G1::generator()
}

pub fn hash_1(g_target: PairingOutput<ark_ec::bls12::Bls12<ark_bls12_381::Config>>) -> Vec<u8> {
    let mut uncompressed_bytes = Vec::new();
    g_target
        .serialize_uncompressed(&mut uncompressed_bytes)
        .unwrap();

    let mut hasher = Sha256::new();
    hasher.update(uncompressed_bytes);
    let result = hasher.finalize();
    //format!("{:?}", result)
    let mut fixed_size_u8 = [0; 32];
    fixed_size_u8.copy_from_slice(result.as_ref());
    fixed_size_u8.to_vec()
}

pub fn hash_2(party: Party,
          pk: &G1Affine, pk_0_vec: &Vec<G>, pk_1_vec : &Vec<G>,
          T_0: &Vec<G2>, T_1: &Vec<G2>,
          y_0: &Vec<Vec<u8>>, y_1: &Vec<Vec<u8>>
) -> bit_vec::BitVec
{
    let mut hasher = Sha256::new();
    hasher.update(party.to_be_bytes());

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
    T_0.serialize_uncompressed(&mut uncompressed_bytes).unwrap();
    hasher.update(uncompressed_bytes);

    let mut uncompressed_bytes = Vec::new();
    T_1.serialize_uncompressed(&mut uncompressed_bytes).unwrap();
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

pub fn field_gen() -> F_L {
    //let mut rng = rand::thread_rng();
    let mut rng = ark_std::test_rng(); // change test for the final version
    <G2 as Group>::ScalarField::rand(&mut rng)
}
pub fn group1_gen() -> G1Affine_L {
    //let mut rng = ark_std::test_rng(); // change test for the final version
    //let f = <G1 as Group>::ScalarField::rand(&mut rng);
    let g = <G1 as Group>::generator();
    let PK = g.mul(field_gen()).into_affine();
    return PK;
}

pub fn group2_gen() -> G2Affine_L {
    let g = <G2 as Group>::generator();
    let PK = g.mul(field_gen()).into_affine();
    return PK;
}
pub fn str_filed(g_str: &str) -> F_L {
    let g_bytes = hex::decode(g_str).unwrap();
    println!("g_byte : {:?}", g_bytes);
    let g = F_L::deserialize_compressed(&*g_bytes).unwrap();
    println!("g : {}", g);
    return g;
}

pub fn compute_z()-> Vec<u8>{
    let g1 = group1_gen();
    let g2 = group2_gen();
    let e = Bls12_381::pairing(g1, g2);
    // println!("e(g1,g2) before serializign : {}", e);
    let mut e_bytes = Vec::new();
    e.serialize_compressed(&mut e_bytes).unwrap();
    //println!("e1 after serializign : {:?}", e_bytes);
    //println!(" e1.len={}", e_bytes.len());
    let e_hex = hex::encode(e_bytes);
    //println!("e = 0x{}", e_hex);
    hash_1(e)
}

pub fn seri_compressed_f(s: &F) -> Vec<u8>{
    let mut compressed_bytes = Vec::new();
    s.serialize_compressed(&mut compressed_bytes).unwrap();
    println!("compressed_bytes: {:?}",compressed_bytes);
    return compressed_bytes;
}

pub fn seri_uncompressed(s: &F) -> Vec<u8>{
    let mut uncompressed_bytes = Vec::new();
    s.serialize_uncompressed(&mut uncompressed_bytes).unwrap();
    println!("uncompressed_bytes: {:?}",uncompressed_bytes);
    return uncompressed_bytes;
}


pub fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}

/*
fn main() {
    let s = "Hello";
    let i = 42;

    print_type_of(&s); // &str
    print_type_of(&i); // i32
    print_type_of(&main); // playground::main
    print_type_of(&print_type_of::<i32>); // playground::print_type_of<i32>
    print_type_of(&{ || "Hi!" }); // playground::main::{{closure}}
}
 */