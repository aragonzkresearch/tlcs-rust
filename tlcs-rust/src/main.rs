#[allow(unused)]
#[allow(dead_code)]
use std::sync::Arc;

use ark_bls12_381::{
    Bls12_381, Fr as F_L, G1Affine as G1Affine_L, G1Projective as G1, G2Affine as G2Affine_L,
    G2Projective as G2,
};

use ark_mnt6_753::{Fr as F, G1Affine, G1Projective as G, MNT6_753};
use ark_bn254::G1Projective;
use ark_ec::pairing::PairingOutput;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group};

use ark_ff::{Field, PrimeField};
use ark_secp256k1::Projective;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{ops::Mul, ops::Sub, UniformRand, Zero};
use bit_vec::BitVec;
use rand::Rng;
use sha2::{Digest, Sha256};

const K_SHARE: u32 = 2; // 10 is only a example
const TIME: u128 = 100; // 100 only an example

pub struct Parameters<C: CurveGroup> {
    pub generator: C,
}
pub type Party = u64;
pub type PublicKey<C> = C;
pub type SecretKey<C> = <C as Group>::ScalarField;

#[derive(CanonicalSerialize)]
struct KeyShare<C: ark_ec::CurveGroup, D: ark_ec::CurveGroup> {
    party: u64, //this can be considered as the id
    pk: PublicKey<D>,
    pk_0: Vec<PublicKey<D>>,
    pk_1: Vec<PublicKey<D>>,
    t: Vec<<C as Group>::ScalarField>,
    //first_k_bits    : Vec<<G2 as Group>::ScalarField>,
    T_0: Vec<PublicKey<C>>,
    T_1: Vec<PublicKey<C>>,
    y_0: Vec<String>,
    y_1: Vec<String>,
}

pub fn hash_L(t: u128) -> G1 {
    G1::generator()
}

fn hash_1(g_target: PairingOutput<ark_ec::bls12::Bls12<ark_bls12_381::Config>>) -> [u8; 32] {
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
    fixed_size_u8
}

fn hash_2(party: Party,
           pk: G1Affine, pk_0_vec: &Vec<G1Affine>, pk_1_vec : &Vec<G1Affine>,
           T_0: &Vec<G2>, T_1: &Vec<G2>,
           y_0: &Vec<String>, y_1: &Vec<String>
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

fn xor_strings(
    z: [u8; 32],
    f : F
) -> String {
    /*
    let s1_bytes = z_0;
   // let mut s2_bytes = Vec::new();
   // sk.serialize_uncompressed(&mut s2_bytes).unwrap();
    //let min_len = std::cmp::min(s1_bytes.len(), s2_bytes.len());

    let xor_result: Vec<u8> = s1_bytes
        .iter()
        .zip(s2_bytes.iter())
        .take(sk)
        .map(|(&b1, &b2)| b1 ^ b2)
        .collect();
    println!("str : {:?}", xor_result);
    String::from_utf8(xor_result).unwrap()

     */
    let f_num: num_bigint::BigUint = f.into();

    let f_bytes = F::from_le_bytes_mod_order(&f_num.to_bytes_le());
    //  let b_bytes = Fr::from_le_bytes_mod_order(&b_num.to_bytes_le());

    //let c_xor = a_num.to_bytes_le() ^ b_num.to_bytes_le();
    let xor_result: Vec<u8> = f_num.to_bytes_le().iter()
        .zip(z.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();


    xor_result.iter()
        .map(|byte| format!("{:02X}", byte))
        .collect()
}

fn leo_setup(){

}

fn main() {
    println!("HELLO!");

    let party :Party = 123;
    let g = <G as Group>::generator();
    let mut rng = ark_std::test_rng(); // change test for the final version
    let sk = <G as Group>::ScalarField::rand(&mut rng);
    let mut PK = g.mul(sk).into_affine();

        let mut pk_vector_0: Vec<G1Affine> = Vec::new();
        let mut pk_vector_1: Vec<G1Affine> = Vec::new();
        let mut t_vector_0: Vec<<G2 as Group>::ScalarField> = Vec::new();
        let mut t_vector_1: Vec<<G2 as Group>::ScalarField> = Vec::new();
        let mut y_vector_0: Vec<String> = Vec::new();
        let mut y_vector_1: Vec<String> = Vec::new();
        let mut T_vector_0: Vec<G2> = Vec::new();
        let mut T_vector_1: Vec<G2> = Vec::new();
        let g2 = G2::generator();
        let PK_L: G2 = G2::generator();

        for i in 0..K_SHARE {
            let sk_0 = <G as Group>::ScalarField::rand(&mut rng);
            let sk_1 = &sk - &sk_0;
            pk_vector_0.push(g.mul(&sk_0).into());
            pk_vector_1.push(g.mul(&sk_1).into());
            let t_0 = <G2 as Group>::ScalarField::rand(&mut rng);
            let t_1 = <G2 as Group>::ScalarField::rand(&mut rng);
            T_vector_0.push(g2.mul(&t_0));
            T_vector_1.push(g2.mul(&t_1));
            let Z_0 = Bls12_381::pairing(hash_L(TIME), PK_L.mul(&t_0));
            let Z_1 = Bls12_381::pairing(hash_L(TIME), PK_L.mul(&t_1));
            t_vector_0.push(t_0);
            t_vector_1.push(t_1);
            println!("HERE01!");
            let y_0 = xor_strings(hash_1(Z_0), sk_0);
            let y_1 = xor_strings(hash_1(Z_1), sk_1);
            y_vector_0.push(y_0);
            y_vector_1.push(y_1);
        }
   //hash_2(party, PK,pk_0,pk_1,T_),T_!,y_0,y_1);
    let hash_val = hash_2(party,PK,
                          &pk_vector_0,&pk_vector_1,
                          &T_vector_0,&T_vector_1,
                          &y_vector_0,&y_vector_1);
    println!("{:?}",pk_vector_0);
    println!("{:?}",pk_vector_1);
    println!("{:?}",pk_vector_1);
    println!("{:?}",y_vector_0);
    println!("{:?}",y_vector_1);
    println!("{:?}",T_vector_0);
    println!("{:?}",T_vector_1);
    println!("hash_val: {:?}, {:?}",hash_val, hash_val.len());

    let first_k_bits : Vec<<G2 as Group>::ScalarField>= hash_val
        .iter()
        .take(K_SHARE as usize)
        .enumerate()
        .map(|(i, val)| match val {
            false => t_vector_0[i],
            true => t_vector_1[i],
            _ => panic!("Invalid value in c vector"),
        })
        .collect();

    let key: KeyShare::<G1,G>{
        party: party,
        pk: PublicKey<D>,
        pk_0: Vec<PublicKey<D>>,
        pk_1: Vec<PublicKey<D>>,
        t: Vec<<C as Group>::ScalarField>,
        T_0: Vec<PublicKey<C>>,
        T_1: Vec<PublicKey<C>>,
        y_0: Vec<String>,
        y_1: Vec<String>

    };


    println!("first_k_ones: {:?}", first_k_bits);

}

