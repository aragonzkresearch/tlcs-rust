

use crate::primitives::*;

#[allow(unused)]
#[allow(dead_code)]

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

pub struct Parameters<C: CurveGroup> {
    pub generator: C,
}
pub type PublicKey<C> = C;
pub type SecretKey<C> = <C as Group>::ScalarField;
const K_SHARE: u32 = 2; // 10 is only a example
const TIME: u128 = 100; // 100 only an example

#[derive(CanonicalSerialize)]
#[derive(Debug)]
struct KeyShare{//<C: ark_ec::CurveGroup, D: ark_ec::CurveGroup> {
    party: u64, //this can be considered as the id
    pk: PublicKey<G>,
    pk_0: Vec<PublicKey<G>>,
    pk_1: Vec<PublicKey<G>>,
    t: Vec<SecretKey<G2>>,
    T_0: Vec<G2>,
    T_1: Vec<G2>,
    y_0: Vec<Vec<u8>>,
    y_1: Vec<Vec<u8>>,
}
pub fn key_share_gen( ){
    let party :Party = 123;
    let g = <G as Group>::generator();
    let mut rng = ark_std::test_rng(); // change test for the final version
    let sk = <G as Group>::ScalarField::rand(&mut rng);
    let mut PK = g.mul(sk).into_affine();
    let mut pk_vector_0: Vec<G> = Vec::new();
    let mut pk_vector_1: Vec<G> = Vec::new();
    let mut t_vector_0: Vec<<G2 as Group>::ScalarField> = Vec::new();
    let mut t_vector_1: Vec<<G2 as Group>::ScalarField> = Vec::new();
    let mut y_vector_0: Vec<Vec<u8>> = Vec::new();
    let mut y_vector_1: Vec<Vec<u8>> = Vec::new();
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

        let sk_ser_0 = seri_compressed_f(&sk_0);
        let sk_ser_1 = seri_compressed_f(&sk_1);

        let y_0 = xor(&hash_1(Z_0), &sk_ser_0);
        let y_1 = xor(&hash_1(Z_1), &sk_ser_1);
        y_vector_0.push(y_0);
        y_vector_1.push(y_1);
    }

    let hash_val = hash_2(party,&PK,
                          &pk_vector_0,&pk_vector_1,
                          &T_vector_0,&T_vector_1,
                          &y_vector_0,&y_vector_1);


    let t_vector: Vec<<G2 as Group>::ScalarField>= hash_val
        .iter()
        .take(K_SHARE as usize)
        .enumerate()
        .map(|(i, val)| match val {
            false => t_vector_0[i],
            true => t_vector_1[i],
            _ => panic!("Invalid value in c vector"),
        })
        .collect();
    println!("Here");
    /*
        let key_share = KeyShare{
            party: party,
            pk: PK.into(),
            pk_0: pk_vector_0,
            pk_1: pk_vector_1,
            t: first_k_bits,
            T_0: T_vector_0,
            T_1: T_vector_1,
            y_0: y_vector_0,
            y_1: y_vector_1,
        };

     */
    println!("party = {}", party);
    println!("pk = {}", PK);
    println!("pk_0 = {:?}", pk_vector_1);
    println!("pk_1 = {:?}", pk_vector_1);
    println!("t = {:?}", t_vector);
    // println!("T_vector_0 = {:?}", T_vector_0);
    // println!("T_vector_1 = {:?}", T_vector_1);
    // println!("y_vector_0 = {:?}", y_vector_0);
    // println!("y_vector_0 = {:?}", y_vector_0);
}
pub fn key_share_vrfy(key_share: &KeyShare) {
    let a = key_share.party;
    let b = key_share.pk_0;

    println!("a : {}",a);
    println!("b : {}",b);
    println!("key_share.pk_1 : {:?}",key_share.pk_1);

    /*

    for i in 0..K_SHARE{
        if pk_vector_0[i as usize] + pk_vector_1[i as usize] != PK {
            println!("FALSE");
        } else {
            println!("TRUE");
        }
    }
    let hash_vrf = hash_2(party,&PK,
                          &pk_vector_0,&pk_vector_1,
                          &T_vector_0,&T_vector_1,
                          &y_vector_0,&y_vector_1);
    println!("hash_vrf = {:?}",hash_vrf);

    */
}