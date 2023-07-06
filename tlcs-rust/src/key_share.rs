

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
pub const K_SHARE: u32 = 2; // 10 is only a example
pub const TIME: u128 = 100; // 100 only an example

#[derive(CanonicalSerialize)]
#[derive(Debug)]
pub struct KeyShare{//<C: ark_ec::CurveGroup, D: ark_ec::CurveGroup> {
    pub party: u64, //this can be considered as the id
    pub pk: G,
    pub pk_0: Vec<G>,
    pub pk_1: Vec<G>,
    pub sk : SecretKey<G>,
    pub sk_0: Vec<SecretKey<G>>,
    pub sk_1: Vec<SecretKey<G>>,
    pub t: Vec<SecretKey<G2>>,
    pub T_0: Vec<G2>,
    pub T_1: Vec<G2>,
    pub y_0: Vec<Vec<u8>>,
    pub y_1: Vec<Vec<u8>>,
   // pub z : Vec<PairingOutput<ark_ec::bls12::Bls12<ark_bls12_381::Config>>>,
}

pub fn key_share_gen( )-> KeyShare{
    let party :Party = 123;
    let g = <G as Group>::generator();
    let mut rng = ark_std::test_rng(); // change test for the final version
    let Sk = <G as Group>::ScalarField::rand(&mut rng);
    let mut PK = g.mul(Sk).into_affine();
    let mut pk_vector_0: Vec<G> = Vec::new();
    let mut pk_vector_1: Vec<G> = Vec::new();
    let mut sk_vector_0: Vec<<G as Group>::ScalarField> = Vec::new();
    let mut sk_vector_1: Vec<<G as Group>::ScalarField> = Vec::new();
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
        let sk_1 = &Sk - &sk_0;


        pk_vector_0.push(g.mul(&sk_0).into());
        pk_vector_1.push(g.mul(&sk_1).into());


        sk_vector_0.push(sk_0);
        sk_vector_1.push(sk_1);
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
    let key_share: KeyShare = KeyShare{
        party: party, //this can be considered as the id
        pk: PK.into(),
        pk_0: pk_vector_0,
        pk_1: pk_vector_1,
        t: t_vector,
        T_0:  T_vector_0,
        T_1:  T_vector_1,
        y_0: y_vector_0,
        y_1: y_vector_1,
        sk: Sk,
        sk_0: sk_vector_0,
        sk_1: sk_vector_1,
    };
    return key_share;
    // println!("T_vector_0 = {:?}", T_vector_0);
    // println!("T_vector_1 = {:?}", T_vector_1);
    // println!("y_vector_0 = {:?}", y_vector_0);
    // println!("y_vector_0 = {:?}", y_vector_0);
}

pub fn sk_vrf( pk: &G, t: &<G2 as Group>::ScalarField , T : &G2, y : &Vec<u8>) -> bool{
    let PK_L: G2 = G2::generator();
    let g = G::generator();
    let g2 = G2::generator();
    if g2.mul(t) != *T{
        return false
    }

    let Z = Bls12_381::pairing(hash_L(TIME), PK_L.mul(t));
    let sk0 = xor(&hash_1(Z) , y);
    let sk  = F::deserialize_uncompressed(&*sk0).unwrap();
    if *pk != g.mul(sk){
        return false;
    }
    true
}

pub fn verf_key_share(k: &KeyShare) -> bool{
    //let k = key_share_gen();
    //println!("the key = {:?}", k);
    let t = &k.pk_0[0] + &k.pk_1[0];
    let a = &k.pk;
    //println!("t= {}",t);
    //println!("a= {}",a);
    print_type_of(&t);
    print_type_of(&a);
    let g2 = G2::generator();

    for i in 0..K_SHARE{
        if &k.pk_0[i as usize] + &k.pk_1[i as usize] != *&k.pk {
            return false
        }
    }

    let hash_vrf = hash_2(k.party,&k.pk.into_affine(),
                          &k.pk_0,&k.pk_1,
                          &k.T_0,&k.T_1,
                          &k.y_0,&k.y_1);


    let first_k_bits_vrf : Vec<bool>= hash_vrf
        .iter()
        .take(K_SHARE as usize)
        .collect();


    for i in 0..K_SHARE{
        for bit in first_k_bits_vrf.iter() {
            let vrf_result = match bit {
                true =>  sk_vrf(&k.pk_1[i as usize],&k.t[i as usize], &k.T_1[i as usize] , &k.y_1[i as usize]),
                false => sk_vrf(&k.pk_0[i as usize],&k.t[i as usize], &k.T_0[i as usize] , &k.y_0[i as usize]),
                _ => panic!("Invalid bit value"),
            };
            if  !vrf_result{
                return vrf_result;
            }
        }
    }

    true
}
pub fn mpk_aggregation(key_shares : &Vec<KeyShare>) -> G {
    let mut mpk = G::zero();
    for i in 0..key_shares.len(){
        mpk = mpk + &key_shares[i as usize].pk;
    }
    return mpk;
}
pub fn msk_aggregation(sk_t : &G1Affine_L , key_shares : &Vec<KeyShare>) -> F {
    let mut msk = F::zero();

    for i in 0..key_shares.len(){
        let Z_0 = Bls12_381::pairing(sk_t, &key_shares[i as usize].T_0[0]);
        let Z_1 = Bls12_381::pairing(sk_t, &key_shares[i as usize].T_1[0]);

        let sk0 = xor(&hash_1(Z_0) , &key_shares[i as usize].y_0[0]);
        let sk1 = xor(&hash_1(Z_1) , &key_shares[i as usize].y_1[0]);
        let sk_0  = F::deserialize_uncompressed(&*sk0).unwrap();
        let sk_1  = F::deserialize_uncompressed(&*sk1).unwrap();
        msk = msk + sk_0;
        msk = msk + sk_1;
    }
    return msk;

}
