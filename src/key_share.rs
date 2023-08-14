use crate::primitives::*;
use crate::hashes::*;
//use crate::bls_signature::*;

//#[allow(unused)]
//#[allow(dead_code)]

#[allow(unused)]
use ark_bls12_381::{
    Bls12_381, Fr as F_L, G1Affine as G1Affine_L, G1Projective as G1Projective_L, G2Affine as G2Affine_L,
    G2Projective as G2Projective_L,
};
use ark_bn254::{Fr , G1Projective};
use ark_ec::{pairing::Pairing, CurveGroup, Group};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::Mul, UniformRand, Zero};

//pub struct Parameters<C: CurveGroup> {
//    pub generator: C,
//}
//pub type PublicKey<C> = C;
pub type SecretKey<C> = <C as Group>::ScalarField;

pub const K_SHARE: u32 = 2;
pub const TIME: u64 = 100;

#[derive(CanonicalSerialize)]
#[derive(Debug)]
pub struct KeyShare{//<C: ark_ec::CurveGroup, D: ark_ec::CurveGroup> {
//pub party: u64, //this can be considered as the id (the round)
pub pk: G1Projective,
    pub pk_0: Vec<G1Projective>,
    pub pk_1: Vec<G1Projective>,
    pub sk : SecretKey<G1Projective>,
    pub sk_0: Vec<SecretKey<G1Projective>>,
    pub sk_1: Vec<SecretKey<G1Projective>>,
    pub t: Vec<SecretKey<G2Projective_L>>,
    pub t_0: Vec<G2Projective_L>,
    pub t_1: Vec<G2Projective_L>,
    pub y_0: Vec<Vec<u8>>,
    pub y_1: Vec<Vec<u8>>,
}

pub fn key_share_gen(
   // party: u64,
)-> KeyShare{
    let g = <G1Projective as Group>::generator();
    let mut rng = ark_std::test_rng(); // change test for the final version
    let secret_key = <G1Projective as Group>::ScalarField::rand(&mut rng);
    let private_key = g.mul(secret_key).into_affine();
    let mut pk_vector_0: Vec<G1Projective> = Vec::new();
    let mut pk_vector_1: Vec<G1Projective> = Vec::new();
    let mut sk_vector_0: Vec<<G1Projective as Group>::ScalarField> = Vec::new();
    let mut sk_vector_1: Vec<<G1Projective as Group>::ScalarField> = Vec::new();
    let mut t_vector_0: Vec<<G2Projective_L as Group>::ScalarField> = Vec::new();

    let mut t_vector_1: Vec<<G2Projective_L as Group>::ScalarField> = Vec::new();
    let mut y_vector_0: Vec<Vec<u8>> = Vec::new();
    let mut y_vector_1: Vec<Vec<u8>> = Vec::new();

    let mut v_vector_0: Vec<G2Projective_L> = Vec::new();
    let mut v_vector_1: Vec<G2Projective_L> = Vec::new();

    let g2 = G2Projective_L::generator();
    let pk_l: G2Projective_L = G2Projective_L::generator();

    for _ in 0..K_SHARE {
        let sk_0 = <G1Projective as Group>::ScalarField::rand(&mut rng);
        let sk_1 = &secret_key - &sk_0;
        pk_vector_0.push(g.mul(&sk_0).into());
        pk_vector_1.push(g.mul(&sk_1).into());
        sk_vector_0.push(sk_0);
        sk_vector_1.push(sk_1);
        let t_0 = <G2Projective_L as Group>::ScalarField::rand(&mut rng);
        let t_1 = <G2Projective_L as Group>::ScalarField::rand(&mut rng);
        v_vector_0.push(g2.mul(&t_0));
        v_vector_1.push(g2.mul(&t_1));
        let z_0 = Bls12_381::pairing(hash_loe_g1(&round_to_bytes(TIME)), pk_l.mul(&t_0));
        let z_1 = Bls12_381::pairing(hash_loe_g1(&round_to_bytes(TIME)), pk_l.mul(&t_1));
        t_vector_0.push(t_0);
        t_vector_1.push(t_1);
        let sk_ser_0 = seri_compressed_f(&sk_0);
        let sk_ser_1 = seri_compressed_f(&sk_1);
        let y_0 = xor(&hash_1(z_0), &sk_ser_0);
        let y_1 = xor(&hash_1(z_1), &sk_ser_1);
        y_vector_0.push(y_0);
        y_vector_1.push(y_1);
    }

    let hash_val = hash_2(&private_key,
                          &pk_vector_0,&pk_vector_1,
                          &v_vector_0,&v_vector_1,
                          &y_vector_0,&y_vector_1);


    let t_vector: Vec<<G2Projective_L as Group>::ScalarField>= hash_val
        .iter()
        .take(K_SHARE as usize)
        .enumerate()
        .map(|(i, val)| match val {
            false => t_vector_0[i],
            true => t_vector_1[i],
            //_ => panic!("Invalid value in c vector"),
        })
        .collect();

    let key_share: KeyShare = KeyShare{
        //party: party, //this can be considered as the id
        pk: private_key.into(),
        pk_0: pk_vector_0,
        pk_1: pk_vector_1,
        t: t_vector,
        t_0:  v_vector_0,
        t_1:  v_vector_1,
        y_0: y_vector_0,
        y_1: y_vector_1,
        sk: secret_key,
        sk_0: sk_vector_0,
        sk_1: sk_vector_1,
    };
    return key_share;
}

pub fn sk_vrf(
    pk: &G1Projective,
    t1: &<G2Projective_L as Group>::ScalarField,
    t2: &G2Projective_L,
    y: &Vec<u8>
) -> bool{
    let pk_l: G2Projective_L = G2Projective_L::generator();
    let g = G1Projective::generator();
    let g2 = G2Projective_L::generator();

    if g2.mul(t1) != *t2{
        return false
    }


    let z = Bls12_381::pairing(hash_loe_g1(&round_to_bytes(TIME)), pk_l.mul(t1));
    let sk0 = xor(&hash_1(z) , y);
    let sk  = Fr::deserialize_uncompressed(&*sk0).unwrap();
    if *pk != g.mul(sk){
        return false;
    }
    true
}

pub fn verf_key_share(k: &KeyShare) -> bool{
    //let k = key_share_gen();
    //let t = &k.pk_0[0] + &k.pk_1[0];
    //let a = &k.pk;
    //let g2 = G2::generator();

    for i in 0..K_SHARE{
        if &k.pk_0[i as usize] + &k.pk_1[i as usize] != *&k.pk {
            return false
        }
    }

    let hash_vrf = hash_2(//k.party,
                          &k.pk.into_affine(),
                          &k.pk_0,&k.pk_1,
                          &k.t_0,&k.t_1,
                          &k.y_0,&k.y_1);

    let first_k_bits_vrf : Vec<bool>= hash_vrf
        .iter()
        .take(K_SHARE as usize)
        .collect();


    for i in 0..K_SHARE{
        for bit in first_k_bits_vrf.iter() {
            let vrf_result = match bit {
                true =>  sk_vrf(&k.pk_1[i as usize],&k.t[i as usize], &k.t_1[i as usize] , &k.y_1[i as usize]),
                false => sk_vrf(&k.pk_0[i as usize],&k.t[i as usize], &k.t_0[i as usize] , &k.y_0[i as usize]),
                //_ => panic!("Invalid bit value"),
            };
            if  !vrf_result{
                return vrf_result;
            }
        }
    }

    true
}

pub fn mpk_aggregation(key_shares : &Vec<KeyShare>) -> G1Projective  {
    let mut mpk = G1Projective::zero();
    for i in 0..key_shares.len(){
        mpk = mpk + &key_shares[i as usize].pk;
    }
    return mpk;
}

#[allow(unused)]
pub fn msk_aggregation(sk_t : &G1Affine_L , key_shares : &Vec<KeyShare>) -> Fr {
    let mut msk = Fr::zero();
    for i in 0..key_shares.len(){
        let z_0 = Bls12_381::pairing(sk_t, &key_shares[i as usize].t_0[0]);
        let z_1 = Bls12_381::pairing(sk_t, &key_shares[i as usize].t_1[0]);

        let sk0 = xor(&hash_1(z_0) , &key_shares[i as usize].y_0[0]);
        let sk1 = xor(&hash_1(z_1) , &key_shares[i as usize].y_1[0]);
        let sk_0  = Fr::deserialize_uncompressed(&*sk0).unwrap();
        let sk_1  = Fr::deserialize_uncompressed(&*sk1).unwrap();
        msk = msk + sk_0;
        msk = msk + sk_1;
    }
    return msk;

}