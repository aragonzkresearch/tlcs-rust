mod primitives;
mod key_share;

use primitives::*;
use key_share::*;


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


#[allow(unused)]
#[allow(dead_code)]
pub fn msk_calculation(sk_t : &G1Affine_L , key_shares : &Vec<KeyShare>) -> F {
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

fn main() {
    let k = key_share_gen();
    let b = verf_key_share(&k);
    println!("b = {}",b);
    let vrf_result_0 = sk_vrf(&k.pk_0[1],&k.t[1], &k.T_0[1] , &k.y_0[1]);
    let vrf_result_1 = sk_vrf(&k.pk_1[1],&k.t[1], &k.T_1[1] , &k.y_1[1]);

    println!("vrf_result_0 = {}",vrf_result_0);
    println!("vrf_result_1 = {}",vrf_result_1);

    let mut mpk = G::zero();
    mpk = mpk + &k.pk_0[0];
    mpk = mpk + &k.pk_1[0];
   // mpk = (20106700217463746305048032898949407617883523207135889272173868626673792621347,
    // 4804546012839924970484986554969310938967353593402702843218205218892929056231)


    /*for i in 0..K_SHARE{
        mpk = mpk + k.pk[i as usize]
    }

     */

    println!("mpk = {}",mpk);





}
