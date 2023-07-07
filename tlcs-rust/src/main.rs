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
use rand::Rng;
use sha2::{Digest, Sha256};

#[allow(unused)]
#[allow(dead_code)]

fn main() {
    /*
    let k = key_share_gen();
    let b = verf_key_share(&k);

    let mut k_vec : Vec<KeyShare> = Vec::new();
    k_vec.push(k);


    let mpk = mpk_aggregation(&k_vec);

     */

    let mut hasher = Sha256::new();
    hasher.update(1.into());
    println!("hasher = {}", hasher);

    //let msk = msk_aggregation();

}
//Round = 3657496, hash = 405597ed3520b1b413cee9426fb0e8b74d20e0b40d843bb4641a1e5edf2fa595
//Round = 1 hash _value = cd2662154e6d76b2b2b92e70c0cac3ccf534f9b74eb5b89819ec509083d00a50

