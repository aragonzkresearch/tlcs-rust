
use crate::key_share::*;
use crate::primitives::*;
use crate::hashes::*;
//use crate::bls_signature::*;

//#[allow(unused)]
//#[allow(dead_code)]
use ark_bls12_381::{
    Bls12_381,Fr as F_bls,
    G1Affine as G1Affine_bls, G2Affine as G2Affine_bls,
    G2Projective as G2Projective_bls, G1Projective as G1Projective_bls,
};
use ark_ec::{pairing::Pairing, CurveGroup, Group};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize,Valid};
use ark_std::{ops::Mul, rand::Rng, UniformRand, Zero};

pub fn key_share_store<E:Pairing>( key_share: &KeyShare<E>) -> Vec<u8>{
    let mut key_share_serialized_compressed = Vec::new();
    key_share
        .serialize_compressed(&mut key_share_serialized_compressed)
        .expect("Serialization should succeed");
    return key_share_serialized_compressed;
}

pub fn verify_key_share_store<E:Pairing> (key_share_stored: Vec<u8>, round : u64) ->bool{
    //type KS = KeyShare<E>;
    let ks = KeyShare::<E>::deserialize_compressed(
        key_share_stored.as_slice()
    )
        .expect("Deserialization should succeed");
    KeyShare::<E>::key_share_verify(&ks,round)
}

pub fn mpk_aggregation_from_stored_data<E: Pairing>(key_shares: &Vec<Vec<u8>>) ->Vec<u8>{
    //type KS = KeyShare<E>;
    let mut mpk = E::G1::zero();
    for k in key_shares{
        let key_share = KeyShare::<E>::deserialize_compressed(
            k.as_slice()
        )
            .expect("Deserialization should succeed");
        mpk = mpk + key_share.pk;
    }
    let mut mpk_serialized_compressed = Vec::new();
    mpk.serialize_compressed(&mut mpk_serialized_compressed)
        .expect("Serialization should succeed");
    mpk_serialized_compressed
}

pub fn msk_aggregation_from_stored_data<E: Pairing>(sk_t: &G1Affine_bls, key_shares: &Vec<Vec<u8>>) -> E::ScalarField {
    let mut msk = E::ScalarField::zero();
    for k in key_shares{
        let key_share = KeyShare::<E>::deserialize_compressed(
            k.as_slice()
        )
            .expect("Deserialization should succeed");
        let z_0 = Bls12_381::pairing(sk_t, &key_share.t_0[0]);
        let z_1 = Bls12_381::pairing(sk_t, &key_share.t_1[0]);

        let sk0 = xor(&hash_1::<Bls12_381>(z_0) , &key_share.y_0[0]);
        let sk1 = xor(&hash_1::<Bls12_381>(z_1) , &key_share.y_1[0]);
        let sk_0  = E::ScalarField ::deserialize_uncompressed(&*sk0).unwrap();
        let sk_1  = E::ScalarField ::deserialize_uncompressed(&*sk1).unwrap();
        msk = msk + sk_0;
        msk = msk + sk_1;
    }
    return msk;

}