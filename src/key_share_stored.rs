use crate::hashes::*;
use crate::key_share::*;
use crate::primitives::*;
//use crate::bls_signature::*;

//#[allow(unused)]
//#[allow(dead_code)]
use ark_bls12_381::{
    Bls12_381,
    //Fr as F_bls,
    G1Affine as G1Affine_bls,
    //G2Affine as G2Affine_bls,
    //G2Projective as G2Projective_bls, G1Projective as G1Projective_bls,
};
use ark_ec::pairing::Pairing;
use ark_serialize::{
    CanonicalDeserialize,
    CanonicalSerialize,
    //    Valid
};
//use ark_std::{ops::Mul, rand::Rng, UniformRand, Zero};
use ark_std::Zero;

const LOE_PUBLIC_KEY: [u8; 96] = hex!("a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e";

/******************************************************************************************
** The four functions needed by the chain
******************************************************************************************/

pub fn keyshare_generate(
    round: u64,
    _scheme: u32,
    loe_pk: Vec<u8>,
) -> Vec<u8> {
    // Make key from round and loe_pk
    let mut rng = ark_std::test_rng();
    let loe_pk_str = hex::encode(loe_pk);
    let key: KeyShare = key_share_gen(&mut rng, &loe_pk_str, round);

    return key_share_store(&key);
}

pub fn keyshare_verify(
    round: u64,
    _scheme: u32,
    data: Vec<u8>,
) -> bool {
    return verify_key_share_store(data, round);
}

pub fn make_aggregate_key(
    round: u64,
    _scheme: u32,
    all_data: Vec<Vec<u8>>,
) -> Vec<u8> {
    pk_vec = mpk_aggregation_from_stored_data(&all_data);
    return hex::encode(pk_vec);
}

pub fn make_secret_key(
    round: u64,
    _scheme: u32,
    signature: Vec<u8>,
    all_data: Vec<Vec<u8>>,
    pubkey: String,
) -> Vec<u8> {
    sk_vec = msk_aggregation_from_stored_data(all_data);
    return hex::encode(sk_vec);
}

/******************************************************************************************/

#[allow(dead_code)]
fn key_share_store<E: Pairing>(key_share: &KeyShare<E>) -> Vec<u8> {
    let mut key_share_serialized_compressed = Vec::new();
    key_share
        .serialize_compressed(&mut key_share_serialized_compressed)
        .expect("Serialization should succeed");
    return key_share_serialized_compressed;
}

#[allow(dead_code)]
pub fn verify_key_share_store<E: Pairing>(key_share_stored: Vec<u8>, round: u64) -> bool {
    let ks = KeyShare::<E>::deserialize_compressed(key_share_stored.as_slice())
        .expect("Deserialization should succeed");
    KeyShare::<E>::key_share_verify(&ks, round)
}

#[allow(dead_code)]
pub fn mpk_aggregation_from_stored_data<E: Pairing>(key_shares: &Vec<Vec<u8>>) -> Vec<u8> {
    //type KS = KeyShare<E>;
    let mut mpk = E::G1::zero();
    for k in key_shares {
        let key_share = KeyShare::<E>::deserialize_compressed(k.as_slice())
            .expect("Deserialization should succeed");
        mpk = mpk + key_share.pk;
    }
    let mut mpk_serialized_compressed = Vec::new();
    mpk.serialize_compressed(&mut mpk_serialized_compressed)
        .expect("Serialization should succeed");
    mpk_serialized_compressed
}

#[allow(dead_code)]
pub fn msk_aggregation_from_stored_data<E: Pairing>(
    sk_t: &G1Affine_bls,
    key_shares: &Vec<Vec<u8>>,
) -> E::ScalarField {
    let mut msk = E::ScalarField::zero();
    for k in key_shares {
        let key_share = KeyShare::<E>::deserialize_compressed(k.as_slice())
            .expect("Deserialization should succeed");
        let z_0 = Bls12_381::pairing(sk_t, &key_share.t_0[0]);
        let z_1 = Bls12_381::pairing(sk_t, &key_share.t_1[0]);

        let sk0 = xor(&hash_1::<Bls12_381>(z_0), &key_share.y_0[0]);
        let sk1 = xor(&hash_1::<Bls12_381>(z_1), &key_share.y_1[0]);
        let sk_0 = E::ScalarField::deserialize_uncompressed(&*sk0).unwrap();
        let sk_1 = E::ScalarField::deserialize_uncompressed(&*sk1).unwrap();
        msk = msk + sk_0;
        msk = msk + sk_1;
    }
    return msk;
}

#[cfg(test)]
mod tests {
│   use serial_test::serial;
│
│   use super::*;
│
│   #[test]
│   #[serial]
│   fn verify_participant_data_works() {
│   │   let participant_data = keyshare_generate(2, 1, LOE_PUBLIC_KEY);
│   │   let verified = keyshare_verify(2, 1, participant_data);
│   │
│   │   assert!(verified);
│   }
│
│   #[test]
│   #[serial]
│   fn aggregate_participant_data_works() {
│   │   let mut all_participant_data = keyshare_generate(2, 1, LOE_PUBLIC_KEY);
│   │   let mut participant_data_2 = keyshare_generate(2, 1, LOE_PUBLIC_KEY);
│   │   all_participant_data.append(&mut participant_data_2);

│   │   let public_key = make_aggregate_key(all_participant_data);
│   │   let vec_public_key = hex::decode(public_key).expect("will return valid hex");
│   │
│   │   assert!(vec_public_key.len() == 33)
│   }
│
│   #[test]
│   #[serial]
│   fn make_secret_key_works() {
│   │   let mut all_participant_data = keyshare_generate(2);
│   │   let mut participant_data_2 = keyshare_generate(2);
│   │   all_participant_data.append(&mut participant_data_2);
│   │   let public_key: Vec<u8> = make_aggregate_key(all_participant_data.clone());
│   │
│   │   // retrieved from https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/public/2
│   │   let signature: Vec<u8> = hex::decode("a050676d1a1b6ceedb5fb3281cdfe88695199971426ff003c0862460b3a72811328a07ecd53b7d57fc82bb67f35efaf1").unwrap();
│   │
│   │   let secret_key = make_secret_key(2, 1, signature, all_participant_data, public_key);
│   │   let vec_secret_key = hex::decode(secret_key).expect("will return valid hex");
│   │
│   │   assert!(vec_secret_key.len() == 32)
│   }
}
