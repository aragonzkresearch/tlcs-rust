use crate::hashes::*;
use crate::key_share::*;
use crate::primitives::*;

use ark_bls12_381::{Bls12_381, G1Affine as G1Affine_bls, G1Projective as G1Projective_bls};

use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use ark_std::Zero;

/******************************************************************************************
** The four functions needed by the chain
******************************************************************************************/

//pub fn keyshare_generate(round: u64, _scheme: String, loe_pk: Vec<u8>) -> Vec<u8> {
#[allow(unused)]
pub fn keyshare_generate(round: u64, _scheme: String, loe_pk: String) -> Vec<u8> {
    // Make key from round and loe_pk
    type KS = KeyShare<Bn254>;

    //let mut rng = ark_std::test_rng();
    let mut rng = rand::thread_rng();
    //let loe_pk_str = hex::encode(loe_pk);
    let key = KS::key_share_gen(&mut rng, &loe_pk, round);
    //let key : KeyShare::<Bn254> = KeyShare::<Bn254>::key_share_gen::<Bn254>(&mut rng, &loe_pk_str, round);
    // TODO: use the proper Pairing (from scheme)
    // let key: KeyShare<Bn254> = key_share_gen(&mut rng, &loe_pk_str, round);

    return key_share_store::<Bn254>(&key);
}

#[allow(unused)]
pub fn keyshare_verify(round: u64, _scheme: String, data: Vec<u8>) -> bool {
    // TODO: use the proper Pairing (from scheme)
    return verify_key_share_store::<Bn254>(data, round);
}

//pub fn make_aggregate_key(round: u64, _scheme: String, all_data: Vec<Vec<u8>>) -> Vec<u8> {
#[allow(unused)]
pub fn make_aggregate_key(all_data: Vec<Vec<u8>>) -> Vec<u8> {
    // TODO: use the proper Pairing (from scheme)
    return mpk_aggregation_from_stored_data::<Bn254>(&all_data);
}

#[allow(unused)]
pub fn make_secret_key(
    _round: u64,
    _scheme: String,
    loe_signature: String,
    all_data: Vec<Vec<u8>>,
) -> Vec<u8> {
    // TODO: use the proper Pairing (from scheme)
    // TODO: change msk_aggregation_from_stored_data output to Vec<u8>
    let sk_t = str_to_group::<G1Projective_bls>(&loe_signature)
        .unwrap()
        .into_affine();
    return msk_aggregation_from_stored_data::<Bn254>(&sk_t, &all_data);
}

/*
fn main() {
    println!("only a main!");
}
*/

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
    return KeyShare::<E>::key_share_verify(&ks, round);
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
    return mpk_serialized_compressed;
}

#[allow(dead_code)]
pub fn msk_aggregation_from_stored_data<E: Pairing>(
    sk_t: &G1Affine_bls,
    key_shares: &Vec<Vec<u8>>,
) -> Vec<u8> {
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
    let mut msk_bytes = Vec::new();
    msk.serialize_compressed(&mut msk_bytes).unwrap();
    return msk_bytes;
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOE_PUBLIC_KEY: &str = "a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e";
    const SCHEME: &str = "BJJ";

    #[test]
    fn verify_participant_data_works() {
        let participant_data = keyshare_generate(2, SCHEME.to_string(), LOE_PUBLIC_KEY.into());
        let verified = keyshare_verify(2, SCHEME.to_string(), participant_data);

        assert!(verified);
    }

    #[test]
    fn aggregate_participant_data_works() {
        let mut all_participant_data: Vec<Vec<u8>> = vec![vec![]];
        all_participant_data.push(keyshare_generate(
            2,
            SCHEME.to_string(),
            LOE_PUBLIC_KEY.into(),
        ));
        all_participant_data.push(keyshare_generate(
            2,
            SCHEME.to_string(),
            LOE_PUBLIC_KEY.into(),
        ));

        let public_key = make_aggregate_key(all_participant_data);
        let vec_public_key = hex::decode(public_key).expect("will return valid hex");

        assert!(vec_public_key.len() == 33)
    }

    #[test]
    fn make_secret_key_works() {
        let mut all_participant_data: Vec<Vec<u8>> = vec![vec![]];
        all_participant_data.push(keyshare_generate(
            2,
            SCHEME.to_string(),
            LOE_PUBLIC_KEY.into(),
        ));
        all_participant_data.push(keyshare_generate(
            2,
            SCHEME.to_string(),
            LOE_PUBLIC_KEY.into(),
        ));

        // retrieved from https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/public/2
        //let signature: Vec<u8> = hex::decode("a050676d1a1b6ceedb5fb3281cdfe88695199971426ff003c0862460b3a72811328a07ecd53b7d57fc82bb67f35efaf1").unwrap();
        let signature: String = "a050676d1a1b6ceedb5fb3281cdfe88695199971426ff003c0862460b3a72811328a07ecd53b7d57fc82bb67f35efaf1".to_string();

        let secret_key = make_secret_key(2, SCHEME.to_string(), signature, all_participant_data);
        let vec_secret_key = hex::decode(secret_key).expect("will return valid hex");

        assert!(vec_secret_key.len() == 32)
    }
}
