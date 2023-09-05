use crate::hashes::*;
use crate::key_share::*;
use crate::primitives::*;

use ark_bls12_381::{
    Bls12_381, G1Affine as G1Affine_bls, G1Projective as G1Projective_bls,
    G2Affine as G2Affine_bls, G2Projective as G2Projective_bls,
};

use ark_bn254::Bn254;
use ark_ec::AffineRepr;
//G1Projective as G1Projective_bn};
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use ark_std::Zero;

/******************************************************************************************
** The four functions needed by the chain
******************************************************************************************/

#[allow(unused)]
pub fn make_keyshare(pk_loe: String, round: u64, _scheme: String, sec_param: usize) -> Vec<u8> {
    // Make key from round and loe_pk
    type TlcsKeyShare = KeyShare<Bn254>;

    let mut rng = ark_std::test_rng();
    let key = TlcsKeyShare::key_share_gen(&mut rng, &pk_loe, round, sec_param);
    // TODO: use the proper Pairing (from scheme)

    return key_share_store::<Bn254>(&key);
}

#[allow(unused)]
pub fn verify_keyshare(
    pk_loe: String,
    round: u64,
    _scheme: String,
    data: Vec<u8>,
    sec_param: usize,
) -> bool {
    // TODO: use the proper Pairing (from scheme)
    return verify_key_share_store::<Bn254>(pk_loe.into(), data, round, sec_param);
}

#[allow(unused)]
pub fn make_public_key(pk_loe: String, all_data: &Vec<Vec<u8>>) -> Vec<u8> {
    // TODO: use the proper Pairing (from scheme)
    return mpk_aggregation_from_stored_data::<Bn254>(all_data);
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

#[allow(dead_code)]
pub fn loe_signature_is_valid(round: u64, signature: String, loe_pk: String) -> bool {
    let pk_affine_2 = str_to_group::<G2Projective_bls>(loe_pk.as_str())
        .unwrap()
        .into_affine();
    let signature_affine_1 = str_to_group::<G1Projective_bls>(signature.as_str())
        .unwrap()
        .into_affine();
    let msg = message(round);

    let hash_on_curve_1 = hash_loe_g1(&msg);

    let left_hand = Bls12_381::pairing(&signature_affine_1, G2Affine_bls::generator());
    let right_hand = Bls12_381::pairing(&hash_on_curve_1, &pk_affine_2);
    return left_hand == right_hand;
}

#[allow(dead_code)]
fn key_share_store<E: Pairing>(key_share: &KeyShare<E>) -> Vec<u8> {
    // println!("key_share_store : {:?}", key_share);
    let mut key_share_serialized_compressed = Vec::new();
    key_share
        .serialize_compressed(&mut key_share_serialized_compressed)
        .expect("Serialization should succeed");
    //println!("key_share_serialized_compressed : {:?}", key_share_serialized_compressed);
    return key_share_serialized_compressed;
}

#[allow(dead_code)]
fn verify_key_share_store<E: Pairing>(
    pk_loe: String,
    key_share_stored: Vec<u8>,
    round: u64,
    sec_param: usize,
) -> bool {
    let ks = KeyShare::<E>::deserialize_compressed(key_share_stored.as_slice())
        .expect("Deserialization should succeed");
    return KeyShare::<E>::key_share_verify(&pk_loe.as_str(), &ks, round, sec_param);
}

#[allow(dead_code)]
fn mpk_aggregation_from_stored_data<E: Pairing>(key_shares: &Vec<Vec<u8>>) -> Vec<u8> {
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
fn msk_aggregation_from_stored_data<E: Pairing>(
    sk_t: &G1Affine_bls,
    key_shares: &Vec<Vec<u8>>,
) -> Vec<u8> {
    // println!("step 4.3- inside the secodn one ");

    let mut msk = E::ScalarField::zero();
    for k in key_shares {
        let key_share = KeyShare::<E>::deserialize_compressed(k.as_slice())
            .expect("Deserialization should succeed");

        let z_0 = Bls12_381::pairing(sk_t, &key_share.t_0[0]);
        let z_1 = Bls12_381::pairing(sk_t, &key_share.t_1[0]);

        let sk0 = xor(&hash_1::<Bls12_381>(z_0), &key_share.y_0[0]);
        let sk1 = xor(&hash_1::<Bls12_381>(z_1), &key_share.y_1[0]);
        let sk_0 = E::ScalarField::deserialize_compressed(&*sk0).unwrap();
        let sk_1 = E::ScalarField::deserialize_compressed(&*sk1).unwrap();

        msk = msk + sk_0;
        msk = msk + sk_1;
    }
    let mut msk_bytes = Vec::new();
    msk.serialize_compressed(&mut msk_bytes).unwrap();
    // printlnb !("step 4.4 msk_bytes ={:?} ", msk_bytes);
    return msk_bytes;
}

#[cfg(test)]
mod tests {
    use super::*;
    /*
    use ark_bn254::{
        Bn254, Fr as Fr_bn, G1Affine as G1Affine_bn, G1Projective as G1Projective_bn,
        G2Affine as G2Affine_bn, G2Affine, G2Projective as G2Projective_bn,
    };
    */
    use ark_bn254::{Fr as Fr_bn, G1Projective as G1Projective_bn};

    // retrieved from https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/public/2
    const LOE_PUBLIC_KEY: &str = "a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e";
    const SIGNATURE: &str = "9544ddce2fdbe8688d6f5b4f98eed5d63eee3902e7e162050ac0f45905a55657714880adabe3c3096b92767d886567d0";
    const ROUND: u64 = 1;
    const SECURITY_PARAM: usize = 10;
    const SCHEME: &str = "BJJ";

    #[test]
    fn verify_participant_data_works() {
        let participant_data = make_keyshare(
            LOE_PUBLIC_KEY.into(),
            ROUND,
            SCHEME.to_string(),
            SECURITY_PARAM,
        );
        let verified = verify_keyshare(
            LOE_PUBLIC_KEY.into(),
            ROUND,
            SCHEME.to_string(),
            participant_data,
            SECURITY_PARAM,
        );
        assert!(verified);
    }

    #[test]
    fn aggregate_participant_data_works() {
        let mut all_participant_data: Vec<Vec<u8>> = vec![];
        all_participant_data.push(make_keyshare(
            LOE_PUBLIC_KEY.into(),
            2,
            SCHEME.to_string(),
            SECURITY_PARAM,
        ));
        all_participant_data.push(make_keyshare(
            LOE_PUBLIC_KEY.into(),
            2,
            SCHEME.to_string(),
            SECURITY_PARAM,
        ));

        let public_key = make_public_key(LOE_PUBLIC_KEY.into(), &all_participant_data);
        let str_public_key = hex::encode(&public_key);
        assert!(public_key.len() == 32);
        assert!(
            str_to_group::<G1Projective_bn>(&str_public_key).is_ok(),
            "Expected Ok, but got Err"
        );
    }

    #[test]
    fn make_secret_key_works() {
        let mut all_participant_data: Vec<Vec<u8>> = vec![];
        all_participant_data.push(make_keyshare(
            LOE_PUBLIC_KEY.into(),
            ROUND,
            SCHEME.to_string(),
            SECURITY_PARAM,
        ));
        all_participant_data.push(make_keyshare(
            LOE_PUBLIC_KEY.into(),
            ROUND,
            SCHEME.to_string(),
            SECURITY_PARAM,
        ));

        let secret_key = make_secret_key(
            ROUND,
            SCHEME.to_string(),
            SIGNATURE.to_string(),
            all_participant_data,
        );
        let vec_secret_key = hex::encode(secret_key);
        let _f = str_to_field::<Fr_bn>(&vec_secret_key);
        assert!(vec_secret_key.len() == 64);
    }

    #[test]
    fn mpk_and_msk_are_correct() {
        let mut all_participant_data: Vec<Vec<u8>> = vec![];
        all_participant_data.push(make_keyshare(
            LOE_PUBLIC_KEY.into(),
            ROUND,
            SCHEME.to_string(),
            SECURITY_PARAM,
        ));
        all_participant_data.push(make_keyshare(
            LOE_PUBLIC_KEY.into(),
            ROUND,
            SCHEME.to_string(),
            SECURITY_PARAM,
        ));
        // TODO: make a test to encrypt/decrypt
    }

    #[test]
    fn loe_signature_validate_works() {
        assert!(loe_signature_is_valid(
            ROUND,
            SIGNATURE.into(),
            LOE_PUBLIC_KEY.into()
        ));
    }
}
