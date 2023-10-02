use crate::hashes::*;
use crate::key_share::*;
use crate::primitives::*;

use ark_bls12_381::{
    Bls12_381, G1Affine as G1Affine_bls, G1Projective as G1Projective_bls,
    G2Affine as G2Affine_bls, G2Projective as G2Projective_bls,
};

#[allow(unused)]
use ark_ed_on_bn254::{EdwardsProjective as tlcs_curve_bjj, Fr as Fr_tlcs_bjj};
#[allow(unused)]
use ark_secp256k1::{Fr as Fr_tlcs_secp, Projective as tlcs_curve_secp};

use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use ark_std::Zero;

/******************************************************************************************
** The four functions needed by the chain
******************************************************************************************/
// TODO: use the proper Pairing (from scheme) in these functions properly

//
// Wrapper functions (temporary)
//
#[allow(unused)]
pub fn make_keyshare(pk_loe: String, round: u64, scheme: String, sec_param: usize) -> Vec<u8> {
    match scheme.as_str() {
        "BJJ" => make_keyshare_bjj(pk_loe, round, scheme, sec_param),
        "SECP256K1" => make_keyshare_secp(pk_loe, round, scheme, sec_param),
        &_ => make_keyshare_bjj(pk_loe, round, scheme, sec_param),
    }
}

#[allow(unused)]
pub fn verify_keyshare(
    pk_loe: String,
    round: u64,
    scheme: String,
    data: Vec<u8>,
    sec_param: usize,
) -> bool {
    match scheme.as_str() {
        "BJJ" => verify_keyshare_bjj(pk_loe, round, scheme, data, sec_param),
        "SECP256K1" => verify_keyshare_secp(pk_loe, round, scheme, data, sec_param),
        &_ => verify_keyshare_bjj(pk_loe, round, scheme, data, sec_param),
    }
}

#[allow(unused)]
pub fn make_public_key(scheme: String, all_data: &Vec<Vec<u8>>) -> String {
    match scheme.as_str() {
        "BJJ" => make_public_key_bjj(all_data),
        "SECP256K1" => make_public_key_secp(all_data),
        &_ => make_public_key_bjj(all_data),
    }
}

#[allow(unused)]
pub fn make_secret_key(scheme: String, loe_signature: String, all_data: Vec<Vec<u8>>) -> String {
    match scheme.as_str() {
        "BJJ" => make_secret_key_bjj(loe_signature, all_data),
        "SECP256K1" => make_secret_key_secp(loe_signature, all_data),
        &_ => make_secret_key_bjj(loe_signature, all_data),
    }
}

//
// BabyJubJub functions
//
#[allow(unused)]
pub fn make_keyshare_bjj(pk_loe: String, round: u64, _scheme: String, sec_param: usize) -> Vec<u8> {
    //let mut rng = ark_std::test_rng();
    let mut rng = ark_std::rand::thread_rng();

    type TlcsKeyShare = KeyShare<tlcs_curve_bjj>;
    let key = TlcsKeyShare::key_share_gen(&mut rng, &pk_loe, round, sec_param);

    return key_share_store::<tlcs_curve_bjj>(&key);
}

#[allow(unused)]
pub fn verify_keyshare_bjj(
    pk_loe: String,
    round: u64,
    _scheme: String,
    data: Vec<u8>,
    sec_param: usize,
) -> bool {
    return verify_key_share_store::<tlcs_curve_bjj>(pk_loe.into(), data, round, sec_param);
}

#[allow(unused)]
pub fn make_public_key_bjj(all_data: &Vec<Vec<u8>>) -> String {
    mpk_aggregation_from_stored_data::<tlcs_curve_bjj>(all_data)
}

#[allow(unused)]
pub fn make_secret_key_bjj(loe_signature: String, all_data: Vec<Vec<u8>>) -> String {
    let sk_t = str_to_group::<G1Projective_bls>(&loe_signature)
        .unwrap()
        .into_affine();
    msk_aggregation_from_stored_data::<tlcs_curve_bjj>(&sk_t, &all_data)
}

//
// SECP256K1 functions
//
#[allow(unused)]
pub fn make_keyshare_secp(
    pk_loe: String,
    round: u64,
    _scheme: String,
    sec_param: usize,
) -> Vec<u8> {
    //let mut rng = ark_std::test_rng();
    let mut rng = ark_std::rand::thread_rng();

    type TlcsKeyShare = KeyShare<tlcs_curve_secp>;
    let key = TlcsKeyShare::key_share_gen(&mut rng, &pk_loe, round, sec_param);

    return key_share_store::<tlcs_curve_secp>(&key);
}

#[allow(unused)]
pub fn verify_keyshare_secp(
    pk_loe: String,
    round: u64,
    _scheme: String,
    data: Vec<u8>,
    sec_param: usize,
) -> bool {
    return verify_key_share_store::<tlcs_curve_secp>(pk_loe.into(), data, round, sec_param);
}

#[allow(unused)]
pub fn make_public_key_secp(all_data: &Vec<Vec<u8>>) -> String {
    mpk_aggregation_from_stored_data::<tlcs_curve_secp>(all_data)
}

#[allow(unused)]
pub fn make_secret_key_secp(loe_signature: String, all_data: Vec<Vec<u8>>) -> String {
    let sk_t = str_to_group::<G1Projective_bls>(&loe_signature)
        .unwrap()
        .into_affine();
    msk_aggregation_from_stored_data::<tlcs_curve_secp>(&sk_t, &all_data)
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
fn key_share_store<E: CurveGroup>(key_share: &KeyShare<E>) -> Vec<u8> {
    let mut key_share_serialized_compressed = Vec::new();
    key_share
        .serialize_compressed(&mut key_share_serialized_compressed)
        .expect("Serialization should succeed");
    return key_share_serialized_compressed;
}

#[allow(dead_code)]
fn verify_key_share_store<E: CurveGroup>(
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
fn mpk_aggregation_from_stored_data<E: CurveGroup>(key_shares: &Vec<Vec<u8>>) ->String {
    //type KS = KeyShare<E>;
    let mut mpk = E::zero();
    for k in key_shares {
        let key_share = KeyShare::<E>::deserialize_compressed(k.as_slice())
            .expect("Deserialization should succeed");
        mpk = mpk + key_share.pk;
    }
    group_compressed::<E> (&mpk)
}

#[allow(dead_code)]
fn msk_aggregation_from_stored_data<E: CurveGroup>(
sk_t: &G1Affine_bls,
    key_shares: &Vec<Vec<u8>>,
) -> String{
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
    field_compressed::<E::ScalarField>(&msk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::Group;
    use ark_std::UniformRand;

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

        let g = tlcs_curve_bjj::generator();
        let g_str = group_to_hex::<tlcs_curve_bjj>(&g);
        //assert_eq!(true, false);
        assert_eq!(str_public_key.len(), g_str.len());

        // assert!(str_public_key.len()==  64);
        assert!(
            str_to_group::<tlcs_curve_bjj>(&str_public_key).is_ok(),
            "Expected Ok, but got Err"
        );
    }

    #[test]
    fn make_secret_key_works_bjj() {
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
            SCHEME.to_string(),
            SIGNATURE.to_string(),
            all_participant_data,
        );
        let vec_secret_key = hex::encode(secret_key);
        let _f = str_to_field::<Fr_tlcs_bjj>(&vec_secret_key);

        let mut rng = ark_std::test_rng();
        let f = Fr_tlcs_bjj::rand(&mut rng);
        let f_str = field_to_hex::<Fr_tlcs_bjj>(&f);
        assert_eq!(vec_secret_key.len(), f_str.len());

        //assert!(vec_secret_key.len() == 64);
    }

    #[test]
    fn make_secret_key_works_secp256k1() {
        let mut all_participant_data: Vec<Vec<u8>> = vec![];
        all_participant_data.push(make_keyshare(
            LOE_PUBLIC_KEY.into(),
            ROUND,
            "SECP256K1".into(),
            SECURITY_PARAM,
        ));
        all_participant_data.push(make_keyshare(
            LOE_PUBLIC_KEY.into(),
            ROUND,
            "SECP256K1".into(),
            SECURITY_PARAM,
        ));

        let secret_key = make_secret_key(
            "SECP256K1".into(),
            SIGNATURE.to_string(),
            all_participant_data,
        );
        let vec_secret_key = hex::encode(secret_key);
        let _f = str_to_field::<Fr_tlcs_secp>(&vec_secret_key);

        let mut rng = ark_std::test_rng();
        let f = Fr_tlcs_secp::rand(&mut rng);
        let f_str = field_to_hex::<Fr_tlcs_secp>(&f);
        assert_eq!(vec_secret_key.len(), f_str.len());

        //assert!(vec_secret_key.len() == 64);
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
