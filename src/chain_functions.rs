use crate::hashes::*;
use crate::key_share::*;
use crate::primitives::*;

use ark_bls12_381::{
    Bls12_381, G1Affine as G1Affine_bls, G1Projective as G1Projective_bls,
    G2Affine as G2Affine_bls, G2Projective as G2Projective_bls,
};
use num_bigint::BigUint;
//use num_bigint;
use num_integer::Integer;
//use ark_ff::BigInteger;


#[allow(unused)]
use ark_ed_on_bn254::{EdwardsProjective as tlcs_curve_bjj, EdwardsAffine as affin_bjj,  Fr as Fr_tlcs_bjj, Fq as Fq_tlcs_bjj};
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
pub fn make_public_key(scheme: String, all_data: &Vec<Vec<u8>>) -> String{
    println!("04-01");
    println!("scheme = {}", scheme);
    match scheme.as_str() {
        "BJJ" => make_public_key_bjj(all_data),
        "SECP256K1" => make_public_key_secp(all_data),
        &_ => make_public_key_bjj(all_data),
    }
}

#[allow(unused)]
pub fn make_secret_key(scheme: String, loe_signature: String, all_data: Vec<Vec<u8>>) ->String {
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
pub fn make_secret_key_bjj(loe_signature: String, all_data: Vec<Vec<u8>>) -> String{
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
    println!("04-02");
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
    //println!("key_share_serialized_compressed : {:?}", key_share_serialized_compressed);
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
fn mpk_aggregation_from_stored_data<E: CurveGroup>(key_shares: &Vec<Vec<u8>>) -> String {
    //type KS = KeyShare<E>;
    let mut mpk = E::zero();
    for k in key_shares {
        let key_share = KeyShare::<E>::deserialize_compressed(k.as_slice())
            .expect("Deserialization should succeed");
        mpk = mpk + key_share.pk;
    }
    println!(" this is the master pk {}", &mpk);
    let mpk_hex_compressed = group_compressed_format::<E>(&mpk);
    return mpk_hex_compressed;
    /*
    let mut mpk_serialized_compressed = Vec::new();
    mpk.serialize_compressed(&mut mpk_serialized_compressed)
        .expect("Serialization should succeed");
    return mpk_serialized_compressed;
     */
}

#[allow(dead_code)]
fn msk_aggregation_from_stored_data<E: CurveGroup>(
    sk_t: &G1Affine_bls,
    key_shares: &Vec<Vec<u8>>,
) -> String {
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
//    println!("this is the mask {}", &msk);
    let msk_big_int: BigUint = msk.into();
    //println!("this is the mask {}", &msk_big_int);
    let msk_hex = format!("0X{:X}", msk_big_int);
    return msk_hex
    /*
    let mut msk_bytes = Vec::new();
    msk.serialize_compressed(&mut msk_bytes).unwrap();
    // printlnb !("step 4.4 msk_bytes ={:?} ", msk_bytes);
    return msk_bytes;
     */
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::Group;
    use ark_std::ops::Mul;
    //use serde::__private::de::Content::String;

    // Fastnet
    // retrieved from https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/public/2
    //const LOE_PUBLIC_KEY: &str = "a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e";
    //const SIGNATURE: &str = "9544ddce2fdbe8688d6f5b4f98eed5d63eee3902e7e162050ac0f45905a55657714880adabe3c3096b92767d886567d0";
    // Quicknet
    // retrieved from https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/info
    const LOE_PUBLIC_KEY: &str = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
   const SIGNATURE: &str = "b6b6a585449b66eb12e875b64fcbab3799861a00e4dbf092d99e969a5eac57dd3f798acf61e705fe4f093db926626807"; // For testing

    //const SIGNATURE: &str = "b55e7cb2d5c613ee0b2e28d6750aabbb78c39dcc96bd9d38c2c2e12198df95571de8e8e402a0cc48871c7089a2b3af4b"; // For testing

    const ROUND: u64 = 2;
    const SECURITY_PARAM: usize = 10;
    const SCHEME: &str = "BJJ";



    fn group_from_compressed_format_bjj(g_str : &str) -> tlcs_curve_bjj {
        let (g_hex_str , is_even) : (&str, bool) = match g_str {
            s if s.starts_with("0x02") || s.starts_with("0X02") => {
                (&s[4..], true)
            },
            s if s.starts_with("0x03") || s.starts_with("0X03") => {
                (&s[4..], false)
            },
            _ => ("0", false),
        };
        let g_big_int = hex_to_bignum(&g_hex_str).unwrap();
        let g_x : Fq_tlcs_bjj = g_big_int.into();
        let (x_0 , x_1)  = affin_bjj::get_xs_from_y_unchecked(g_x.clone()).unwrap();
        let x_is_even = x_0.to_string().chars().last().unwrap().to_digit(10).unwrap().is_even();
        let g_y = match is_even ^ x_is_even{
            true  => x_1,
            false => x_0,
        };
        let g : affin_bjj = affin_bjj::new(g_x, g_y);
        return g.into();
    }


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

        let public_key_compressed = make_public_key(SCHEME.to_string(), &all_participant_data);
        let public_key = group_from_compressed_format_bjj(&public_key_compressed);
        assert!(public_key.into_affine().is_on_curve());
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

        let secret_key_hex = make_secret_key(
            SCHEME.to_string(),
            SIGNATURE.to_string(),
            all_participant_data,
        );
        let f_str = &secret_key_hex[2..];


        let secret_key_int = hex_to_bignum(&f_str);

        assert!(secret_key_int.is_ok());
    }

    #[test]
    fn make_secret_key_works_secp256k1() {
        println!("start test");
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

        let secret_key_hex  = make_secret_key(
            "SECP256K1".into(),
            SIGNATURE.to_string(),
            all_participant_data,
        );

        let f_str = &secret_key_hex[2..];

        let secret_key_int = hex_to_bignum(&f_str);

        assert!(secret_key_int.is_ok());

    }
    #[test]
    fn mpk_and_msk_are_correct_bjj() {
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
        let msk_str_x = make_secret_key(
            SCHEME.to_string(),
            SIGNATURE.to_string(),
            all_participant_data.clone(),
        );
        let msk_str = &msk_str_x[2..];
        let public_key_compressed = make_public_key(LOE_PUBLIC_KEY.into(), &all_participant_data);
        let mpk = group_from_compressed_format_bjj(&public_key_compressed);
        let msk_int = hex_to_bignum(&msk_str).unwrap();
        let msk : Fr_tlcs_bjj = msk_int.into();
        let gen = tlcs_curve_bjj::generator();
        assert_eq!( gen.mul(&msk), mpk);
    }
    #[test]
    fn mpk_and_msk_are_correct_secp() {
        let mut all_participant_data: Vec<Vec<u8>> = vec![];
        all_participant_data.push(make_keyshare(
            LOE_PUBLIC_KEY.into(),
            ROUND,
            "SECP256K1".to_string(),
            SECURITY_PARAM,
        ));
        all_participant_data.push(make_keyshare(
            LOE_PUBLIC_KEY.into(),
            ROUND,
            "SECP256K1".to_string(),
            SECURITY_PARAM,
        ));
        println!("02");
        let msk_str_x = make_secret_key(
            "SECP256K1".to_string(),
            SIGNATURE.to_string(),
            all_participant_data.clone(),
        );
        let msk_str = &msk_str_x[2..];
        println!("03");
        let public_key_compressed = make_public_key("SECP256K1".to_string(), &all_participant_data);
        println!("04");
        println!("public_key_compressed {}", public_key_compressed);

        let mpk = group_from_compressed::<tlcs_curve_secp>(&public_key_compressed);
        println!("mpk {}", mpk);

        let msk_int = hex_to_bignum(&msk_str).unwrap();
        let msk : Fr_tlcs_secp = msk_int.into();
        println!("msk {}", msk);
        let gen = tlcs_curve_secp::generator();

        assert_eq!( gen.mul(&msk), mpk);
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
