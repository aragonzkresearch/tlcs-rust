mod hashes;
mod key_share;
mod primitives;

//use hashes::*;
use key_share::*;
//use primitives::*;
//use crate::bls_signature::*;

//#[allow(unused)]
//#[allow(dead_code)]
/*
use ark_bls12_381::{
    Bls12_381,
    Fr as F_bls,
    G1Affine as G1Affine_bls,
    G1Projective as G1Projective_bls,
    G2Affine as G2Affine_bls, G2Projective as G2Projective_bls,
};
use ark_bn254::{
    Bn254,
    Fr as Fr_bn,
    G1Affine as G1Affine_bn,
    G1Affine,
    G1Projective as G1Projective_bn,
    G2Affine as G2Affine_bn,
    G2Projective as G2Projective_bn,
};
*/
use ark_ec::{
    pairing::Pairing,
    //    CurveGroup,
    Group,
};
use ark_serialize::CanonicalSerialize;
//use ark_std::{ops::Mul, rand::Rng, UniformRand, Zero};

pub type PublicKey<C> = C;
pub type SecretKey<C> = <C as Group>::ScalarField;

pub const K_SHARE: u32 = 2;

pub fn key_share_store<E: Pairing>(key_share: &KeyShare<E>) -> Vec<u8> {
    let mut key_share_serialized_compressed = Vec::new();
    key_share
        .serialize_compressed(&mut key_share_serialized_compressed)
        .expect("Serialization should succeed");
    return key_share_serialized_compressed;
}

fn main() {}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;
    #[test]
    fn test_serialization() {
        type KS = KeyShare<Bn254>;
        let pk_loe_str = "a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e";
        let round = 34;
        let mut rng = ark_std::test_rng();

        let ks = KS::key_share_gen(&mut rng, &pk_loe_str, round);
        //dbg!(&ks);

        let mut serialized_data_ks = Vec::new();
        ks.serialize_compressed(&mut serialized_data_ks)
            .expect("Serialization should succeed");

        // Deserialize MyStruct
        let deserialized_ks = KS::deserialize_compressed(serialized_data_ks.as_slice())
            .expect("Deserialization should succeed");

        // Check that the deserialized struct is equal to the original
        // dbg!(&deserialized_njm_struct);

        deserialized_ks.check().expect("Validation should succeed");
        assert_eq!(ks, deserialized_ks);

        let ks_se = key_share_store(&ks);
        let ks_sr_test = KS::deserialize_compressed(serialized_data_ks.as_slice())
            .expect("Deserialization should succeed");

        assert_eq!(ks, ks_sr_test);
    }

    #[test]
    fn test_aggregation() {
        type KS = KeyShare<Bn254>; // "type alias"

        let mut rng = ark_std::test_rng();
        let pk_l = G2Projective_bls::generator();
        let pk_loe_str = "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31";
        let pk_1 = str_to_group::<G1Projective_bls>(&pk_loe_str).unwrap();
        let pk_2 = str_to_group::<G2Projective_bls>(&pk_loe_str).unwrap();
        dbg!(pk_1);
        dbg!(pk_2);
        /*

        let round = 34;

        let ks = KeyShare::<Bn254>::key_share_gen(&mut rng, &pk_l, round);

        todo!();

        */
    }
}
