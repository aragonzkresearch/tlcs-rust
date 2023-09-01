mod primitives;
mod hashes;
mod key_share;
mod key_share_stored;
mod bls_verify;

use primitives::*;
use crate::hashes::*;
use crate::key_share::*;
use crate::key_share_stored::*;


#[cfg(test)]
mod tests {
    use crate::primitives::*;
    use ark_std::{ops::Mul, UniformRand};
    use ark_ec::{CurveGroup, Group};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use hex::ToHex;
    use std::fmt;
    use ark_ff::Field;
    use rand::{thread_rng, Rng};
    use ark_bls12_381::{
        Bls12_381,Fr as F_bls,
        G1Affine as G1Affine_bls, G2Affine as G2Affine_bls,
        G2Projective as G2Projective_bls, G1Projective as G1Projective_bls,
    };
    use ark_bn254::{Bn254, Fr as Fr_bn, G1Affine as G1Affine_bn,  G2Affine as G2Affine_bn,
                    G1Projective as G1Projective_bn, G2Projective as G2Projective_bn};

    /// test for baby jubju curve
    ///

    #[test]
    
    fn bn256_group_to_hex_1(){
        for i in 0..10 {
            dbg!(i);
            let mut rng = rand::thread_rng();
            let g = G1Projective_bn::rand(&mut rng);
            dbg!(&g);
            let g_str = group_to_hex::<G1Projective_bn>(&g);
            //dbg!(&g_str);
            let g_str_backto_group = str_to_group::<G1Projective_bn>(&g_str).unwrap();
            //dbg!(&g_str_backto_group);
            assert_eq!(g,g_str_backto_group);
        }
    }

    #[test]
    
    fn bn256_group_to_hex_2(){
        for i in 0..10 {
            let mut rng = rand::thread_rng();
            let g = G2Projective_bn::rand(&mut rng);
            dbg!(&g);
            let g_str = group_to_hex::<G2Projective_bn>(&g);
            //dbg!(&g_str);
            let g_str_backto_group = str_to_group::<G2Projective_bn>(&g_str).unwrap();
            //dbg!(&g_str_backto_group);
            assert_eq!(g,g_str_backto_group);
        }
    }
    /// test for bls group

    #[test]
    
    fn bls_group_to_hex_1(){
        for i in 0..10 {
            let mut rng = rand::thread_rng();
            let g = G1Projective_bls::generator();
            //dbg!(&g);
            let g_str = group_to_hex::<G1Projective_bls>(&g);
            //dbg!(&g_str);
            let g_str_backto_group = str_to_group::<G1Projective_bls>(&g_str).unwrap();
            //dbg!(&g_str_backto_group);
            assert_eq!(g,g_str_backto_group)
        }
    }

    #[test]
    
    fn bls_group_to_hex_2(){
        for i in 0..10 {
            let mut rng = rand::thread_rng();
            let g = G2Projective_bls::generator();
            //dbg!(&g);
            let g_str = group_to_hex::<G2Projective_bls>(&g);
            //dbg!(&g_str);
            let g_str_backto_group = str_to_group::<G2Projective_bls>(&g_str).unwrap();
            //dbg!(&g_str_backto_group);
            assert!(str_to_group::<G2Projective_bls>(&g_str).is_ok(), "Expected Ok(G), but got Err(InvalidPoint).");
            assert_eq!(g,g_str_backto_group)
        }
    }

    #[test]
    
    fn bls_str_to_group_bls() {
        let g = "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31";
        let g_porjective = str_to_group::<G1Projective_bls>(&g);
        let g_str_projective = group_to_hex::<G1Projective_bls>(&g_porjective.unwrap());
        assert_eq!(g_str_projective, g);
    }
    #[test]
    
    fn xor_test(){
        for i in 0..10 {
            let mut rng = rand::thread_rng();
            let random_vec_a: Vec<u8> = (0..10).map(|_| rng.gen()).collect();
            let random_vec_b: Vec<u8> = (0..7).map(|_| rng.gen()).collect();
            let a_xor_b = xor(&random_vec_a, &random_vec_b);

            assert_eq!(a_xor_b, xor(&random_vec_b, &random_vec_a));
            assert_eq!(xor(&a_xor_b, &random_vec_b), random_vec_a);

            let zero_vec: Vec<u8> = vec![0; 10];
            assert_eq!(zero_vec, xor(&random_vec_a, &random_vec_a));
        }
    }
}
