use crate::hashes::*;
use crate::primitives::*;

use ark_bls12_381::{
    Bls12_381,
    Fr as F_bls,
    G1Affine as G1Affine_bls,
    G1Projective as G1Projective_bls,
    G2Affine as G2Affine_bls, G2Projective as G2Projective_bls,
};
use ark_ec::{
    pairing::Pairing,CurveGroup,Group,AffineRepr,
};
use digest::Update;
use sha2::{Digest, Sha256};
use hex::ToHex;

fn verify_loe_data(pk: &str, message: &str, signature: &str, randomness: &str)-> bool{
    let hasher = Sha256::new();
    hasher.update(&str_to_byte(signature));
    hasher.finalize();
    let loe_randmness : &str = hasher.finalize().encode_hex();

    if loe_randmness != randomness{
       return  false
    }
     return match str_to_byte(pk).len(){
         96 => bls_verify_1(pk, message, signature),
         192 => bls_verify_2(pk, message, signature),
         _ =>  false,
     };
}
fn bls_verify_1(pk: &str, message: &str, signature: &str)-> bool{
    let pk_affine_1 = str_to_group::<G1Affine_bls>(pk);
    let signature_affine_2 = str_to_group::<G2Affine_bls>(signature);
    let mut hash_on_curve_2 = hash_loe_g2( &str_to_byte(&message));
    let left_hand = Bls12_381::pairing(G1Affine_bls::generator(),&signature_affine_2 );
    let right_hand = Bls12_381::pairing( &pk_affine_1 , &hash_on_curve_2);
    return left_hand == right_hand;
}
fn bls_verify_2(pk: &str, message: &str, signature: &str)-> bool{
    let pk_affine_2 = str_to_group::<G2Affine_bls>(pk);
    let signature_affine_1 = str_to_group::<G1Affine_bls>(signature);
    let mut hash_on_curve_1 = hash_loe_g1( &str_to_byte(&message));
    let left_hand = Bls12_381::pairing(&signature_affine_1,G2Affine_bls::generator());
    let right_hand = Bls12_381::pairing(  &hash_on_curve_1, &pk_affine_2 );
    return left_hand == right_hand;
}