mod primitives;
mod hashes;
mod key_share;

use primitives::*;
use hashes::*;
use key_share::*;
//use crate::bls_signature::*;

//#[allow(unused)]
//#[allow(dead_code)]

use ark_ec::{pairing::Pairing, CurveGroup, Group};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::Mul, rand::Rng, UniformRand, Zero};
use ark_bls12_381::{
    Bls12_381,Fr as F_bls,
    G1Affine as G1Affine_bls, G2Affine as G2Affine_bls,
    G2Projective as G2Projective_bls, G1Projective as G1Projective_bls,
};
use ark_bn254::{Bn254, Fr as Fr_bn, G1Affine as G1Affine_bn, G2Affine as G2Affine_bn, G1Projective as G1Projective_bn, G2Projective as G2Projective_bn, G1Affine};


pub type PublicKey<C> = C;
pub type SecretKey<C> = <C as Group>::ScalarField;

pub const K_SHARE: u32 = 2;


fn main(){
    let mut pk_loe_str = "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31";
    let pk_1 = str_to_group::<G1Projective_bls>(&pk_loe_str).unwrap();
    dbg!(pk_1);

    pk_loe_str = "a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e";

   // let pk_loe_str = "042f04820f8e0B8A5E5E3E87FD7B9B64F3653D56C42E1206395BABF0558CBE49E11F127FFBF0CF0AB95A03F5870E1B634CB91B5C3BEA2DF5FD1AA5144FE28AF4A";
    let pk_1 = str_to_group::<G2Projective_bls>(&pk_loe_str).unwrap();
   //let pk_1 = str_to_group::<G1Projective_bls>(&pk_loe_str).unwrap();
    dbg!(pk_1);
    //let pk_2 = str_to_group::<G2Projective_bn>(&pk_loe_str).unwrap();

    //dbg!(pk_2);
    //dbg!(pk_2);
    /*
    type KS = KeyShare<Bn254>; // "type alias"
    let pk_l = G2Projective_bls::generator();
    let round = 34;

    let mut rng = ark_std::test_rng();

    let ks = KS::key_share_gen(&mut rng, &pk_l, round);
    dbg!(ks);
    //let ks = KeyShare::<Bn254>::key_share_gen(&mut rng);

     */

}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;

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
