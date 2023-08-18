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
use ark_bn254::{Bn254, Fr as Fr_bn, G1Affine as G1Affine_bn,  G2Affine as G2Affine_bn,
                G1Projective as G1Projective_bn, G2Projective as G2Projective_bn};


pub type PublicKey<C> = C;
pub type SecretKey<C> = <C as Group>::ScalarField;

pub const K_SHARE: u32 = 2;


fn main(){
    type KS = KeyShare<Bn254>; // "type alias"
    let pk_l = G2Projective_bls::generator();
    let round = 34;

    let mut rng = ark_std::test_rng();

    let ks = KS::key_share_gen(&mut rng, &pk_l, round);
    dbg!(ks);
    //let ks = KeyShare::<Bn254>::key_share_gen(&mut rng);

}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;

    #[test]
    fn test_aggregation() {
        type KS = KeyShare<Bn254>; // "type alias"

        let mut rng = ark_std::test_rng();
        let pk_l = G2Projective_bls::generator();
        let round = 34;

        let ks = KeyShare::<Bn254>::key_share_gen(&mut rng, &pk_l, round);

        todo!();
    }
}
