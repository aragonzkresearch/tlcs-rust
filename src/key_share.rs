//use crate::bls_signature::*;
use crate::primitives::*;
use crate::hashes::*;

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



// /// G1L: the Pairing G1 grup used by the TLock chain (drand/LoE)
// /// G2L: the Pairing G2 grup used by the TLock chain (drand/LoE)
// /// G1: the custom blablabla
// pub struct KeyShare<G1L: CurveGroup, G2L: CurveGroup, G1: CurveGroup> {
/// E1: LoE Pairing
/// E: custom Pairing
///
#[derive(Debug,CanonicalSerialize)]
pub struct KeyShare<E: Pairing> {
    pub pk: E::G1,
    pub pk_0: Vec<E::G1>,
    pub pk_1: Vec<E::G1>,
    pub sk: SecretKey<E::G1>,
    pub sk_0: Vec<SecretKey<E::G1>>,
    pub sk_1: Vec<SecretKey<E::G1>>,
    pub t: Vec<SecretKey<G2Projective_bls>>,
    pub t_0: Vec<G2Projective_bls>,
    pub t_1: Vec<G2Projective_bls>,
    pub y_0: Vec<Vec<u8>>,
    pub y_1: Vec<Vec<u8>>,
}

impl<E: Pairing> KeyShare<E> {
    pub fn key_share_gen<R: Rng>(rng: &mut R, pk_l: &G2Projective_bls, round: u64) -> Self {
        let g = <E::G1 as Group>::generator();
        let secret_key = <E::G1 as Group>::ScalarField::rand(rng);
        let public_key : E::G1 = g.mul(secret_key);
        let mut pk_vector_0: Vec<E::G1> = Vec::new();
        let mut pk_vector_1: Vec<E::G1> = Vec::new();
        let mut sk_vector_0: Vec<<E::G1 as Group>::ScalarField> = Vec::new();
        let mut sk_vector_1: Vec<<E::G1 as Group>::ScalarField> = Vec::new();
        let mut t_vector_0: Vec<<G2Projective_bls as Group>::ScalarField> = Vec::new();

        let mut t_vector_1: Vec<<G2Projective_bls as Group>::ScalarField> = Vec::new();
        let mut y_vector_0: Vec<Vec<u8>> = Vec::new();
        let mut y_vector_1: Vec<Vec<u8>> = Vec::new();

        let mut v_vector_0: Vec<G2Projective_bls> = Vec::new();
        let mut v_vector_1: Vec<G2Projective_bls> = Vec::new();

        let g2 = G2Projective_bls::generator();
        //let pk_l: G2Projective_bls = G2Projective_bls::generator();
        //let pk_l: <ark_bls12_381::Config>::G2 = Bls12_381::G2::generator();

        for _ in 0..K_SHARE {
            let sk_0 = <E::G1 as Group>::ScalarField::rand(rng);
            let sk_1 = secret_key - &sk_0;
            pk_vector_0.push(g.mul(&sk_0));
            pk_vector_1.push(g.mul(&sk_1));
            sk_vector_0.push(sk_0);
            sk_vector_1.push(sk_1);
            let t_0 = <G2Projective_bls as Group>::ScalarField::rand(rng);
            let t_1 = <G2Projective_bls as Group>::ScalarField::rand(rng);
            v_vector_0.push(g2.mul(&t_0));
            v_vector_1.push(g2.mul(&t_1));

            /*let z_0 = E1::pairing(hash_loe_g1(&round_to_bytes(TIME)), pk_l.mul(&t_0));
            let z_1 = E1::pairing(hash_loe_g1(&round_to_bytes(TIME)), pk_l.mul(&t_1));
            */

            let z_0 = Bls12_381::pairing(hash_loe_g1(&round_to_bytes(round)), pk_l.mul(&t_0));
            let z_1 = Bls12_381::pairing(hash_loe_g1(&round_to_bytes(round)), pk_l.mul(&t_1));



            t_vector_0.push(t_0);
            t_vector_1.push(t_1);
            let sk_ser_0 = serialize_compressed_f(&sk_0);
            let sk_ser_1 = serialize_compressed_f(&sk_1);
            let y_0 = xor(&hash_1(z_0), &sk_ser_0);
            let y_1 = xor(&hash_1(z_1), &sk_ser_1);
            y_vector_0.push(y_0);
            y_vector_1.push(y_1);
        }

        let hash_val = hash_2::<E>(
            &public_key,
            &pk_vector_0,
            &pk_vector_1,
            &v_vector_0,
            &v_vector_1,
            &y_vector_0,
            &y_vector_1,
        );

        let t_vector: Vec<<G2Projective_bls as Group>::ScalarField> = hash_val
            .iter()
            .take(K_SHARE as usize)
            .enumerate()
            .map(|(i, val)| match val {
                false => t_vector_0[i],
                true  => t_vector_1[i],
                //_ => panic!("Invalid value in c vector"),
            })
            .collect();

        let key_share = Self {
            //party: party, //this can be considered as the id
            pk: public_key,
            pk_0: pk_vector_0,
            pk_1: pk_vector_1,
            t: t_vector,
            t_0: v_vector_0,
            t_1: v_vector_1,
            y_0: y_vector_0,
            y_1: y_vector_1,
            sk: secret_key,
            sk_0: sk_vector_0,
            sk_1: sk_vector_1,
        };
        return key_share;
    }

    // sk_verification
    // sk_verify
    pub fn sk_verify(
        pk: &E::G1,
        t1: &<G2Projective_bls as Group>::ScalarField,
        t2: &G2Projective_bls,
        y: &Vec<u8>,
        round: u64,
    ) -> bool {
        let pk_l: G2Projective_bls = G2Projective_bls::generator();
        let g = E::G1::generator();
        let g2 = G2Projective_bls::generator();

        if g2.mul(t1) != *t2 {
            return false;
        }

        let z = Bls12_381::pairing(hash_loe_g1(&round_to_bytes(round)), pk_l.mul(t1));
        let sk0 = xor(&hash_1(z), y);
        let sk = E::ScalarField::deserialize_uncompressed(&*sk0).unwrap();
        if *pk != g.mul(sk) {
            return false;
        }
        true
    }

    // /// usage: k.verify_key_share();
    // pub fn verf_key_share(&self) -> bool {
    /// usage: KeyShare::<G1Projective, G2Projective_L>::verf_key_share(k);
    pub fn key_share_verify(k: &Self, round: u64) -> bool {
        //let k = key_share_gen();
        //let t = &k.pk_0[0] + &k.pk_1[0];
        //let a = &k.pk;
        //let g2 = G2::generator();

        for i in 0..K_SHARE {
            if k.pk_0[i as usize] + &k.pk_1[i as usize] != *&k.pk {
                return false;
            }
        }

        let hash_vrf = hash_2::<E>(
            //k.party,
            &k.pk,
            &k.pk_0,
            &k.pk_1,
            &k.t_0,
            &k.t_1,
            &k.y_0,
            &k.y_1,
        );

        let first_k_bits_vrf: Vec<bool> = hash_vrf.iter().take(K_SHARE as usize).collect();

        for i in 0..K_SHARE {
            for bit in first_k_bits_vrf.iter() {
                let vrf_result = match bit {
                    true => Self::sk_verify(
                        &k.pk_1[i as usize],
                        &k.t[i as usize],
                        &k.t_1[i as usize],
                        &k.y_1[i as usize],
                        round,
                    ),
                    false => Self::sk_verify(
                        &k.pk_0[i as usize],
                        &k.t[i as usize],
                        &k.t_0[i as usize],
                        &k.y_0[i as usize],
                        round
                    ),
                    //_ => panic!("Invalid bit value"),
                };
                if !vrf_result {
                    return vrf_result;
                }
            }
        }

        true
    }

    pub fn mpk_aggregation(key_shares: &Vec<Self>) -> E::G1 {
        let mut mpk = E::G1::zero();
        for i in 0..key_shares.len() {
            mpk = mpk + &key_shares[i as usize].pk;
        }
        return mpk;
    }

    #[allow(unused)]
    pub fn msk_aggregation(sk_t: &G1Affine_bls, key_shares: &Vec<Self>) -> E::ScalarField {
        let mut msk = E::ScalarField::zero();
        for i in 0..key_shares.len(){
            let z_0 = Bls12_381::pairing(sk_t, &key_shares[i as usize].t_0[0]);
            let z_1 = Bls12_381::pairing(sk_t, &key_shares[i as usize].t_1[0]);

            let sk0 = xor(&hash_1::<Bls12_381>(z_0) , &key_shares[i as usize].y_0[0]);
            let sk1 = xor(&hash_1::<Bls12_381>(z_1) , &key_shares[i as usize].y_1[0]);
            let sk_0  = E::ScalarField ::deserialize_uncompressed(&*sk0).unwrap();
            let sk_1  = E::ScalarField ::deserialize_uncompressed(&*sk1).unwrap();
            msk = msk + sk_0;
            msk = msk + sk_1;
        }
        return msk;
    }
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
