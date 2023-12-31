use crate::hashes::*;
use crate::primitives::*;

#[allow(unused)]
#[allow(dead_code)]
use ark_bls12_381::{
    Bls12_381, Fr as Fr_bls, G1Affine as G1Affine_bls, G2Affine as G2Affine_bls,
    G2Projective as G2Projective_bls,
};
use ark_ec::{pairing::Pairing, CurveGroup, Group};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::Mul, rand::Rng, UniformRand, Zero};

pub type PublicKey<C> = C;
pub type SecretKey<C> = <C as Group>::ScalarField;

#[derive(Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq, Clone)]
pub struct KeyShare<E: CurveGroup> {
    pub pk: PublicKey<E>,
    pub pk_0: Vec<PublicKey<E>>,
    pub pk_1: Vec<PublicKey<E>>,
    pub t: Vec<SecretKey<G2Projective_bls>>,
    pub t_0: Vec<PublicKey<G2Projective_bls>>,
    pub t_1: Vec<PublicKey<G2Projective_bls>>,
    pub y_0: Vec<Vec<u8>>,
    pub y_1: Vec<Vec<u8>>,
}

impl<E: CurveGroup> KeyShare<E> {
    #[allow(dead_code)]
    pub fn key_share_gen<R: Rng>(
        rng: &mut R,
        pk_loe_str: &str,
        round: u64,
        sec_param: usize,
    ) -> Self {
        let pk_loe = str_to_group::<G2Projective_bls>(pk_loe_str).unwrap();
        let pairing_generator_1 = <E as Group>::generator();
        let bls_generator_2 = G2Projective_bls::generator();

        let secret_key = <E as Group>::ScalarField::rand(rng);

        let public_key: E = pairing_generator_1.mul(secret_key);
        let mut pk_vector_0: Vec<E> = Vec::new();
        let mut pk_vector_1: Vec<E> = Vec::new();

        let mut sk_vector_0: Vec<<E as Group>::ScalarField> = Vec::new();
        let mut sk_vector_1: Vec<<E as Group>::ScalarField> = Vec::new();

        let mut t_vector_0: Vec<SecretKey<G2Projective_bls>> = Vec::new();
        let mut t_vector_1: Vec<SecretKey<G2Projective_bls>> = Vec::new();

        let mut y_vector_0: Vec<Vec<u8>> = Vec::new();
        let mut y_vector_1: Vec<Vec<u8>> = Vec::new();

        #[allow(non_snake_case)]
        let mut T_vector_0: Vec<PublicKey<G2Projective_bls>> = Vec::new();
        #[allow(non_snake_case)]
        let mut T_vector_1: Vec<PublicKey<G2Projective_bls>> = Vec::new();

        for _ in 0..sec_param {
            let sk_0 = <E as Group>::ScalarField::rand(rng);
            let sk_1 = secret_key - &sk_0;

            pk_vector_0.push(pairing_generator_1.mul(&sk_0));
            pk_vector_1.push(pairing_generator_1.mul(&sk_1));

            sk_vector_0.push(sk_0);
            sk_vector_1.push(sk_1);

            let t_0 = <G2Projective_bls as Group>::ScalarField::rand(rng);
            //let t_0 = SecretKey<G2Projective_bls>::rand(rng); These are not same?
            let t_1 = <G2Projective_bls as Group>::ScalarField::rand(rng);

            t_vector_0.push(t_0);
            t_vector_1.push(t_1);

            T_vector_0.push(bls_generator_2.mul(&t_0));
            T_vector_1.push(bls_generator_2.mul(&t_1));
            //println!("gen : t_0 = {}", bls_generator_2.mul(&t_0));
            //println!("gen : t_1 = {}", bls_generator_2.mul(&t_1));

            let z_0 = Bls12_381::pairing(hash_loe_g1(&message(round)), pk_loe.mul(&t_0));
            let z_1 = Bls12_381::pairing(hash_loe_g1(&message(round)), pk_loe.mul(&t_1));

            let sk_ser_0 = serialize_compressed_f(&sk_0);
            let sk_ser_1 = serialize_compressed_f(&sk_1);
            //println!(" sk_ser_0 = {:?}",  sk_ser_0);
            //println!(" sk_ser_1 = {:?}",  sk_ser_1);

            let y_0 = xor(&hash_1(z_0), &sk_ser_0);
            let y_1 = xor(&hash_1(z_1), &sk_ser_1);

            y_vector_0.push(y_0);
            y_vector_1.push(y_1);
        }

        let random_bit_string_value = hash_2::<E>(
            &public_key,
            &pk_vector_0,
            &pk_vector_1,
            &T_vector_0,
            &T_vector_1,
            &y_vector_0,
            &y_vector_1,
        );
        if random_bit_string_value.len() < sec_param {
            println!(" the bit string is not long enough!");
        }

        let t_vector: Vec<SecretKey<G2Projective_bls>> = random_bit_string_value
            .iter()
            .take(sec_param)
            .enumerate()
            .map(|(i, bit)| match bit {
                false => t_vector_0[i],
                true => t_vector_1[i],
            })
            .collect();

        let key_share = Self {
            pk: public_key,
            pk_0: pk_vector_0,
            pk_1: pk_vector_1,
            t: t_vector,
            t_0: T_vector_0,
            t_1: T_vector_1,
            y_0: y_vector_0,
            y_1: y_vector_1,
        };
        return key_share;
    }

    // secret_key_verification
    #[allow(unused)]
    pub fn sk_verify(
        pk_loe_str: &str,
        pk: &E,
        t: &SecretKey<G2Projective_bls>,
        #[allow(non_snake_case)] T: &G2Projective_bls,
        y: &Vec<u8>,
        round: u64,
    ) -> bool {
        let pk_loe = str_to_group::<G2Projective_bls>(pk_loe_str).unwrap();
        let pairing_generator_1 = E::generator();
        let bls_generator_2 = G2Projective_bls::generator();

        #[allow(non_snake_case)]
        let T_A = T.clone().into_affine();

        #[allow(non_snake_case)]
        let T_P = bls_generator_2.mul(t).into_affine();

        if T_A != T_P {
            println!("g^t = {}", bls_generator_2.mul(t));
            println!("T = {}", T);
            println!("line 238");
            return false;
        }

        let z = Bls12_381::pairing(hash_loe_g1(&message(round)), pk_loe.mul(t));
        let sk0 = xor(&hash_1(z), y);
        let sk = <E as Group>::ScalarField::deserialize_compressed(&*sk0).unwrap();
        if *pk != pairing_generator_1.mul(sk) {
            println!("line 246");
            return false;
        }
        true
    }

    #[allow(unused)]
    pub fn key_share_verify(pk_loe_str: &str, k: &Self, round: u64, sec_param: usize) -> bool {
        //println!("verifiaction starts");
        let pk_loe = str_to_group::<G2Projective_bls>(pk_loe_str).unwrap();
        for i in 0..sec_param {
            if k.pk_0[i] + &k.pk_1[i] != *&k.pk {
                return false;
            }
        }

        let hash_vrf = hash_2::<E>(&k.pk, &k.pk_0, &k.pk_1, &k.t_0, &k.t_1, &k.y_0, &k.y_1);

        let first_k_bits_vrf: Vec<bool> = hash_vrf.iter().take(sec_param).collect();

        for (index, &bit) in first_k_bits_vrf.iter().enumerate() {
            if bit {
                //println!("bit is true {}",bit);
                if !Self::sk_verify(
                    pk_loe_str,
                    &k.pk_1[index],
                    &k.t[index],
                    &k.t_1[index],
                    &k.y_1[index],
                    round,
                ) {
                    return false;
                }
            } else {
                //println!("bit is false {}",bit);
                if !Self::sk_verify(
                    pk_loe_str,
                    &k.pk_0[index],
                    &k.t[index],
                    &k.t_0[index],
                    &k.y_0[index],
                    round,
                ) {
                    return false;
                }
            }
        }

        true
    }
    #[allow(dead_code)]
    pub fn mpk_aggregation(key_shares: &Vec<Self>) -> E {
        let mut mpk = E::zero();
        for i in 0..key_shares.len() {
            mpk = mpk + &key_shares[i].pk;
        }
        return mpk;
    }

    #[allow(unused)]
    pub fn msk_aggregation(
        round_secret_key: &G1Affine_bls,
        key_shares: &Vec<Self>,
    ) -> E::ScalarField {
        //let pk_loe = str_to_group::<G2Projective_bls>(pk_loe_str).unwrap();
        let mut msk = E::ScalarField::zero();
        println!("round_secret_key {}", round_secret_key);
        for i in 0..key_shares.len() {
            println!(" msk key {}", i);
            let z_0 = Bls12_381::pairing(round_secret_key, &key_shares[i].t_0[0]);
            let z_1 = Bls12_381::pairing(round_secret_key, &key_shares[i].t_1[0]);
            println!("msk z_0 = {}", z_0);
            println!("msk z_1 = {}", z_1);
            println!("\n");
            //println!("msk t_0 = {}", &key_shares[i].t_0[0]);
            //println!("msk t_1 = {}", &key_shares[i].t_1[0]);

            let sk0 = xor(&hash_1::<Bls12_381>(z_0), &key_shares[i].y_0[0]);
            let sk1 = xor(&hash_1::<Bls12_381>(z_1), &key_shares[i].y_1[0]);
            //println!("sk_0 = {:?}", sk0);
            //println!("sk_1 = {:?}", sk1);

            let sk_0 = <E as Group>::ScalarField::deserialize_compressed(&*sk0).unwrap();
            let sk_1 = <E as Group>::ScalarField::deserialize_compressed(&*sk1).unwrap();
            msk = msk + sk_0;
            msk = msk + sk_1;
        }
        println!("msk = {:?}", msk);
        return msk;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::G1Projective as G1Projective_bls;
    //use ark_secp256k1 :: Projective as tlcs_curve;
    use ark_ed_on_bn254::EdwardsProjective as tlcs_curve;
    //use ark_secp256k1 ::{Projective as tlcs_curve, Fr as Fr_tlcs};

    const LOE_PUBLIC_KEY: &str = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
    const SIGNATURE: &str = "b6b6a585449b66eb12e875b64fcbab3799861a00e4dbf092d99e969a5eac57dd3f798acf61e705fe4f093db926626807"; // For testing
    const ROUND: u64 = 2;
    const SECURITY_PARAM: usize = 2;

    #[test]

    fn aggregation_is_correct() {
        let mut rng = ark_std::test_rng();
        //let mut rng = ark_std::rand::thread_rng();

        type TlcsKeyShare = KeyShare<tlcs_curve>;
        let mut all_key_share: Vec<TlcsKeyShare> = Vec::new();

        for _i in 0..2 {
            let ks = TlcsKeyShare::key_share_gen(&mut rng, &LOE_PUBLIC_KEY, ROUND, SECURITY_PARAM);
            let verified =
                TlcsKeyShare::key_share_verify(&LOE_PUBLIC_KEY, &ks, ROUND, SECURITY_PARAM);
            all_key_share.push(ks);
            assert!(verified);
        }
        let pk = &all_key_share[0].pk + &all_key_share[1].pk;
        let sk_round = str_to_group::<G1Projective_bls>(SIGNATURE)
            .unwrap()
            .into_affine();
        //println!("sk_round = {}", sk_round);
        let msk = TlcsKeyShare::msk_aggregation(&sk_round, &all_key_share);
        let mpk = TlcsKeyShare::mpk_aggregation(&all_key_share);
        let g = tlcs_curve::generator();
        let mpk_test = g.mul(&msk);
        assert_eq!(mpk, mpk_test);
        assert_eq!(pk, mpk);
    }
}

