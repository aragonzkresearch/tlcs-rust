//use crate::bls_signature::*;
use crate::hashes::*;
use crate::primitives::*;

#[allow(unused)]
#[allow(dead_code)]

use ark_bls12_381::{Bls12_381, Fr as Fr_bls, G1Affine as G1Affine_bls, G2Projective as G2Projective_bls,  G2Affine as G2Affine_bls};
use ark_bn254::G2Affine;
/*
use ark_bls12_381::{
    Bls12_381, Fr as F_bls, G1Affine as G1Affine_bls, G1Projective as G1Projective_bls,
    G2Affine as G2Affine_bls, G2Projective as G2Projective_bls,
};
use ark_bn254::{
    Bn254, Fr as Fr_bn, G1Affine as G1Affine_bn, G1Projective as G1Projective_bn,
    G2Affine as G2Affine_bn, G2Projective as G2Projective_bn,
};
*/
use ark_ec::{pairing::Pairing, Group, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize,SerializationError, Validate, Valid, Compress};
use ark_std::io::{Read, Write};
use ark_std::{ops::Mul, rand::Rng, UniformRand, Zero};
use bit_vec::BitVec;

//pub type PublicKey<C> = C;
pub type SecretKey<C> = <C as Group>::ScalarField;

//pub const K_SHARE: u32 = 3;
pub const  Test_STRING: [bool; 3]=  [true , false , false];

#[derive(Debug,CanonicalSerialize, CanonicalDeserialize,PartialEq,Clone)]
pub struct KeyShare<E: Pairing> {
    pub pk: E::G1,
    pub pk_0: Vec<E::G1>,
    pub pk_1: Vec<E::G1>,
    pub t: Vec<SecretKey<G2Projective_bls>>,
    pub t_0: Vec<G2Projective_bls>,
    pub t_1: Vec<G2Projective_bls>,
    pub y_0: Vec<Vec<u8>>,
    pub y_1: Vec<Vec<u8>>,
}
/*
impl<E: Pairing> CanonicalSerialize for KeyShare<E> {
    fn serialize_with_mode<W: Write>(&self, mut writer: W, mode: Compress) -> Result<(), SerializationError> {
        self.pk.serialize_with_mode(&mut writer, mode)?;
        self.pk_0.serialize_with_mode(&mut writer, mode)?;
        self.pk_1.serialize_with_mode(&mut writer, mode)?;
        //self.sk.serialize_with_mode(&mut writer, mode)?;
        //self.sk_0.serialize_with_mode(&mut writer, mode)?;
        //self.sk_1.serialize_with_mode(&mut writer, mode)?;
        self.t.serialize_with_mode(&mut writer, mode)?;
        self.t_0.serialize_with_mode(&mut writer, mode)?;
        self.t_1.serialize_with_mode(&mut writer, mode)?;
        self.y_0.serialize_with_mode(&mut writer, mode)?;
        self.y_1.serialize_with_mode(&mut writer, mode)?;
        Ok(())
    }

    fn serialized_size(&self, mode: Compress) -> usize {
        self.pk.serialized_size(mode) +
        self.pk_0.serialized_size(mode) +
        self.pk_1.serialized_size(mode) +
        // self.sk.serialized_size(mode) +
        // self.sk_0.serialized_size(mode) +
        // self.sk_1.serialized_size(mode) +
        // self.t.serialized_size(mode) +
        self.t_0.serialized_size(mode) +
        self.t_1.serialized_size(mode) +
        self.y_0.serialized_size(mode) +
        self.y_1.serialized_size(mode)
    }
}

impl<E: Pairing> CanonicalDeserialize for KeyShare<E> {
    fn deserialize_with_mode<R: Read>(mut reader: R, compress: Compress, validate: Validate) -> Result<Self, SerializationError> {
        let pk = E::G1::deserialize_with_mode(&mut reader, compress, validate)?;
        let pk_0 = Vec::<E::G1>::deserialize_with_mode(&mut reader, compress, validate)?;
        let pk_1=  Vec::<E::G1>::deserialize_with_mode(&mut reader, compress, validate)?;
        // let sk = SecretKey::<E::G1>::deserialize_with_mode(&mut reader, compress, validate)?;
        // let sk_0 = Vec::<SecretKey<E::G1>>::deserialize_with_mode(&mut reader, compress, validate)?;
        // let sk_1 = Vec::<SecretKey<E::G1>>::deserialize_with_mode(&mut reader, compress, validate)?;
        let t = Vec::<SecretKey<G2Projective_bls>>::deserialize_with_mode(&mut reader, compress, validate)?;
        let t_0 =  Vec::<G2Projective_bls>::deserialize_with_mode(&mut reader, compress, validate)?;
        let t_1 = Vec::<G2Projective_bls>::deserialize_with_mode(&mut reader, compress, validate)?;
        let y_0 = Vec::<Vec<u8>>::deserialize_with_mode(&mut reader, compress, validate)?;
        let y_1 = Vec::<Vec<u8>>::deserialize_with_mode(&mut reader, compress, validate)?;
        Ok(Self {pk, pk_0, pk_1, t, t_0, t_1, y_0, y_1 })
    }
}

impl<E: Pairing>  Valid for KeyShare<E> {
    fn check(&self) -> Result<(), SerializationError> {
        self.pk.check()?;
        self.pk_0.check()?;
        self.pk_1.check()?;
        // self.sk.check()?;
        // self.sk_0.check()?;
        // self.sk_1.check()?;
        self.t.check()?;
        self.t_0.check()?;
        self.t_1.check()?;
        self.y_0.check()?;
        self.y_1.check()?;
       Ok(())
    }
}


 */
impl<E: Pairing> KeyShare<E> {
    #[allow(dead_code)]
    pub fn key_share_gen<R: Rng>(rng: &mut R, pk_loe_str: &str, round: u64, sec_param : usize) -> Self {

        let pk_loe = str_to_group::<G2Projective_bls>(pk_loe_str).unwrap();
        let pairing_generator_1 = <E::G1 as Group>::generator();

        let secret_key = <E::G1 as Group>::ScalarField::rand(rng);

        let public_key: E::G1 = pairing_generator_1.mul(secret_key);
        let mut pk_vector_0: Vec<E::G1> = Vec::new();
        let mut pk_vector_1: Vec<E::G1> = Vec::new();

        let mut sk_vector_0: Vec<<E::G1 as Group>::ScalarField> = Vec::new();
        let mut sk_vector_1: Vec<<E::G1 as Group>::ScalarField> = Vec::new();

        let mut t_vector_0: Vec<Fr_bls> = Vec::new();
        let mut t_vector_1: Vec<Fr_bls> = Vec::new();

        let mut y_vector_0: Vec<Vec<u8>> = Vec::new();
        let mut y_vector_1: Vec<Vec<u8>> = Vec::new();

        let mut v_vector_0: Vec<G2Projective_bls> = Vec::new();
        let mut v_vector_1: Vec<G2Projective_bls> = Vec::new();

        let bls_generator_2 = G2Projective_bls::generator();

        for _ in 0..sec_param {
            let sk_0 = <E::G1 as Group>::ScalarField::rand(rng);
            let sk_1 = secret_key - &sk_0;

            pk_vector_0.push(pairing_generator_1.mul(&sk_0));
            pk_vector_1.push(pairing_generator_1.mul(&sk_1));

            sk_vector_0.push(sk_0);
            sk_vector_1.push(sk_1);

            let t_0 = <G2Projective_bls as Group>::ScalarField::rand(rng);
            let t_1 = <G2Projective_bls as Group>::ScalarField::rand(rng);

            v_vector_0.push(bls_generator_2.mul(&t_0));
            v_vector_1.push(bls_generator_2.mul(&t_1));

            let z_0 = Bls12_381::pairing(hash_loe_g1(&round_to_bytes(round)), pk_loe.mul(&t_0));
            let z_1 = Bls12_381::pairing(hash_loe_g1(&round_to_bytes(round)), pk_loe.mul(&t_1));

            t_vector_0.push(t_0);
            t_vector_1.push(t_1);

            let sk_ser_0 = serialize_compressed_f(&sk_0);
            let sk_ser_1 = serialize_compressed_f(&sk_1);

            let y_0 = xor(&hash_1(z_0), &sk_ser_0);
            let y_1 = xor(&hash_1(z_1), &sk_ser_1);
            y_vector_0.push(y_0);
            y_vector_1.push(y_1);
            }

        let random_bit_string_value = hash_2::<E>(
                    &public_key,
                    &pk_vector_0,
                    &pk_vector_1,
                    &v_vector_0,
                    &v_vector_1,
                    &y_vector_0,
                    &y_vector_1,
                );

        let t_vector: Vec<Fr_bls> = random_bit_string_value
            .iter()
            .take(sec_param)
            .enumerate()
            .map(|(i, bit)| match bit {
                false => t_vector_0[i],
                true  => t_vector_1[i],
                //_ => panic!("Invalid value in c vector"),
            })
            .collect();

        let key_share = Self {
            pk: public_key,
            pk_0: pk_vector_0,
            pk_1: pk_vector_1,
            t: t_vector,
            t_0: v_vector_0,
            t_1: v_vector_1,
            y_0: y_vector_0,
            y_1: y_vector_1,
            };
        return key_share;
    }

    // secret_key_verification
    #[allow(unused)]
    pub fn sk_verify(
        pk_loe_str : &str,
        pk: &E::G1,
        t1: &Fr_bls,
        t2: &G2Projective_bls,
        y: &Vec<u8>,
        round: u64,
    ) -> bool {
        let pk_loe = str_to_group::<G2Projective_bls>(pk_loe_str).unwrap();
        let pk_affine = pk.into_affine();
        let pairing_generator_1 = E::G1::generator();//g
        let bls_generator_2 = G2Projective_bls::generator();

        let t_affine_0 = bls_generator_2.mul(t1).into_affine();
        let t_affine_1 = t2.into_affine();
        if t_affine_0 != t_affine_1{
            println!("1.t mohasebe = {}", t_affine_0);
            println!("2. t dade shode = {}", t_affine_1);
            println!("line 233");
            return false;

        }

        /*if bls_generator_2.mul(t1) != *t2 {
             println!("1.t mohasebe = {}", bls_generator_2.mul(t1));
             println!("2. t dade shode = {}", t2);
             println!("line 233");
            return false;
        }

         */

        let z = Bls12_381::pairing(hash_loe_g1(&round_to_bytes(round)), pk_loe.mul(t1));
        let sk0 = xor(&hash_1(z), y);
        let sk =<E::G1 as Group>::ScalarField::deserialize_compressed(&*sk0).unwrap();
        if pk_affine != pairing_generator_1.mul(sk).into() {
            return false;
        }
        true
    }

    #[allow(unused)]
    pub fn key_share_verify( pk_loe_str: &str, k: &Self, round: u64, sec_param : usize) -> bool {
        for i in 0..sec_param {
            if k.pk_0[i ] + &k.pk_1[i ] != *&k.pk {
                return false;
            }
        }

        let hash_vrf = hash_2::<E>(
            &k.pk,
            &k.pk_0,
            &k.pk_1,
            &k.t_0,
            &k.t_1,
            &k.y_0,
            &k.y_1);

        let first_k_bits_vrf: Vec<bool> = hash_vrf.iter().take(sec_param ).collect();

        for i in 0..sec_param {
            for bit in first_k_bits_vrf.iter() {
                let vrf_result = match bit {
                    true => Self::sk_verify(
                        pk_loe_str,
                        &k.pk_1[i ],
                        &k.t[i],
                        &k.t_1[i ],
                        &k.y_1[i ],
                        round,
                    ),
                    false => Self::sk_verify(
                        pk_loe_str,
                        &k.pk_0[i ],
                        &k.t[i ],
                        &k.t_0[i ],
                        &k.y_0[i ],
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

    #[allow(dead_code)]
    pub fn mpk_aggregation(key_shares: &Vec<Self>) -> E::G1 {
        let mut mpk = E::G1::zero();
        for i in 0..key_shares.len() {
            mpk = mpk + &key_shares[i ].pk;
        }
        return mpk;
    }

    #[allow(unused)]
    pub fn msk_aggregation(sk_t: &G1Affine_bls, key_shares: &Vec<Self>) -> E::ScalarField {
        let mut msk = E::ScalarField::zero();
        for i in 0..key_shares.len() {
            let z_0 = Bls12_381::pairing(sk_t, &key_shares[i ].t_0[0]);
            let z_1 = Bls12_381::pairing(sk_t, &key_shares[i ].t_1[0]);

            let sk0 = xor(&hash_1::<Bls12_381>(z_0), &key_shares[i ].y_0[0]);
            let sk1 = xor(&hash_1::<Bls12_381>(z_1), &key_shares[i ].y_1[0]);
            let sk_0 = E::ScalarField::deserialize_compressed(&*sk0).unwrap();
            let sk_1 = E::ScalarField::deserialize_compressed(&*sk1).unwrap();
            msk = msk + sk_0;
            msk = msk + sk_1;
        }
        return msk;
    }
}
/*
#[cfg(test)]
mod tests {
    use super::*;

    //use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;

    #[test]
    fn test_aggregation() {
        //type KS = KeyShare<Bn254>; // "type alias"
        let mut rng = ark_std::test_rng();
        let pk_loe_str = "a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e";
        let round = 34;

        let _ks = KeyShare::<Bn254>::key_share_gen(&mut rng, &pk_loe_str, round);

        todo!();
    }
}

 */
