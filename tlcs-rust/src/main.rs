mod key_share;
mod primitives;
mod drand;
mod bls_signature;

use key_share::*;
use bls_signature::*;

#[allow(unused)]
#[allow(dead_code)]

#[tokio::main]
async fn main(){
    let k = key_share_gen(2);
    let b = verf_key_share(&k);

    let mut k_vec: Vec<KeyShare> = Vec::new();
    k_vec.push(k);

    let mpk = mpk_aggregation(&k_vec);

    //let sk_t = todo!(); // published by the LoE

    //let msk = msk_aggregation(&sk_t , &k_vec);
}

#[cfg(test)]
mod tests {
    //use serial_test::serial;

    use super::*;

    #[test]
    //#[serial]
    fn verify_participant_data_works() {
        //let participant_data = key_share_gen(2);
        //let verified = verf_key_share(2, participant_data);
        let participant_data: KeyShare = key_share_gen();
        let verified = verf_key_share(&participant_data);

        assert!(verified);
    }

    #[test]
    //#[serial]
    fn aggregate_participant_data_works() {
        let mut all_participant_data: Vec<KeyShare> = Vec::new();
        let mut participant_data_1 = key_share_gen();
        let mut participant_data_2 = key_share_gen();
        //all_participant_data.append(&mut participant_data_2);
        //let public_key = mpk_aggregation(all_participant_data);
        //let vec_public_key = hex::decode(public_key).expect("will return valid hex");
        all_participant_data.push(participant_data_1);
        all_participant_data.push(participant_data_2);
        let public_key = mpk_aggregation(&all_participant_data);
        //let vec_public_key = hex::decode(public_key).expect("will return valid hex");

        assert!(vec_public_key.len() == 33)
    }

    #[test]
    //#[serial]
    fn make_secret_key_works() {
        //let mut all_participant_data = key_share_gen(2);
        //let mut participant_data_2 = key_share_gen(2);
        //all_participant_data.append(&mut participant_data_2);
        let public_key: Vec<u8> = mpk_aggregation(all_participant_data.clone());

        // retrieved from https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/public/2
        let signature: Vec<u8> = hex::decode("a050676d1a1b6ceedb5fb3281cdfe88695199971426ff003c0862460b3a72811328a07ecd53b7d57fc82bb67f35efaf1").unwrap();

        let secret_key = msk_aggregation(all_participant_data, 2, signature, public_key);
        let vec_secret_key = hex::decode(secret_key).expect("will return valid hex");

        assert!(vec_secret_key.len() == 32)
    }
}
