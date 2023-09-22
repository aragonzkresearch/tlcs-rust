mod bls_verify;
mod chain_functions;
mod hashes;
mod key_share;
mod primitives;

use ark_ed_on_bn254;
use ark_ff;
use ark_ed_on_bn254::{EdwardsProjective, EdwardsAffine};
use ark_ff::UniformRand;
use ark_ec::{Group, AffineRepr, CurveGroup};
use crate::primitives::group_to_hex;

fn main() {

    let mut rng = ark_std::test_rng();
    let scalar = EdwardsProjective::rand(&mut rng);

    let g = EdwardsProjective::generator();
    println!(" g = {}", g);
    let g_str = group_to_hex::<EdwardsProjective>(&g);
    println!("g_proj  = {}, len = {}", g_str, g_str.len());
    let example = "26A2B281C4EA791B498D67D3A206FE0E402594720EF675F5BA05B99637823C35";
    println!(" len = {}", example.len());

}
