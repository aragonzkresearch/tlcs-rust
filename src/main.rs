mod bls_verify;
mod chain_functions;
mod hashes;
mod key_share;
mod primitives;

use  ark_ed_on_bn254;
use  ark_ff;
use ark_ed_on_bn254::{EdwardsProjective, EdwardsAffine};
use ark_ff::UniformRand;
use ark_ec::{Group, AffineRepr, CurveGroup};

fn main() {
    // Generate a random scalar element
    let mut rng = ark_std::test_rng();
    let scalar = EdwardsProjective::rand(&mut rng);

    let g = EdwardsProjective::generator();
    let g_affine = EdwardsAffine::generator();
    println!(" g = {}", g);
    println!(" g = {}", g_affine);


    // Output or use the random element as needed
    println!("Random Element: {:?}", scalar);
}
