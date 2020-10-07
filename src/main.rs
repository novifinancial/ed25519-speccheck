// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the APACHE 2.0 license found in
// the LICENSE file in the root directory of this source tree.

use anyhow::{anyhow, Result};
use core::ops::Neg;

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::EdwardsPoint, scalar::Scalar, traits::IsIdentity,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sha2::{Digest, Sha512};

use serde::ser::{Serialize, SerializeStruct, Serializer};
use std::fs::File;
use std::io::prelude::*;

#[macro_use]
extern crate log;

// The 8-torsion subgroup E[8].
//
// In the case of Curve25519, it is cyclic; the i-th element of
// the array is [i]P, where P is a point of order 8
// generating E[8].
//
// Thus E[8] is the points indexed by `0,2,4,6`, and
// E[2] is the points indexed by `0,4`.
//
// The following byte arrays have been ported from curve25519-dalek /backend/serial/u64/constants.rs
// and they represent the serialised version of the CompressedEdwardsY points.
const EIGHT_TORSION: [[u8; 32]; 8] = [
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ], // (0,1), order 1, neutral element
    [
        199, 23, 106, 112, 61, 77, 216, 79, 186, 60, 11, 118, 13, 16, 103, 15, 42, 32, 83, 250, 44,
        57, 204, 198, 78, 199, 253, 119, 146, 172, 3, 122,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 128,
    ],
    [
        38, 232, 149, 143, 194, 178, 39, 176, 69, 195, 244, 137, 242, 239, 152, 240, 213, 223, 172,
        5, 211, 198, 51, 57, 177, 56, 2, 136, 109, 83, 252, 5,
    ],
    [
        236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
    ],
    [
        38, 232, 149, 143, 194, 178, 39, 176, 69, 195, 244, 137, 242, 239, 152, 240, 213, 223, 172,
        5, 211, 198, 51, 57, 177, 56, 2, 136, 109, 83, 252, 133,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    [
        199, 23, 106, 112, 61, 77, 216, 79, 186, 60, 11, 118, 13, 16, 103, 15, 42, 32, 83, 250, 44,
        57, 204, 198, 78, 199, 253, 119, 146, 172, 3, 250,
    ],
];

// 8 as a Scalar - to reflect instructions of "interpreting values as
// integers"
fn eight() -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[31] |= 8;
    Scalar::from_bytes_mod_order(bytes)
}

fn multiple_of_eight_le(scalar: Scalar) -> bool {
    scalar.to_bytes()[31].trailing_zeros() >= 3
}

pub fn check_slice_size<'a>(
    slice: &'a [u8],
    expected_len: usize,
    arg_name: &'static str,
) -> Result<&'a [u8]> {
    if slice.len() != expected_len {
        return Err(anyhow!(
            "slice length for {} must be {} characters, got {}",
            arg_name,
            expected_len,
            slice.len()
        ));
    }
    Ok(slice)
}

fn deserialize_point(pt: &[u8]) -> Result<EdwardsPoint> {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(check_slice_size(pt, 32, "pt")?);

    curve25519_dalek::edwards::CompressedEdwardsY(bytes)
        .decompress()
        .ok_or_else(|| anyhow!("Point decompression failed!"))
}

#[allow(dead_code)]
fn deserialize_scalar(scalar: &[u8]) -> Result<Scalar> {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(check_slice_size(scalar, 32, "scalar")?);

    // This permissive pass-through can produce large scalars!
    Ok(curve25519_dalek::scalar::Scalar::from_bits(bytes))
}

#[allow(dead_code)]
fn deserialize_signature(sig_bytes: &[u8]) -> Result<(EdwardsPoint, Scalar)> {
    let checked_sig_bytes = check_slice_size(sig_bytes, 64, "sig_bytes")?;
    let r = deserialize_point(&checked_sig_bytes[..32])?;
    let s = deserialize_scalar(&checked_sig_bytes[32..])?;
    Ok((r, s))
}

fn serialize_signature(r: &EdwardsPoint, s: &Scalar) -> Vec<u8> {
    [&r.compress().as_bytes()[..], &s.as_bytes()[..]].concat()
}

fn compute_hram(message: &[u8], pub_key: &EdwardsPoint, signature_r: &EdwardsPoint) -> Scalar {
    let k_bytes = Sha512::default()
        .chain(&signature_r.compress().as_bytes())
        .chain(&pub_key.compress().as_bytes()[..])
        .chain(&message);
    // curve25519_dalek is stuck on an old digest version, so we can't do
    // Scalar::from_hash
    let mut k_output = [0u8; 64];
    k_output.copy_from_slice(k_bytes.finalize().as_slice());
    Scalar::from_bytes_mod_order_wide(&k_output)
}

fn compute_hram_with_r_array(message: &[u8], pub_key: &EdwardsPoint, signature_r: &[u8]) -> Scalar {
    let k_bytes = Sha512::default()
        .chain(&signature_r)
        .chain(&pub_key.compress().as_bytes()[..])
        .chain(&message);
    // curve25519_dalek is stuck on an old digest version, so we can't do
    // Scalar::from_hash
    let mut k_output = [0u8; 64];
    k_output.copy_from_slice(k_bytes.finalize().as_slice());
    Scalar::from_bytes_mod_order_wide(&k_output)
}

fn compute_hram_with_pk_array(
    message: &[u8],
    pub_key_arr: &[u8],
    signature_r: &EdwardsPoint,
) -> Scalar {
    let k_bytes = Sha512::default()
        .chain(&signature_r.compress().as_bytes())
        .chain(&pub_key_arr)
        .chain(&message);
    // curve25519_dalek is stuck on an old digest version, so we can't do
    // Scalar::from_hash
    let mut k_output = [0u8; 64];
    k_output.copy_from_slice(k_bytes.finalize().as_slice());
    Scalar::from_bytes_mod_order_wide(&k_output)
}

fn verify_cofactored(
    message: &[u8],
    pub_key: &EdwardsPoint,
    unpacked_signature: &(EdwardsPoint, Scalar),
) -> Result<()> {
    let k = compute_hram(message, pub_key, &unpacked_signature.0);
    verify_final_cofactored(pub_key, unpacked_signature, &k)
}

fn verify_cofactorless(
    message: &[u8],
    pub_key: &EdwardsPoint,
    unpacked_signature: &(EdwardsPoint, Scalar),
) -> Result<()> {
    let k = compute_hram(message, pub_key, &unpacked_signature.0);
    verify_final_cofactorless(pub_key, unpacked_signature, &k)
}

fn verify_pre_reduced_cofactored(
    message: &[u8],
    pub_key: &EdwardsPoint,
    unpacked_signature: &(EdwardsPoint, Scalar),
) -> Result<()> {
    let k = compute_hram(message, pub_key, &unpacked_signature.0);
    verify_final_pre_reduced_cofactored(pub_key, unpacked_signature, &k)
}

fn verify_final_cofactored(
    pub_key: &EdwardsPoint,
    unpacked_signature: &(EdwardsPoint, Scalar),
    hash: &Scalar,
) -> Result<()> {
    let rprime = EdwardsPoint::vartime_double_scalar_mul_basepoint(
        &hash,
        &pub_key.neg(),
        &unpacked_signature.1,
    );
    if (unpacked_signature.0 - rprime)
        .mul_by_cofactor()
        .is_identity()
    {
        Ok(())
    } else {
        Err(anyhow!("Invalid cofactored signature"))
    }
}

fn verify_final_pre_reduced_cofactored(
    pub_key: &EdwardsPoint,
    unpacked_signature: &(EdwardsPoint, Scalar),
    hash: &Scalar,
) -> Result<()> {
    let eight_hash = eight() * hash;
    let eight_s = eight() * unpacked_signature.1;

    let rprime =
        EdwardsPoint::vartime_double_scalar_mul_basepoint(&eight_hash, &pub_key.neg(), &eight_s);
    if (unpacked_signature.0.mul_by_cofactor() - rprime).is_identity() {
        Ok(())
    } else {
        Err(anyhow!("Invalid pre-reduced cofactored signature"))
    }
}

fn verify_final_cofactorless(
    pub_key: &EdwardsPoint,
    unpacked_signature: &(EdwardsPoint, Scalar),
    hash: &Scalar,
) -> Result<()> {
    let rprime = EdwardsPoint::vartime_double_scalar_mul_basepoint(
        &hash,
        &pub_key.neg(),
        &unpacked_signature.1,
    );
    if (unpacked_signature.0 - rprime).is_identity() {
        Ok(())
    } else {
        Err(anyhow!("Invalid cofactorless signature"))
    }
}

///////////
// Cases //
///////////

pub struct TestVector {
    #[allow(dead_code)]
    message: [u8; 32],
    #[allow(dead_code)]
    pub_key: [u8; 32],
    #[allow(dead_code)]
    signature: Vec<u8>,
}

impl Serialize for TestVector {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Color", 3)?;
        state.serialize_field("message", &hex::encode(&self.message))?;
        state.serialize_field("pub_key", &hex::encode(&self.pub_key))?;
        state.serialize_field("signature", &hex::encode(&self.signature))?;
        state.end()
    }
}

fn new_rng() -> impl RngCore {
    let mut pi_bytes = [0u8; 32];
    for i in 0..4 {
        pi_bytes[8 * i..8 * i + 8].copy_from_slice(&std::f64::consts::PI.to_le_bytes()[..]);
    }
    StdRng::from_seed(pi_bytes)
}

fn pick_small_nonzero_point(idx: usize) -> EdwardsPoint {
    deserialize_point(&EIGHT_TORSION[(idx % 7 + 1)]).unwrap()
}

//////////////////////
// 0 (cofactored)   //
// 1 (cofactorless) //
//////////////////////

pub fn zero_small_small() -> Result<(TestVector, TestVector), anyhow::Error> {
    let mut rng = new_rng();
    // Pick a torsion point
    let small_idx: usize = rng.next_u64() as usize;

    let pub_key = pick_small_nonzero_point(small_idx + 1);
    let r = pub_key.neg();
    let s = Scalar::zero();

    let mut message = [0u8; 32];
    rng.fill_bytes(&mut message);
    if (r + compute_hram(&message, &pub_key, &r) * pub_key).is_identity() {
        return Err(anyhow!("wrong rng seed"));
    }
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_err());
    debug!(
        "S=0, small A, small R\n\
             passes cofactored, fails cofactorless, repudiable\n\
             \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    let tv1 = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    while !(r + compute_hram(&message, &pub_key, &r) * pub_key).is_identity() {
        rng.fill_bytes(&mut message);
    }

    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_ok());

    debug!(
        "S=0, small A, small R\n\
         passes cofactored, passes cofactorless, repudiable\n\
         \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    let tv2 = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    Ok((tv1, tv2))
}

//////////////////////
// 2 (cofactored)   //
// 3 (cofactorless) //
//////////////////////

pub fn non_zero_mixed_small() -> Result<(TestVector, TestVector)> {
    let mut rng = new_rng();
    // Pick a random Scalar
    let mut scalar_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);
    let s = Scalar::from_bytes_mod_order(scalar_bytes);
    debug_assert!(s.is_canonical());
    debug_assert!(s != Scalar::zero());

    let r0 = s * ED25519_BASEPOINT_POINT;

    // Pick a torsion point
    let small_idx: usize = rng.next_u64() as usize;
    let pub_key = pick_small_nonzero_point(small_idx + 1);

    let r = r0 + pub_key.neg();

    let mut message = [0u8; 32];
    rng.fill_bytes(&mut message);
    if (pub_key.neg() + compute_hram(&message, &pub_key, &r) * pub_key).is_identity() {
        return Err(anyhow!("wrong rng seed"));
    }
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_err());
    debug!(
        "S > 0, small A, mixed R\n\
             passes cofactored, fails cofactorless, repudiable\n\
             \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    let tv1 = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    while !(pub_key.neg() + compute_hram(&message, &pub_key, &r) * pub_key).is_identity() {
        rng.fill_bytes(&mut message);
    }
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_ok());
    debug!(
        "S > 0, small A, mixed R\n\
         passes cofactored, passes cofactorless, repudiable\n\
         \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    let tv2 = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    Ok((tv1, tv2))
}

//////////////////////
// 4 (cofactored)   //
// 5 (cofactorless) //
//////////////////////

// The symmetric case from non_zero_mixed_small
pub fn non_zero_small_mixed() -> Result<(TestVector, TestVector)> {
    let mut rng = new_rng();
    // Pick a random scalar
    let mut scalar_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);
    let a = Scalar::from_bytes_mod_order(scalar_bytes);
    debug_assert!(a.is_canonical());
    debug_assert!(a != Scalar::zero());

    let pub_key_component = a * ED25519_BASEPOINT_POINT;

    // Pick a torsion point
    let small_idx: usize = rng.next_u64() as usize;
    let r = pick_small_nonzero_point(small_idx + 1);

    let pub_key = pub_key_component + r.neg();

    let mut message = [0u8; 32];
    rng.fill_bytes(&mut message);
    if (r + compute_hram(&message, &pub_key, &r) * r.neg()).is_identity() {
        return Err(anyhow!("wrong rng seed"));
    }
    let s = compute_hram(&message, &pub_key, &r) * a;
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_err());
    debug!(
        "S > 0, mixed A, small R\n\
             passes cofactored, fails cofactorless, leaks private key\n\
             \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );

    let tv1 = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    while !(r + compute_hram(&message, &pub_key, &r) * r.neg()).is_identity() {
        rng.fill_bytes(&mut message);
    }
    let s = compute_hram(&message, &pub_key, &r) * a;
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_ok());
    debug!(
        "S > 0, mixed A, small R\n\
         passes cofactored, passes cofactorless, leaks private key\n\
         \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    let tv2 = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    Ok((tv1, tv2))
}

//////////////////////
// 6 (cofactored)   //
// 7 (cofactorless) //
//////////////////////

pub fn non_zero_mixed_mixed() -> Result<(TestVector, TestVector)> {
    let mut rng = new_rng();
    // Pick a random scalar
    let mut scalar_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);
    let a = Scalar::from_bytes_mod_order(scalar_bytes);
    debug_assert!(a.is_canonical());
    debug_assert!(a != Scalar::zero());
    // Pick a random nonce
    let nonce_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);

    // Pick a torsion point
    let small_idx: usize = rng.next_u64() as usize;
    let small_pt = pick_small_nonzero_point(small_idx + 1);

    // generate the r of a "normal" signature
    let prelim_pub_key = a * ED25519_BASEPOINT_POINT;

    let mut message = [0u8; 32];
    rng.fill_bytes(&mut message);
    let mut h = Sha512::new();
    h.update(&nonce_bytes);
    h.update(&message);

    let mut output = [0u8; 64];
    output.copy_from_slice(h.finalize().as_slice());
    let mut prelim_r = curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&output);

    let pub_key = prelim_pub_key + small_pt;
    let mut r = prelim_r * ED25519_BASEPOINT_POINT + small_pt.neg();

    if (small_pt.neg() + compute_hram(&message, &pub_key, &r) * small_pt).is_identity() {
        return Err(anyhow!("wrong rng seed"));
    }
    let s = prelim_r + compute_hram(&message, &pub_key, &r) * a;
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_err());
    debug!(
        "S > 0, mixed A, mixed R\n\
             passes cofactored, fails cofactorless\n\
             \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );

    let tv1 = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    while !(small_pt.neg() + compute_hram(&message, &pub_key, &r) * small_pt).is_identity() {
        rng.fill_bytes(&mut message);
        let mut h = Sha512::new();
        h.update(&nonce_bytes);
        h.update(&message);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.finalize().as_slice());
        prelim_r = curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&output);

        r = prelim_r * ED25519_BASEPOINT_POINT + small_pt.neg();
    }
    let s = prelim_r + compute_hram(&message, &pub_key, &r) * a;
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_ok());
    debug!(
        "S > 0, mixed A, mixed R\n\
         passes cofactored, passes cofactorless\n\
         \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    let tv2 = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    Ok((tv1, tv2))
}

////////////////////////////
// 8 (pre-reduced scalar) //
////////////////////////////

fn pre_reduced_scalar() -> Result<TestVector> {
    let mut rng = new_rng();

    // Pick a random scalar
    let mut scalar_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);
    let a = Scalar::from_bytes_mod_order(scalar_bytes);
    debug_assert!(a.is_canonical());
    debug_assert!(a != Scalar::zero());
    // Pick a random nonce
    let nonce_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);

    // generate the r of a "normal" signature
    let prelim_pub_key = a * ED25519_BASEPOINT_POINT;

    // Pick a torsion point
    let small_idx: usize = rng.next_u64() as usize;
    let small_pt = pick_small_nonzero_point(small_idx + 1);
    let pub_key = prelim_pub_key + small_pt;

    let mut message = [0u8; 32];
    rng.fill_bytes(&mut message);
    let mut h = Sha512::new();
    h.update(&nonce_bytes);
    h.update(&message);

    let mut output = [0u8; 64];
    output.copy_from_slice(h.finalize().as_slice());
    let r_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&output);
    let r = r_scalar * ED25519_BASEPOINT_POINT;

    // grind a k so that 8*k gets reduced to a number NOT multiple of eight,
    // and add a small order component to the public key.
    while multiple_of_eight_le(eight() * compute_hram(&message, &pub_key, &r)) {
        rng.fill_bytes(&mut message);
    }

    let s = r_scalar + compute_hram(&message, &pub_key, &r) * a;

    // that's because we do cofactored verification without pre-reducing scalars
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());

    // pre-reducing is a mistake
    debug_assert!(verify_pre_reduced_cofactored(&message, &pub_key, &(r, s)).is_err());

    // as expected
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_err());
    debug!(
        "S > 0, mixed A, large order R\n\
         passes cofactored, fails pre-reducing cofactored, fails cofactorless\n\
         \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    let tv = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };
    Ok(tv)
}

mod non_reducing_scalar52;
use non_reducing_scalar52::Scalar52;

////////
// 9  //
////////

fn large_s() -> Result<TestVector> {
    let mut rng = new_rng();
    // Pick a random scalar
    let mut scalar_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);
    let a = Scalar::from_bytes_mod_order(scalar_bytes);
    debug_assert!(a.is_canonical());
    debug_assert!(a != Scalar::zero());
    // Pick a random nonce
    let nonce_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);

    // generate the r of a "normal" signature
    let pub_key = a * ED25519_BASEPOINT_POINT;

    let mut message = [0u8; 32];
    rng.fill_bytes(&mut message);
    let mut h = Sha512::new();
    h.update(&nonce_bytes);
    h.update(&message);

    let mut output = [0u8; 64];
    output.copy_from_slice(h.finalize().as_slice());
    let r_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&output);

    let r = r_scalar * ED25519_BASEPOINT_POINT;

    let s = r_scalar + compute_hram(&message, &pub_key, &r) * a;
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_ok());

    let s_nonreducing = Scalar52::from_bytes(&s.to_bytes());
    let s_prime_bytes = Scalar52::add(&s_nonreducing, &non_reducing_scalar52::L).to_bytes();
    // using deserialize_scalar is key here, we use `from_bits` to represent
    // the scalar
    let s_prime = deserialize_scalar(&s_prime_bytes)?;

    debug_assert!(s != s_prime);
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s_prime)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s_prime)).is_ok());

    debug!(
        "S > L, large order A, large order R\n\
         passes cofactored, passes  cofactorless, often excluded from both, breaks strong unforgeability\n\
         \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s_prime))
    );
    let tv = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s_prime),
    };

    Ok(tv)
}

////////
// 10 //
////////

fn really_large_s() -> Result<TestVector> {
    let mut rng = new_rng();
    // Pick a random scalar
    let mut scalar_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);
    let a = Scalar::from_bytes_mod_order(scalar_bytes);
    debug_assert!(a.is_canonical());
    debug_assert!(a != Scalar::zero());
    // Pick a random nonce
    let mut nonce_bytes = [0u8; 32];
    rng.fill_bytes(&mut nonce_bytes);

    // generate the r of a "normal" signature
    let pub_key = a * ED25519_BASEPOINT_POINT;

    let mut message = [0u8; 32];
    rng.fill_bytes(&mut message);
    let mut h = Sha512::new();
    h.update(&nonce_bytes);
    h.update(&message);

    let mut output = [0u8; 64];
    output.copy_from_slice(h.finalize().as_slice());
    let r_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&output);

    let r = r_scalar * ED25519_BASEPOINT_POINT;

    let s = r_scalar + compute_hram(&message, &pub_key, &r) * a;
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_ok());

    let mut s_nonreducing = Scalar52::from_bytes(&s.to_bytes());
    // perform the incomplete higher-bits check often used in place of s<L
    while (s_nonreducing.to_bytes()[31] as u8 & 224u8) == 0u8 {
        s_nonreducing = Scalar52::add(&s_nonreducing, &non_reducing_scalar52::L);
    }
    let s_prime_bytes = s_nonreducing.to_bytes();

    // using deserialize_scalar is key here, we use `from_bits` to represent
    // the scalar
    let s_prime = deserialize_scalar(&s_prime_bytes)?;

    debug_assert!(s != s_prime);
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s_prime)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s_prime)).is_ok());

    debug!(
        "S much larger than L, large order A, large order R\n\
         passes cofactored, passes  cofactorless, often excluded from both due to high bit checks, breaks strong unforgeability\n\
         \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s_prime))
    );
    let tv = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s_prime),
    };

    Ok(tv)
}

///////////
// 11-12 //
///////////

// This test vector has R of order 4 in non-canonical form, serialialized as EDFFFF..FFFF.
// Libraries that reject non-canonical encodings of R would reject both vectors.
// Libraries that accept the first vector, but reject the second reduce the R prior to hashing.
// Libraries that reject the first vector, but accept the second do not reduce the R prior to hashing.
// Both vectors pass cofactored and cofactorless verification.
pub fn non_zero_small_non_canonical_mixed() -> Result<(TestVector, TestVector)> {
    let mut rng = new_rng();
    // Pick a random scalar
    let mut scalar_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);
    let a = Scalar::from_bytes_mod_order(scalar_bytes);
    debug_assert!(a.is_canonical());
    debug_assert!(a != Scalar::zero());

    let pub_key_component = a * ED25519_BASEPOINT_POINT;

    let r_arr = [
        // non-canonically serialized point EIGHT_TORSION[6]
        // of order 4
        236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    ];
    let r = deserialize_point(&r_arr).unwrap();

    let small_idx: usize = rng.next_u64() as usize;
    let r2 = pick_small_nonzero_point(small_idx + 1);
    let pub_key = pub_key_component + r2.neg();

    let mut message = [0u8; 32];
    rng.fill_bytes(&mut message);

    // reduces r prior to serializing into the hash input
    while !(r + compute_hram(&message, &pub_key, &r) * r2.neg()).is_identity() {
        rng.fill_bytes(&mut message);
    }
    let s = compute_hram(&message, &pub_key, &r) * a;
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_ok());
    let mut signature = serialize_signature(&r, &s);
    signature[..32].clone_from_slice(&r_arr[..32]);
    debug!(
        "S > 0, mixed A, small non-canonical R\n\
         passes cofactored, passes cofactorless, leaks private key\n\
         \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&signature)
    );
    let tv1 = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature,
    };

    // does not reduce r prior to serializing into the hash input
    while !(r + compute_hram_with_r_array(&message, &pub_key, &r_arr) * r2.neg()).is_identity() {
        rng.fill_bytes(&mut message);
    }
    let s = compute_hram_with_r_array(&message, &pub_key, &r_arr) * a;
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_err());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_err());
    let mut signature = serialize_signature(&r, &s);
    signature[..32].clone_from_slice(&r_arr[..32]);
    debug!(
        "S > 0, mixed A, small non-canonical R\n\
         passes cofactored, passes cofactorless, leaks private key\n\
         \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&signature)
    );
    let tv2 = TestVector {
        message,
        pub_key: pub_key.compress().to_bytes(),
        signature,
    };

    Ok((tv1, tv2))
}

///////////
// 13-14 //
///////////

// This test vector has A of order 4 in non-canonical form, serialialized as EDFFFF..FFFF.
// Libraries that reject non-canonical encodings of A would reject both vectors.
// Libraries that accept the first vector, but reject the second reduce the A prior to hashing.
// Libraries that reject the first vector, but accept the second do not reduce the A prior to hashing.
// Both vectors pass cofactored and cofactorless verification.
pub fn non_zero_mixed_small_non_canonical() -> Result<(TestVector, TestVector)> {
    let mut rng = new_rng();
    // Pick a random Scalar
    let mut scalar_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);
    let s = Scalar::from_bytes_mod_order(scalar_bytes);
    debug_assert!(s.is_canonical());
    debug_assert!(s != Scalar::zero());

    let r0 = s * ED25519_BASEPOINT_POINT;

    // Pick a torsion point
    let pub_key_arr = [
        // non-canonically serialized point EIGHT_TORSION[6]
        // of order 4
        236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    ];
    let pub_key = deserialize_point(&pub_key_arr).unwrap();

    let r = r0 + pub_key.neg();

    let mut message = [0u8; 32];
    rng.fill_bytes(&mut message);

    // succeeds when public key is reserialized
    while !(pub_key.neg() + compute_hram(&message, &pub_key, &r) * pub_key).is_identity()
        || (pub_key.neg() + compute_hram_with_pk_array(&message, &pub_key_arr, &r) * pub_key)
            .is_identity()
    {
        rng.fill_bytes(&mut message);
    }
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_ok());
    debug!(
        "S > 0, negative-zero non-canonical A, mixed R\n\
         passes cofactored, passes cofactorless, repudiable\n\
         reserializes A\n\
         \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    let tv1 = TestVector {
        message,
        pub_key: pub_key_arr,
        signature: serialize_signature(&r, &s),
    };

    // succeeds when public key is not-reserialized
    while !(pub_key.neg() + compute_hram_with_pk_array(&message, &pub_key_arr, &r) * pub_key)
        .is_identity()
        || (pub_key.neg() + compute_hram(&message, &pub_key, &r) * pub_key).is_identity()
    {
        rng.fill_bytes(&mut message);
    }
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_err());
    debug!(
        "S > 0, negative-zero non-canonical A, mixed R\n\
         passes cofactored, passes cofactorless, repudiable\n\
         does not reserialize A\n\
         \"message\": \"{}\", \"pub_key\": \"{}\", \"signature\": \"{}\"",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    let tv2 = TestVector {
        message,
        pub_key: pub_key_arr,
        signature: serialize_signature(&r, &s),
    };

    Ok((tv1, tv2))
}

fn generate_test_vectors() -> Result<Vec<TestVector>> {
    // #0-1: canonical S, small R, small A
    let mut vec = Vec::new();
    let (tv1, tv2) = zero_small_small().unwrap();
    vec.push(tv1); // passes cofactored, fails cofactorless
    vec.push(tv2); // passes cofactored, passes cofactorless

    // #2-3: canonical S, mixed R, small A
    let (tv1, tv2) = non_zero_mixed_small().unwrap();
    vec.push(tv1); // passes cofactored, fails cofactorless
    vec.push(tv2); // passes cofactored, passes cofactorless

    // #4-5: canonical S, small R, mixed A
    let (tv1, tv2) = non_zero_small_mixed().unwrap();
    vec.push(tv1); // passes cofactored, fails cofactorless
    vec.push(tv2); // passes cofactored, passes cofactorless

    // #6-7: canonical S, mixed R, mixed Axs
    let (tv1, tv2) = non_zero_mixed_mixed().unwrap();
    vec.push(tv2); // passes cofactored, passes cofactorless
    vec.push(tv1); // passes cofactored, fails cofactorless

    // #8 Prereduce scalar which fails cofactorless
    let tv1 = pre_reduced_scalar().unwrap();
    vec.push(tv1);

    // #9 Large S
    let tv1 = large_s().unwrap();
    vec.push(tv1);

    // #10 Large S beyond the high bit checks (i.e. non-canonical representation)
    let tv1 = really_large_s().unwrap();
    vec.push(tv1);

    // #11-12
    let (tv1, tv2) = non_zero_small_non_canonical_mixed().unwrap();
    vec.push(tv1);
    vec.push(tv2);

    // #13-14
    let (tv1, tv2) = non_zero_mixed_small_non_canonical().unwrap();
    vec.push(tv1);
    vec.push(tv2);

    Ok(vec)
}

fn main() -> Result<()> {
    env_logger::init();
    let vec = generate_test_vectors().unwrap();

    // Write test vectors to json
    let cases_json = serde_json::to_string(&vec)?;
    let mut file = File::create("cases.json")?;
    file.write_all(cases_json.as_bytes())?;

    // Write test vectors to txt (to ease testing C implementations)
    let mut file = File::create("cases.txt")?;
    file.write_all(vec.len().to_string().as_bytes())?;
    for tv in vec.iter() {
        file.write_all(b"\nmsg=")?;
        file.write_all(hex::encode(&tv.message).as_bytes())?;
        file.write_all(b"\npbk=")?;
        file.write_all(hex::encode(&tv.pub_key).as_bytes())?;
        file.write_all(b"\nsig=")?;
        file.write_all(hex::encode(&tv.signature).as_bytes())?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{PublicKey, Signature, Verifier};
    use ed25519_zebra::{Signature as ZSignature, VerificationKey as ZPublicKey};
    use libra_crypto;
    use ring::signature;
    use std::convert::TryFrom;
    use untrusted;

    fn unpack_test_vector_dalek(t: &TestVector) -> (PublicKey, Signature) {
        let pk = PublicKey::from_bytes(&t.pub_key[..]).unwrap();
        let sig = Signature::try_from(&t.signature[..]).unwrap();
        (pk, sig)
    }

    fn unpack_test_vector_zebra(t: &TestVector) -> (ZPublicKey, ZSignature) {
        let pk = ZPublicKey::try_from(&t.pub_key[..]).unwrap();
        let sig = ZSignature::try_from(&t.signature[..]).unwrap();
        (pk, sig)
    }

    fn ring_verify(t: &TestVector) -> Result<()> {
        let pk = untrusted::Input::from(&t.pub_key[..]);
        let sig = untrusted::Input::from(&t.signature[..]);
        let msg = untrusted::Input::from(&t.message[..]);
        <signature::EdDSAParameters as signature::VerificationAlgorithm>::verify(
            &signature::ED25519,
            pk,
            msg,
            sig,
        )
        .map_err(|_| anyhow!("signature verification failed"))
    }

    #[test]
    fn test_libra() {
        let vec = generate_test_vectors().unwrap();

        print!("\n|libra-crypto   |");
        for tv in vec.iter() {
            let pk = match libra_crypto::ed25519::Ed25519PublicKey::try_from(&tv.pub_key[..]) {
                Ok(pk) => pk,
                Err(_e) => {
                    print!(" X |");
                    continue;
                }
            };
            let sig = match libra_crypto::ed25519::Ed25519Signature::try_from(&tv.signature[..]) {
                Ok(sig) => sig,
                Err(_e) => {
                    print!(" X |");
                    continue;
                }
            };
            match libra_crypto::traits::Signature::verify_arbitrary_msg(&sig, &tv.message[..], &pk)
            {
                Ok(_v) => print!(" V |"),
                Err(_e) => print!(" X |"),
            }
        }
        println!();
    }

    #[test]
    fn test_dalek() {
        let vec = generate_test_vectors().unwrap();

        print!("\n|Dalek          |");
        for tv in vec.iter() {
            match Signature::try_from(&tv.signature[..]) {
                Ok(_v) => {}
                Err(_e) => {
                    print!(" V |");
                    continue;
                }
            }

            let (pk, sig) = unpack_test_vector_dalek(&tv);
            match pk.verify(&tv.message[..], &sig) {
                Ok(_v) => print!(" V |"),
                Err(_e) => print!(" X |"),
            }
        }
        println!();
    }

    #[test]
    fn test_dalek_verify_strict() {
        let vec = generate_test_vectors().unwrap();

        print!("\n|Dalek strict   |");
        for tv in vec.iter() {
            match Signature::try_from(&tv.signature[..]) {
                Ok(_v) => {}
                Err(_e) => {
                    print!(" V |");
                    continue;
                }
            }

            let (pk, sig) = unpack_test_vector_dalek(&tv);
            match pk.verify_strict(&tv.message[..], &sig) {
                Ok(_v) => print!(" V |"),
                Err(_e) => print!(" X |"),
            }
        }
        println!();
    }

    #[test]
    fn test_boringssl() {
        let vec = generate_test_vectors().unwrap();

        print!("\n|BoringSSL      |");
        for tv in vec.iter() {
            match ring_verify(&tv) {
                Ok(_v) => print!(" V |"),
                Err(_e) => print!(" X |"),
            }
        }
        println!();
    }

    #[test]
    fn test_zebra() {
        let vec = generate_test_vectors().unwrap();

        print!("\n|Zebra          |");
        for tv in vec.iter() {
            match Signature::try_from(&tv.signature[..]) {
                Ok(_v) => {}
                Err(_e) => {
                    print!(" X |");
                    continue;
                }
            }

            let (pk, sig) = unpack_test_vector_zebra(&tv);
            match pk.verify(&sig, &tv.message[..]) {
                Ok(_v) => print!(" V |"),
                Err(_e) => print!(" X |"),
            }
        }
        println!();
    }
}
