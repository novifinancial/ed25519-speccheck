use anyhow::{anyhow, Result};
use core::{
    convert::TryFrom,
    ops::{Add, Index, IndexMut, Mul, Neg, Sub},
};

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::EdwardsPoint, scalar::Scalar, traits::IsIdentity,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sha2::{Digest, Sha512};

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
    ],
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

// Takes a point in eight_torsion and finds its order
fn eight_torsion_order(ep: EdwardsPoint) -> usize {
    let mut pt = ep;
    let mut ord = 1;
    for _i in 0..8 {
        if pt == curve25519_dalek::edwards::EdwardsPoint::default() {
            break;
        } else {
            pt = pt.add(ep);
            ord += 1;
        }
    }
    ord
}

fn deserialize_point(pt: &[u8]) -> Result<EdwardsPoint> {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(check_slice_size(pt, 32, "pt")?);

    curve25519_dalek::edwards::CompressedEdwardsY(bytes)
        .decompress()
        .ok_or_else(|| anyhow!("Point decompression failed!"))
}

fn deserialize_scalar(scalar: &[u8]) -> Result<Scalar> {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(check_slice_size(scalar, 32, "scalar")?);

    // This permissive pass-through can produce large scalars!
    Ok(curve25519_dalek::scalar::Scalar::from_bits(bytes))
}

fn deserialize_privkey(priv_key_bytes: &[u8]) -> Result<(Scalar, [u8; 32])> {
    let mut expanded_priv_key = [0u8; 64];
    let mut h: Sha512 = Sha512::default();
    h.update(check_slice_size(priv_key_bytes, 32, "priv_key_bytes")?);
    expanded_priv_key.copy_from_slice(h.finalize().as_slice());

    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&expanded_priv_key[32..]);

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&expanded_priv_key[..32]);
    key_bytes[0] &= 248;
    // ensures multiple of cofactor
    key_bytes[31] &= 127;
    key_bytes[31] |= 64;
    let priv_scalar = curve25519_dalek::scalar::Scalar::from_bits(key_bytes);

    Ok((priv_scalar, nonce))
}

fn deserialize_signature(sig_bytes: &[u8]) -> Result<(EdwardsPoint, Scalar)> {
    let checked_sig_bytes = check_slice_size(sig_bytes, 64, "sig_bytes")?;
    let r = deserialize_point(&checked_sig_bytes[..32])?;
    let s = deserialize_scalar(&checked_sig_bytes[32..])?;
    Ok((r, s))
}

fn serialize_signature(r: &EdwardsPoint, s: &Scalar) -> Vec<u8> {
    [&r.compress().as_bytes()[..], &s.as_bytes()[..]].concat()
}

fn prehash(message: &[u8], pub_key: &EdwardsPoint, signature_r: &EdwardsPoint) -> Scalar {
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

fn verify_cofactored(
    message: &[u8],
    pub_key: &EdwardsPoint,
    unpacked_signature: &(EdwardsPoint, Scalar),
) -> Result<()> {
    let k = prehash(message, pub_key, &unpacked_signature.0);
    verify_prehashed_cofactored(pub_key, unpacked_signature, &k)
}

fn verify_cofactorless(
    message: &[u8],
    pub_key: &EdwardsPoint,
    unpacked_signature: &(EdwardsPoint, Scalar),
) -> Result<()> {
    let k = prehash(message, pub_key, &unpacked_signature.0);
    verify_prehashed_cofactorless(pub_key, unpacked_signature, &k)
}

fn verify_prehashed_cofactored(
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

fn verify_prehashed_cofactorless(
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
    message: [u8; 32],
    pub_key: [u8; 32],
    signature: Vec<u8>,
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

pub fn zero_small_small() -> Result<(TestVector, TestVector), anyhow::Error> {
    let mut rng = new_rng();
    // Pick a torsion point
    let small_idx: usize = rng.next_u64() as usize;

    let pub_key = pick_small_nonzero_point(small_idx + 1);
    let r = pub_key.neg();
    let s = Scalar::zero();

    let mut message = [0u8; 32];
    rng.fill_bytes(&mut message);
    if (r + prehash(&message, &pub_key, &r) * pub_key).is_identity() {
        panic!("wrong rng seed")
    }
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_err());
    println!(
        "S=0, small A, small R\n\
             passes cofactored, fails cofactorless, repudiable\n\
             message: {}, pub_key: {}, signature: {}",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    let tv1 = TestVector {
        message: message.clone(),
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    while !(r + prehash(&message, &pub_key, &r) * pub_key).is_identity() {
        rng.fill_bytes(&mut message);
    }

    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_ok());

    println!(
        "S=0, small A, small R\n\
         passes cofactored, passes cofactorless, repudiable\n\
         message: {}, pub_key: {}, signature: {}",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    let tv2 = TestVector {
        message: message.clone(),
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    Ok((tv1, tv2))
}

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
    if (pub_key.neg() + prehash(&message, &pub_key, &r) * pub_key).is_identity() {
        panic!("wrong rng seed");
    }
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_err());
    println!(
        "S > 0, small A, mixed R\n\
             passes cofactored, fails cofactorless, repudiable\n\
             message: {}, pub_key: {}, signature: {}",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    let tv1 = TestVector {
        message: message.clone(),
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    while !(pub_key.neg() + prehash(&message, &pub_key, &r) * pub_key).is_identity() {
        rng.fill_bytes(&mut message);
    }
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_ok());
    println!(
        "S > 0, small A, mixed R\n\
         passes cofactored, passes cofactorless, repudiable\n\
         message: {}, pub_key: {}, signature: {}",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    let tv2 = TestVector {
        message: message.clone(),
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    Ok((tv1, tv2))
}

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
    if (r + prehash(&message, &pub_key, &r) * r.neg()).is_identity() {
        panic!("wrong rng seed");
    }
    let s = prehash(&message, &pub_key, &r) * a;
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_err());
    println!(
        "S > 0, mixed A, small R\n\
             passes cofactored, fails cofactorless, leaks private key\n\
             message: {}, pub_key: {}, signature: {}",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );

    let tv1 = TestVector {
        message: message.clone(),
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    while !(r + prehash(&message, &pub_key, &r) * r.neg()).is_identity() {
        rng.fill_bytes(&mut message);
    }
    let s = prehash(&message, &pub_key, &r) * a;
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_ok());
    println!(
        "S > 0, mixed A, small R\n\
         passes cofactored, passes cofactorless, leaks private key\n\
         message: {}, pub_key: {}, signature: {}",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    let tv2 = TestVector {
        message: message.clone(),
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    Ok((tv1, tv2))
}

pub fn non_zero_mixed_mixed() -> Result<(TestVector, TestVector)> {
    let mut rng = new_rng();
    // Pick a random scalar
    let mut scalar_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);
    let a = Scalar::from_bytes_mod_order(scalar_bytes);
    debug_assert!(a.is_canonical());
    debug_assert!(a != Scalar::zero());
    // Pick a random nonce
    let mut nonce_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);

    // Pick a torsion component
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

    if (small_pt.neg() + prehash(&message, &pub_key, &r) * small_pt).is_identity() {
        panic!("wrong rng seed");
    }
    let s = prelim_r + prehash(&message, &pub_key, &r) * a;
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_err());
    println!(
        "S > 0, mixed A, mixed R\n\
             passes cofactored, fails cofactorless\n\
             message: {}, pub_key: {}, signature: {}",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );

    let tv1 = TestVector {
        message: message.clone(),
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    while !(small_pt.neg() + prehash(&message, &pub_key, &r) * small_pt).is_identity() {
        rng.fill_bytes(&mut message);
        let mut h = Sha512::new();
        h.update(&nonce_bytes);
        h.update(&message);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.finalize().as_slice());
        prelim_r = curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&output);

        r = prelim_r * ED25519_BASEPOINT_POINT + small_pt.neg();
    }
    let s = prelim_r + prehash(&message, &pub_key, &r) * a;
    debug_assert!(verify_cofactored(&message, &pub_key, &(r, s)).is_ok());
    debug_assert!(verify_cofactorless(&message, &pub_key, &(r, s)).is_ok());
    println!(
        "S > 0, mixed A, mixed R\n\
         passes cofactored, passes cofactorless\n\
         message: {}, pub_key: {}, signature: {}",
        hex::encode(&message),
        hex::encode(&pub_key.compress().as_bytes()),
        hex::encode(&serialize_signature(&r, &s))
    );
    let tv2 = TestVector {
        message: message.clone(),
        pub_key: pub_key.compress().to_bytes(),
        signature: serialize_signature(&r, &s),
    };

    Ok((tv1, tv2))
}

fn main() -> Result<()> {
    zero_small_small()?;
    non_zero_mixed_small()?;
    non_zero_small_mixed()?;
    non_zero_mixed_mixed()?;
    Ok(())
}
