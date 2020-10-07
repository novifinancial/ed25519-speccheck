// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the APACHE 2.0 license found in
// the LICENSE file in the root directory of this source tree.

use core::ops::{Index, IndexMut};

/// The `Scalar52` struct represents an element in
/// ℤ/ℓℤ as 5 52-bit limbs.
pub struct Scalar52(pub [u64; 5]);

/// `L` is the order of base point, i.e. 2^252 + 27742317777372353535851937790883648493
pub const L: Scalar52 = Scalar52([
    0x0002_631a_5cf5_d3ed,
    0x000d_ea2f_79cd_6581,
    0x0000_0000_0014_def9,
    0x0000_0000_0000_0000,
    0x0000_1000_0000_0000,
]);

impl Scalar52 {
    /// Return the zero scalar
    pub fn zero() -> Scalar52 {
        Scalar52([0, 0, 0, 0, 0])
    }

    /// Unpack a 32 byte / 256 bit scalar into 5 52-bit limbs.
    pub fn from_bytes(bytes: &[u8; 32]) -> Scalar52 {
        let mut words = [0u64; 4];
        for i in 0..4 {
            for j in 0..8 {
                words[i] |= u64::from(bytes[(i * 8) + j]) << (j * 8) as u64;
            }
        }

        let mask = (1u64 << 52) - 1;
        let top_mask = (1u64 << 48) - 1;
        let mut s = Scalar52::zero();

        s[0] = words[0] & mask;
        s[1] = ((words[0] >> 52) | (words[1] << 12)) & mask;
        s[2] = ((words[1] >> 40) | (words[2] << 24)) & mask;
        s[3] = ((words[2] >> 28) | (words[3] << 36)) & mask;
        s[4] = (words[3] >> 16) & top_mask;

        s
    }

    /// Pack the limbs of this `Scalar52` into 32 bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut s = [0u8; 32];

        s[0] = self.0[0] as u8;
        s[1] = (self.0[0] >> 8) as u8;
        s[2] = (self.0[0] >> 16) as u8;
        s[3] = (self.0[0] >> 24) as u8;
        s[4] = (self.0[0] >> 32) as u8;
        s[5] = (self.0[0] >> 40) as u8;
        s[6] = ((self.0[0] >> 48) | (self.0[1] << 4)) as u8;
        s[7] = (self.0[1] >> 4) as u8;
        s[8] = (self.0[1] >> 12) as u8;
        s[9] = (self.0[1] >> 20) as u8;
        s[10] = (self.0[1] >> 28) as u8;
        s[11] = (self.0[1] >> 36) as u8;
        s[12] = (self.0[1] >> 44) as u8;
        s[13] = self.0[2] as u8;
        s[14] = (self.0[2] >> 8) as u8;
        s[15] = (self.0[2] >> 16) as u8;
        s[16] = (self.0[2] >> 24) as u8;
        s[17] = (self.0[2] >> 32) as u8;
        s[18] = (self.0[2] >> 40) as u8;
        s[19] = ((self.0[2] >> 48) | (self.0[3] << 4)) as u8;
        s[20] = (self.0[3] >> 4) as u8;
        s[21] = (self.0[3] >> 12) as u8;
        s[22] = (self.0[3] >> 20) as u8;
        s[23] = (self.0[3] >> 28) as u8;
        s[24] = (self.0[3] >> 36) as u8;
        s[25] = (self.0[3] >> 44) as u8;
        s[26] = self.0[4] as u8;
        s[27] = (self.0[4] >> 8) as u8;
        s[28] = (self.0[4] >> 16) as u8;
        s[29] = (self.0[4] >> 24) as u8;
        s[30] = (self.0[4] >> 32) as u8;
        s[31] = (self.0[4] >> 40) as u8;

        s
    }

    /// Compute `a + b` (without mod ℓ)
    pub fn add(a: &Scalar52, b: &Scalar52) -> Scalar52 {
        let mut sum = Scalar52::zero();
        let mask = (1u64 << 52) - 1;

        // a + b
        let mut carry: u64 = 0;
        for i in 0..5 {
            carry = a[i] + b[i] + (carry >> 52);
            sum[i] = carry & mask;
        }

        sum
    }
}

impl Index<usize> for Scalar52 {
    type Output = u64;
    fn index(&self, _index: usize) -> &u64 {
        &(self.0[_index])
    }
}

impl IndexMut<usize> for Scalar52 {
    fn index_mut(&mut self, _index: usize) -> &mut u64 {
        &mut (self.0[_index])
    }
}
