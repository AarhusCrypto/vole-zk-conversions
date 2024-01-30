use crate::field::{convolve::Convolve, polynomial::Polynomial, FiniteField, PrimeFiniteField};
use crate::ring::FiniteRing;
use crate::serialization::{BiggerThanModulus, CanonicalSerialize};
use generic_array::GenericArray;
use rand_core::RngCore;
use smallvec::{smallvec, SmallVec};
use std::ops::{AddAssign, MulAssign, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// A finite field over the Mersenne Prime 2^61 - 1
#[derive(Clone, Copy, Eq, Debug, Hash)]
pub struct F61p(u64);

const MODULUS: u64 = (1 << 61) - 1;

impl ConstantTimeEq for F61p {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for F61p {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        F61p(u64::conditional_select(&a.0, &b.0, choice))
    }
}

impl FiniteRing for F61p {
    /// This has a 2^-61 probability of being a biased draw.
    #[inline]
    fn from_uniform_bytes(x: &[u8; 16]) -> Self {
        F61p(reduce(
            u64::from_le_bytes(<[u8; 8]>::try_from(&x[0..8]).unwrap()) as u128,
        ))
    }

    /// This has a 2^-61 probability of being a biased draw.
    #[inline]
    fn random<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        F61p(reduce(rng.next_u64() as u128))
    }

    const ZERO: Self = F61p(0);
    const ONE: Self = F61p(1);
}

impl CanonicalSerialize for F61p {
    type Serializer = crate::serialization::ByteElementSerializer<Self>;
    type Deserializer = crate::serialization::ByteElementDeserializer<Self>;
    type ByteReprLen = generic_array::typenum::U8;
    type FromBytesError = BiggerThanModulus;

    #[inline]
    fn from_bytes(
        bytes: &GenericArray<u8, Self::ByteReprLen>,
    ) -> Result<Self, Self::FromBytesError> {
        let buf = <[u8; 8]>::from(*bytes);
        let raw = u64::from_le_bytes(buf);
        if raw < MODULUS {
            Ok(F61p(raw))
        } else {
            Err(BiggerThanModulus)
        }
    }

    #[inline]
    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
        self.0.to_le_bytes().into()
    }
}

impl FiniteField for F61p {
    type PrimeField = Self;

    const GENERATOR: Self = F61p(37);

    fn polynomial_modulus() -> Polynomial<Self::PrimeField> {
        Polynomial::x()
    }

    type NumberOfBitsInBitDecomposition = generic_array::typenum::U61;

    fn bit_decomposition(&self) -> GenericArray<bool, Self::NumberOfBitsInBitDecomposition> {
        super::standard_bit_decomposition(u128::from(self.0))
    }
    fn inverse(&self) -> Self {
        if *self == Self::ZERO {
            panic!("Zero cannot be inverted");
        }
        self.pow_var_time(u128::from(MODULUS) - 2)
    }
}

#[inline]
fn reduce(k: u128) -> u64 {
    // Based on https://ariya.io/2007/02/modulus-with-mersenne-prime
    let i = (k & u128::from(MODULUS)) + (k >> 61);
    // Equivalent to:
    /*u64::conditional_select(
        &(i as u64),
        &((i.wrapping_sub(F61p::MODULUS)) as u64),
        Choice::from((i >= F61p::MODULUS) as u8),
    )*/
    let flag = (i < u128::from(MODULUS)) as u128;
    let operand = flag.wrapping_sub(1) & u128::from(MODULUS);
    (i - operand) as u64
}

#[inline]
fn full_reduce(k: u128) -> u64 {
    // same as reduce, but also works for larger values
    let i = (k & u128::from(MODULUS)) + (k >> 61);
    let j = (i & u128::from(MODULUS)) + (i >> 61);
    let flag = (j < u128::from(MODULUS)) as u128;
    let operand = flag.wrapping_sub(1) & u128::from(MODULUS);
    (j - operand) as u64
}

impl AddAssign<&F61p> for F61p {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        let a = self.0 as u128;
        let b = rhs.0 as u128;
        self.0 = reduce(a + b);
    }
}

impl SubAssign<&F61p> for F61p {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        // We add modulus so it can't overflow.
        let a = u128::from(self.0) + u128::from(MODULUS);
        let b = u128::from(rhs.0);
        self.0 = reduce(a - b);
    }
}

impl MulAssign<&F61p> for F61p {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        self.0 = reduce(u128::from(self.0) * u128::from(rhs.0));
    }
}

impl std::iter::Sum for F61p {
    #[inline]
    // // Naive Implementations
    // fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
    //     //iter.fold(F61p::ZERO, std::ops::Add::add)
    //     let mut a : F61p = F61p::ZERO;
    //     for e in iter {
    //         a += e;
    //     }
    //     return a;
    // }

    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut out: u128 = 0;
        // Invariant: this code is correct if the length of the
        // iterator is less than 2^(128 - 61).
        for e in iter {
            out += u128::from(e.0);
        }
        return F61p(reduce(out));
    }
}

impl Convolve for F61p {
    fn convolve(z0: &mut Self, zs: &mut [Self], x0: Self, xs: &[Self], y0: Self, ys: &[Self]) {
        #[inline(always)]
        fn rlmul(x: u64, y: u64) -> u128 {
            u128::from(x) * u128::from(y)
        }

        if ys.len() > xs.len() {
            return Self::convolve(z0, zs, y0, ys, x0, xs);
        }

        let x_deg = xs.len();
        let y_deg = ys.len();
        let z_deg = x_deg + y_deg;

        assert_eq!(zs.len(), z_deg);
        debug_assert!(x_deg >= y_deg);

        *z0 = x0 * y0;
        if y_deg == 0 {
            for i in 0..x_deg {
                zs[i] = xs[i] * y0;
            }
            return;
        }

        for k in 0..y_deg {
            let mut t = rlmul(x0.0, ys[k].0) + rlmul(xs[k].0, y0.0);
            for i in 0..k {
                let j = k - i - 1;
                t += rlmul(xs[i].0, ys[j].0);
            }
            zs[k] = F61p(full_reduce(t));
        }
        for k in y_deg..x_deg {
            let mut t = rlmul(xs[k].0, y0.0);
            for i in k - y_deg..k {
                let j = k - i - 1;
                t += rlmul(xs[i].0, ys[j].0);
            }
            zs[k] = F61p(full_reduce(t));
        }
        for k in x_deg..z_deg - 1 {
            let mut t = 0u128;
            for i in k - y_deg..x_deg {
                let j = k - i - 1;
                t += rlmul(xs[i].0, ys[j].0);
            }
            zs[k] = F61p(full_reduce(t));
        }
        zs[z_deg - 1] = xs[x_deg - 1] * ys[y_deg - 1];

        // assert_eq!(zs.len(), xs.len() + ys.len());
        // *z0 = x0 * y0;
        // let mut zs_int: SmallVec<[_; 32]> = smallvec![0u128; zs.len()];
        // for i in 0..ys.len() {
        //     zs_int[i] = u128::from(x0.0) * u128::from(ys[i].0);
        // }
        // for i in 0..xs.len() {
        //     zs_int[i] += u128::from(y0.0) * u128::from(xs[i].0);
        // }
        // for i in 0..xs.len() {
        //     for j in 0..ys.len() {
        //         zs_int[i + j + 1] += u128::from(xs[i].0) * u128::from(ys[j].0);
        //     }
        // }
        // for i in 0..zs.len() {
        //     zs[i] = F61p(full_reduce(zs_int[i]));
        // }
    }
}

impl TryFrom<u128> for F61p {
    type Error = BiggerThanModulus;

    fn try_from(value: u128) -> Result<Self, Self::Error> {
        if value < MODULUS.into() {
            // This unwrap should never fail since we check that the value fits
            // in the modulus.
            Ok(F61p(value.try_into().unwrap()))
        } else {
            Err(BiggerThanModulus)
        }
    }
}

impl From<F61p> for u128 {
    fn from(value: F61p) -> Self {
        value.0 as u128
    }
}

impl PrimeFiniteField for F61p {}

field_ops!(F61p, SUM_ALREADY_DEFINED);

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    test_field!(test_field, crate::field::F61p);

    #[cfg(test)]
    proptest! {
        #[test]
        fn test_reduce(x in 0u128..((1 << (2 * 61))-1)) {
            assert_eq!(u128::from(reduce(x)), x % u128::from(MODULUS));
        }
    }

    #[test]
    fn test_sum_overflow() {
        let neg1 = F61p::ZERO - F61p::ONE;
        let x = [neg1; 2];
        assert_eq!(x.iter().map(|x| *x).sum::<F61p>(), neg1 + neg1);
    }
}
