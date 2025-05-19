//! The scalar field of the BLS12 curve, defined as `F_r` where `r = 52435875175126190479447740508185965837690552500527637822603658699938581184513`.

mod poseidon2;

use core::fmt;
use core::fmt::{Debug, Display, Formatter};
use core::hash::{Hash, Hasher};
use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign};

use ff::{Field as FFField, PrimeField as FFPrimeField, PrimeFieldBits};
use num_bigint::BigUint;
use p3_field::{AbstractField, Field, Packable, PrimeField};
pub use poseidon2::DiffusionMatrixBLS12;
use rand::distributions::{Distribution, Standard};
use rand::Rng;
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(FFPrimeField)]
#[PrimeFieldModulus = "52435875175126190479447740508185965837690552500527637822603658699938581184513"]
#[PrimeFieldGenerator = "7"]
#[PrimeFieldReprEndianness = "little"]
pub struct FFBls12Fr([u64; 4]);

/// The BLS12 curve scalar field prime, defined as `F_r` where `r = 52435875175126190479447740508185965837690552500527637822603658699938581184513`.
#[derive(Copy, Clone, Default, Eq, PartialEq)]
pub struct Bls12Fr {
    pub value: FFBls12Fr,
}

impl Bls12Fr {
    pub(crate) const fn new(value: FFBls12Fr) -> Self {
        Self { value }
    }
}

impl Serialize for Bls12Fr {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let repr = self.value.to_repr();
        let bytes = repr.as_ref();

        let mut seq = serializer.serialize_seq(Some(bytes.len()))?;
        for e in bytes {
            seq.serialize_element(&e)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Bls12Fr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(d)?;

        let mut res = <FFBls12Fr as FFPrimeField>::Repr::default();

        for (i, digit) in res.0.as_mut().iter_mut().enumerate() {
            *digit = bytes[i];
        }

        let value = FFBls12Fr::from_repr(res);

        if value.is_some().into() {
            Ok(Self { value: value.unwrap() })
        } else {
            Err(serde::de::Error::custom("Invalid field element"))
        }
    }
}

impl Packable for Bls12Fr {}

impl Hash for Bls12Fr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for byte in self.value.to_repr().as_ref().iter() {
            state.write_u8(*byte);
        }
    }
}

impl Ord for Bls12Fr {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}

impl PartialOrd for Bls12Fr {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for Bls12Fr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        <FFBls12Fr as Debug>::fmt(&self.value, f)
    }
}

impl Debug for Bls12Fr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.value, f)
    }
}

impl AbstractField for Bls12Fr {
    type F = Self;

    fn zero() -> Self {
        Self::new(FFBls12Fr::ZERO)
    }
    fn one() -> Self {
        Self::new(FFBls12Fr::ONE)
    }
    fn two() -> Self {
        Self::new(FFBls12Fr::from(2u64))
    }

    fn neg_one() -> Self {
        Self::new(FFBls12Fr::ZERO - FFBls12Fr::ONE)
    }

    #[inline]
    fn from_f(f: Self::F) -> Self {
        f
    }

    fn from_bool(b: bool) -> Self {
        Self::new(FFBls12Fr::from(b as u64))
    }

    fn from_canonical_u8(n: u8) -> Self {
        Self::new(FFBls12Fr::from(n as u64))
    }

    fn from_canonical_u16(n: u16) -> Self {
        Self::new(FFBls12Fr::from(n as u64))
    }

    fn from_canonical_u32(n: u32) -> Self {
        Self::new(FFBls12Fr::from(n as u64))
    }

    fn from_canonical_u64(n: u64) -> Self {
        Self::new(FFBls12Fr::from(n))
    }

    fn from_canonical_usize(n: usize) -> Self {
        Self::new(FFBls12Fr::from(n as u64))
    }

    fn from_wrapped_u32(n: u32) -> Self {
        Self::new(FFBls12Fr::from(n as u64))
    }

    fn from_wrapped_u64(n: u64) -> Self {
        Self::new(FFBls12Fr::from(n))
    }

    fn generator() -> Self {
        Self::new(FFBls12Fr::from(7u64))
    }
}

impl Field for Bls12Fr {
    type Packing = Self;

    fn is_zero(&self) -> bool {
        self.value.is_zero().into()
    }

    fn try_inverse(&self) -> Option<Self> {
        let inverse = self.value.invert();

        if inverse.is_some().into() {
            Some(Self::new(inverse.unwrap()))
        } else {
            None
        }
    }

    fn order() -> BigUint {
        let bytes = FFBls12Fr::char_le_bits();
        BigUint::from_bytes_le(bytes.as_raw_slice())
    }
}

impl PrimeField for Bls12Fr {
    fn as_canonical_biguint(&self) -> BigUint {
        let repr = self.value.to_repr();
        let le_bytes = repr.as_ref();
        BigUint::from_bytes_le(le_bytes)
    }
}

impl Add for Bls12Fr {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self::new(self.value + rhs.value)
    }
}

impl AddAssign for Bls12Fr {
    fn add_assign(&mut self, rhs: Self) {
        self.value += rhs.value;
    }
}

impl Sum for Bls12Fr {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|x, y| x + y).unwrap_or(Self::zero())
    }
}

impl Sub for Bls12Fr {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self::new(self.value.sub(rhs.value))
    }
}

impl SubAssign for Bls12Fr {
    fn sub_assign(&mut self, rhs: Self) {
        self.value -= rhs.value;
    }
}

impl Neg for Bls12Fr {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self * Self::neg_one()
    }
}

impl Mul for Bls12Fr {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self::new(self.value * rhs.value)
    }
}

impl MulAssign for Bls12Fr {
    fn mul_assign(&mut self, rhs: Self) {
        self.value *= rhs.value;
    }
}

impl Product for Bls12Fr {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|x, y| x * y).unwrap_or(Self::one())
    }
}

impl Div for Bls12Fr {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self {
        self * rhs.inverse()
    }
}

impl Distribution<Bls12Fr> for Standard {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Bls12Fr {
        Bls12Fr::new(FFBls12Fr::random(rng))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::One;

    type F = Bls12Fr;

    #[test]
    fn test_bls12fr() {
        let f = F::new(FFBls12Fr::from_u128(100));
        assert_eq!(f.as_canonical_biguint(), BigUint::new(vec![100]));

        let f = F::from_canonical_u64(0);
        assert!(f.is_zero());

        let f = F::new(FFBls12Fr::from_str_vartime(&F::order().to_str_radix(10)).unwrap());
        assert!(f.is_zero());

        assert_eq!(F::generator().as_canonical_biguint(), BigUint::new(vec![7]));

        let f_1 = F::new(FFBls12Fr::from_u128(1));
        let f_1_copy = F::new(FFBls12Fr::from_u128(1));

        let expected_result = F::zero();
        assert_eq!(f_1 - f_1_copy, expected_result);

        let expected_result = F::new(FFBls12Fr::from_u128(2));
        assert_eq!(f_1 + f_1_copy, expected_result);

        let f_2 = F::new(FFBls12Fr::from_u128(2));
        let expected_result = F::new(FFBls12Fr::from_u128(3));
        assert_eq!(f_1 + f_1_copy * f_2, expected_result);

        let expected_result = F::new(FFBls12Fr::from_u128(5));
        assert_eq!(f_1 + f_2 * f_2, expected_result);

        let f_r_minus_1 = F::new(
            FFBls12Fr::from_str_vartime(&(F::order() - BigUint::one()).to_str_radix(10)).unwrap(),
        );
        let expected_result = F::zero();
        assert_eq!(f_1 + f_r_minus_1, expected_result);

        let f_r_minus_2 = F::new(
            FFBls12Fr::from_str_vartime(&(F::order() - BigUint::new(vec![2])).to_str_radix(10))
                .unwrap(),
        );
        let expected_result = F::new(
            FFBls12Fr::from_str_vartime(&(F::order() - BigUint::new(vec![3])).to_str_radix(10))
                .unwrap(),
        );
        assert_eq!(f_r_minus_1 + f_r_minus_2, expected_result);

        let expected_result = F::new(FFBls12Fr::from_u128(1));
        assert_eq!(f_r_minus_1 - f_r_minus_2, expected_result);

        let expected_result = f_r_minus_1;
        assert_eq!(f_r_minus_2 - f_r_minus_1, expected_result);

        let expected_result = f_r_minus_2;
        assert_eq!(f_r_minus_1 - f_1, expected_result);

        let expected_result = F::new(FFBls12Fr::from_u128(3));
        assert_eq!(f_2 * f_2 - f_1, expected_result);

        // Generator check
        let expected_multiplicative_group_generator = F::new(FFBls12Fr::from_u128(7));
        assert_eq!(F::generator(), expected_multiplicative_group_generator);

        let f_serialized = serde_json::to_string(&f).unwrap();
        let f_deserialized: F = serde_json::from_str(&f_serialized).unwrap();
        assert_eq!(f, f_deserialized);

        let f_1_serialized = serde_json::to_string(&f_1).unwrap();
        let f_1_deserialized: F = serde_json::from_str(&f_1_serialized).unwrap();
        let f_1_serialized_again = serde_json::to_string(&f_1_deserialized).unwrap();
        let f_1_deserialized_again: F = serde_json::from_str(&f_1_serialized_again).unwrap();
        assert_eq!(f_1, f_1_deserialized);
        assert_eq!(f_1, f_1_deserialized_again);

        let f_2_serialized = serde_json::to_string(&f_2).unwrap();
        let f_2_deserialized: F = serde_json::from_str(&f_2_serialized).unwrap();
        assert_eq!(f_2, f_2_deserialized);

        let f_r_minus_1_serialized = serde_json::to_string(&f_r_minus_1).unwrap();
        let f_r_minus_1_deserialized: F = serde_json::from_str(&f_r_minus_1_serialized).unwrap();
        assert_eq!(f_r_minus_1, f_r_minus_1_deserialized);

        let f_r_minus_2_serialized = serde_json::to_string(&f_r_minus_2).unwrap();
        let f_r_minus_2_deserialized: F = serde_json::from_str(&f_r_minus_2_serialized).unwrap();
        assert_eq!(f_r_minus_2, f_r_minus_2_deserialized);
    }
}
