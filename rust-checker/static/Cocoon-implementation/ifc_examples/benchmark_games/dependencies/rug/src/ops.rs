// Copyright © 2016–2020 University of Malta

// This program is free software: you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License and a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.

/*!
Operations on numbers.

See the documentation for each trait method to see a usage example.
*/

/**
Compound negation and assignment.

# Examples

```rust
use rug::ops::NegAssign;
struct I(i32);
impl NegAssign for I {
    fn neg_assign(&mut self) {
        self.0 = -self.0;
    }
}
let mut i = I(42);
i.neg_assign();
assert_eq!(i.0, -42);
```
*/
pub trait NegAssign {
    /// Peforms the negation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "integer")] {
    /// use rug::{ops::NegAssign, Integer};
    /// let mut i = Integer::from(-42);
    /// i.neg_assign();
    /// assert_eq!(i, 42);
    /// # }
    /// ```
    fn neg_assign(&mut self);
}

/**
Compound bitwise complement and assignement.

# Examples

```rust
use rug::ops::NotAssign;
struct I(i32);
impl NotAssign for I {
    fn not_assign(&mut self) {
        self.0 = !self.0;
    }
}
let mut i = I(42);
i.not_assign();
assert_eq!(i.0, !42);
```
*/
pub trait NotAssign {
    /// Peforms the complement.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "integer")] {
    /// use rug::{ops::NotAssign, Integer};
    /// let mut i = Integer::from(-42);
    /// i.not_assign();
    /// assert_eq!(i, !-42);
    /// # }
    /// ```
    fn not_assign(&mut self);
}

/**
Compound addition and assignment to the rhs operand.

`rhs.add_from(lhs)` has the same effect as `rhs = lhs + rhs`.

# Examples

```rust
use rug::ops::AddFrom;
struct S(String);
impl AddFrom<&str> for S {
    fn add_from(&mut self, lhs: &str) {
        self.0.insert_str(0, lhs);
    }
}
let mut s = S("world!".into());
s.add_from("Hello, ");
assert_eq!(s.0, "Hello, world!");
```
*/
pub trait AddFrom<Lhs = Self> {
    /// Peforms the addition.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "integer")] {
    /// use rug::{ops::AddFrom, Integer};
    /// let mut rhs = Integer::from(10);
    /// rhs.add_from(100);
    /// // rhs = 100 + 10
    /// assert_eq!(rhs, 110);
    /// # }
    /// ```
    fn add_from(&mut self, lhs: Lhs);
}

/**
Compound subtraction and assignment to the rhs operand.

`rhs.sub_from(lhs)` has the same effect as `rhs = lhs - rhs`.

# Examples

```rust
use rug::ops::SubFrom;
struct I(i32);
impl SubFrom<i32> for I {
    fn sub_from(&mut self, lhs: i32) {
        self.0 = lhs - self.0;
    }
}
let mut i = I(10);
i.sub_from(42);
assert_eq!(i.0, 32);
```
*/
pub trait SubFrom<Lhs = Self> {
    /// Peforms the subtraction.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "integer")] {
    /// use rug::{ops::SubFrom, Integer};
    /// let mut rhs = Integer::from(10);
    /// rhs.sub_from(100);
    /// // rhs = 100 − 10
    /// assert_eq!(rhs, 90);
    /// # }
    /// ```
    fn sub_from(&mut self, lhs: Lhs);
}

/**
Compound multiplication and assignment to the rhs operand.

`rhs.mul_from(lhs)` has the same effect as `rhs = lhs * rhs`.

# Examples

```rust
use rug::ops::MulFrom;
struct ColumnVec(i32, i32);
struct SquareMatrix(ColumnVec, ColumnVec);
impl MulFrom<&SquareMatrix> for ColumnVec {
    fn mul_from(&mut self, lhs: &SquareMatrix) {
        let SquareMatrix(ref left, ref right) = *lhs;
        let out_0 = left.0 * self.0 + right.0 * self.1;
        self.1 = left.1 * self.0 + right.1 * self.1;
        self.0 = out_0;
    }
}
let mut col = ColumnVec(2, 30);
let matrix_left = ColumnVec(1, -2);
let matrix_right = ColumnVec(3, -1);
let matrix = SquareMatrix(matrix_left, matrix_right);
// ( 1   3) ( 2) = ( 92)
// (−2  −1) (30)   (−34)
col.mul_from(&matrix);
assert_eq!(col.0, 92);
assert_eq!(col.1, -34);
```
*/
pub trait MulFrom<Lhs = Self> {
    /// Peforms the multiplication.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "integer")] {
    /// use rug::{ops::MulFrom, Integer};
    /// let mut rhs = Integer::from(5);
    /// rhs.mul_from(50);
    /// // rhs = 50 × 5
    /// assert_eq!(rhs, 250);
    /// # }
    /// ```
    fn mul_from(&mut self, lhs: Lhs);
}

/**
Compound division and assignment to the rhs operand.

`rhs.div_from(lhs)` has the same effect as `rhs = lhs / rhs`.

# Examples

```rust
use rug::ops::DivFrom;
struct I(i32);
impl DivFrom<i32> for I {
    fn div_from(&mut self, lhs: i32) {
        self.0 = lhs / self.0;
    }
}
let mut i = I(10);
i.div_from(42);
assert_eq!(i.0, 4);
```
*/
pub trait DivFrom<Lhs = Self> {
    /// Peforms the division.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "integer")] {
    /// use rug::{ops::DivFrom, Integer};
    /// let mut rhs = Integer::from(5);
    /// rhs.div_from(50);
    /// // rhs = 50 / 5
    /// assert_eq!(rhs, 10);
    /// # }
    /// ```
    fn div_from(&mut self, lhs: Lhs);
}

/**
Compound remainder operation and assignment to the rhs operand.

`rhs.rem_from(lhs)` has the same effect as `rhs = lhs % rhs`.

# Examples

```rust
use rug::ops::RemFrom;
struct I(i32);
impl RemFrom<i32> for I {
    fn rem_from(&mut self, lhs: i32) {
        self.0 = lhs % self.0;
    }
}
let mut i = I(10);
i.rem_from(42);
assert_eq!(i.0, 2);
```
*/
pub trait RemFrom<Lhs = Self> {
    /// Peforms the remainder operation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "integer")] {
    /// use rug::{ops::RemFrom, Integer};
    /// let mut rhs = Integer::from(2);
    /// rhs.rem_from(17);
    /// // rhs = 17 / 2
    /// assert_eq!(rhs, 1);
    /// # }
    /// ```
    fn rem_from(&mut self, lhs: Lhs);
}

/**
Compound bitwise AND and assignment to the rhs operand.

`rhs.bitand_from(lhs)` has the same effect as `rhs = lhs & rhs`.

# Examples

```rust
use rug::ops::BitAndFrom;
struct U(u32);
impl BitAndFrom<u32> for U {
    fn bitand_from(&mut self, lhs: u32) {
        self.0 = lhs & self.0;
    }
}
let mut u = U(0xff);
u.bitand_from(0xf0);
assert_eq!(u.0, 0xf0);
```
*/
pub trait BitAndFrom<Lhs = Self> {
    /// Peforms the AND operation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "integer")] {
    /// use rug::{ops::BitAndFrom, Integer};
    /// let mut rhs = Integer::from(0xf0);
    /// rhs.bitand_from(0x33);
    /// // rhs = 0x33 & 0xf0
    /// assert_eq!(rhs, 0x30);
    /// # }
    /// ```
    fn bitand_from(&mut self, lhs: Lhs);
}

/**
Compound bitwise OR and assignment to the rhs operand.

`rhs.bitor_from(lhs)` has the same effect as `rhs = lhs | rhs`.

# Examples

```rust
use rug::ops::BitOrFrom;
struct U(u32);
impl BitOrFrom<u32> for U {
    fn bitor_from(&mut self, lhs: u32) {
        self.0 = lhs | self.0;
    }
}
let mut u = U(0xf);
u.bitor_from(0xf0);
assert_eq!(u.0, 0xff);
```
*/
pub trait BitOrFrom<Lhs = Self> {
    /// Peforms the OR operation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "integer")] {
    /// use rug::{ops::BitOrFrom, Integer};
    /// let mut rhs = Integer::from(0xf0);
    /// rhs.bitor_from(0x33);
    /// // rhs = 0x33 | 0xf0
    /// assert_eq!(rhs, 0xf3);
    /// # }
    /// ```
    fn bitor_from(&mut self, lhs: Lhs);
}

/**
Compound bitwise XOR and assignment to the rhs operand.

`rhs.bitxor_from(lhs)` has the same effect as `rhs = lhs ^ rhs`.

# Examples

```rust
use rug::ops::BitXorFrom;
struct U(u32);
impl BitXorFrom<u32> for U {
    fn bitxor_from(&mut self, lhs: u32) {
        self.0 = lhs ^ self.0;
    }
}
let mut u = U(0xf);
u.bitxor_from(0xff);
assert_eq!(u.0, 0xf0);
```
*/
pub trait BitXorFrom<Lhs = Self> {
    /// Peforms the XOR operation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "integer")] {
    /// use rug::{ops::BitXorFrom, Integer};
    /// let mut rhs = Integer::from(0xf0);
    /// rhs.bitxor_from(0x33);
    /// // rhs = 0x33 ^ 0xf0
    /// assert_eq!(rhs, 0xc3);
    /// # }
    /// ```
    fn bitxor_from(&mut self, lhs: Lhs);
}

/**
Compound left shift and assignment to the rhs operand.

`rhs.shl_from(lhs)` has the same effect as `rhs = lhs << rhs`.

# Examples

```rust
# #[cfg(feature = "integer")] {
use core::mem;
use rug::{ops::ShlFrom, Integer};
struct I(Integer);
impl ShlFrom for I {
    fn shl_from(&mut self, mut lhs: I) {
        let rhs = self.0.to_i32().expect("overflow");
        mem::swap(self, &mut lhs);
        self.0 <<= rhs;
    }
}
let mut i = I(Integer::from(200));
i.shl_from(I(Integer::from(0xf000)));
let expected = Integer::from(0xf000) << 200;
assert_eq!(i.0, expected);
# }
```
*/
pub trait ShlFrom<Lhs = Self> {
    /// Peforms the left shift.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::ops::ShlFrom;
    /// let mut rhs = 4;
    /// rhs.shl_from(0x00f0);
    /// // rhs = 0x00f0 << 4
    /// assert_eq!(rhs, 0x0f00);
    /// ```
    fn shl_from(&mut self, lhs: Lhs);
}

/**
Compound right shift and assignment to the rhs operand.

`rhs.shr_from(lhs)` has the same effect as `rhs = lhs >> rhs`.

# Examples

```rust
# #[cfg(feature = "integer")] {
use core::mem;
use rug::{ops::ShrFrom, Integer};
struct I(Integer);
impl ShrFrom for I {
    fn shr_from(&mut self, mut lhs: I) {
        let rhs = self.0.to_i32().expect("overflow");
        mem::swap(self, &mut lhs);
        self.0 >>= rhs;
    }
}
let mut i = I(Integer::from(4));
i.shr_from(I(Integer::from(0xf000)));
let expected = Integer::from(0xf000) >> 4;
assert_eq!(i.0, expected);
# }
```
*/
pub trait ShrFrom<Lhs = Self> {
    /// Peforms the right shift.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::ops::ShrFrom;
    /// let mut rhs = 4;
    /// rhs.shr_from(0x00f0);
    /// // rhs = 0x00f0 >> 4
    /// assert_eq!(rhs, 0x000f);
    /// ```
    fn shr_from(&mut self, lhs: Lhs);
}

/**
The power operation.

# Examples

```rust
use rug::ops::Pow;
struct U(u32);
impl Pow<u16> for U {
    type Output = u32;
    fn pow(self, rhs: u16) -> u32 {
        self.0.pow(u32::from(rhs))
    }
}
let u = U(5);
assert_eq!(u.pow(2_u16), 25);
```
*/
pub trait Pow<Rhs> {
    /// The resulting type after the power operation.
    type Output;
    /// Performs the power operation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "integer")] {
    /// use rug::{ops::Pow, Integer};
    /// let base = Integer::from(10);
    /// let power = base.pow(5);
    /// assert_eq!(power, 100_000);
    /// # }
    /// ```
    fn pow(self, rhs: Rhs) -> Self::Output;
}

/**
Compound power operation and assignment.

# Examples

```rust
use rug::ops::PowAssign;
struct U(u32);
impl PowAssign<u16> for U {
    fn pow_assign(&mut self, rhs: u16) {
        self.0 = self.0.pow(u32::from(rhs));
    }
}
let mut u = U(5);
u.pow_assign(2_u16);
assert_eq!(u.0, 25);
```
*/
pub trait PowAssign<Rhs> {
    /// Peforms the power operation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "integer")] {
    /// use rug::{ops::PowAssign, Integer};
    /// let mut i = Integer::from(10);
    /// i.pow_assign(5);
    /// assert_eq!(i, 100_000);
    /// # }
    /// ```
    fn pow_assign(&mut self, rhs: Rhs);
}

/**
Compound power operation and assignment to the rhs operand.

`rhs.pow_from(lhs)` has the same effect as `rhs = lhs.pow(rhs)`.

# Examples

```rust
use rug::ops::PowFrom;
struct U(u32);
impl PowFrom<u32> for U {
    fn pow_from(&mut self, lhs: u32) {
        self.0 = lhs.pow(self.0);
    }
}
let mut u = U(2);
u.pow_from(5);
assert_eq!(u.0, 25);
```
*/
pub trait PowFrom<Lhs = Self> {
    /// Peforms the power operation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "float")] {
    /// use rug::{ops::PowFrom, Float};
    /// let mut rhs = Float::with_val(53, 5);
    /// rhs.pow_from(10);
    /// // rhs = 10 ^ 5
    /// assert_eq!(rhs, 100_000);
    /// # }
    /// ```
    fn pow_from(&mut self, lhs: Lhs);
}

/**
Assignment with a specified rounding method.

# Examples

```rust
# #[cfg(feature = "float")] {
use core::cmp::Ordering;
use rug::{float::Round, ops::AssignRound};
struct F(f64);
impl AssignRound<f64> for F {
    type Round = Round;
    type Ordering = Ordering;
    fn assign_round(&mut self, rhs: f64, _round: Round) -> Ordering {
        self.0 = rhs;
        Ordering::Equal
    }
}
let mut f = F(3.0);
let dir = f.assign_round(5.0, Round::Nearest);
assert_eq!(f.0, 5.0);
assert_eq!(dir, Ordering::Equal);
# }
```
*/
pub trait AssignRound<Src = Self> {
    /// The rounding method.
    type Round;
    /// The direction from rounding.
    type Ordering;
    /// Peforms the assignment.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "float")] {
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, ops::AssignRound, Float};
    /// // only four significant bits
    /// let mut f = Float::new(4);
    /// let dir = f.assign_round(3.3, Round::Nearest);
    /// // 3.3 rounded down to 3.25
    /// assert_eq!(f, 3.25);
    /// assert_eq!(dir, Ordering::Less);
    /// let dir = f.assign_round(3.3, Round::Up);
    /// // 3.3 rounded up to 3.5
    /// assert_eq!(f, 3.5);
    /// assert_eq!(dir, Ordering::Greater);
    /// # }
    /// ```
    fn assign_round(&mut self, src: Src, round: Self::Round) -> Self::Ordering;
}

/**
Compound addition and assignment with a specified rounding method.

# Examples

```rust
# #[cfg(feature = "float")] {
use core::cmp::Ordering;
use rug::{float::Round, ops::AddAssignRound, Float};
struct F(f64);
impl AddAssignRound<f64> for F {
    type Round = Round;
    type Ordering = Ordering;
    fn add_assign_round(&mut self, rhs: f64, round: Round) -> Ordering {
        let mut f = Float::with_val(53, self.0);
        let dir = f.add_assign_round(rhs, round);
        self.0 = f.to_f64();
        dir
    }
}
let mut f = F(3.0);
let dir = f.add_assign_round(5.0, Round::Nearest);
// 3.0 + 5.0 = 8.0
assert_eq!(f.0, 8.0);
assert_eq!(dir, Ordering::Equal);
# }
```
*/
pub trait AddAssignRound<Rhs = Self> {
    /// The rounding method.
    type Round;
    /// The direction from rounding.
    type Ordering;
    /// Performs the addition.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "float")] {
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, ops::AddAssignRound, Float};
    /// // only four significant bits
    /// let mut f = Float::with_val(4, -3);
    /// let dir = f.add_assign_round(-0.3, Round::Nearest);
    /// // −3.3 rounded up to −3.25
    /// assert_eq!(f, -3.25);
    /// assert_eq!(dir, Ordering::Greater);
    /// # }
    /// ```
    fn add_assign_round(&mut self, rhs: Rhs, round: Self::Round) -> Self::Ordering;
}

/**
Compound addition and assignment to the rhs operand with a
specified rounding method.

# Examples

```rust
# #[cfg(feature = "float")] {
use core::cmp::Ordering;
use rug::{
    float::Round,
    ops::{AddAssignRound, AddFromRound},
    Float,
};
struct F(f64);
impl AddFromRound<f64> for F {
    type Round = Round;
    type Ordering = Ordering;
    fn add_from_round(&mut self, lhs: f64, round: Round) -> Ordering {
        let mut f = Float::with_val(53, lhs);
        let dir = f.add_assign_round(self.0, round);
        self.0 = f.to_f64();
        dir
    }
}
let mut f = F(5.0);
let dir = f.add_from_round(3.0, Round::Nearest);
// 3.0 + 5.0 = 8.0
assert_eq!(f.0, 8.0);
assert_eq!(dir, Ordering::Equal);
# }
```
*/
pub trait AddFromRound<Lhs = Self> {
    /// The rounding method.
    type Round;
    /// The direction from rounding.
    type Ordering;
    /// Performs the addition.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "float")] {
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, ops::AddFromRound, Float};
    /// // only four significant bits
    /// let mut f = Float::with_val(4, -0.3);
    /// let dir = f.add_from_round(-3, Round::Nearest);
    /// // −3.3 rounded up to −3.25
    /// assert_eq!(f, -3.25);
    /// assert_eq!(dir, Ordering::Greater);
    /// # }
    /// ```
    fn add_from_round(&mut self, lhs: Lhs, round: Self::Round) -> Self::Ordering;
}

/**
Compound subtraction and assignment with a specified rounding
method.

# Examples

```rust
# #[cfg(feature = "float")] {
use core::cmp::Ordering;
use rug::{float::Round, ops::SubAssignRound, Float};
struct F(f64);
impl SubAssignRound<f64> for F {
    type Round = Round;
    type Ordering = Ordering;
    fn sub_assign_round(&mut self, rhs: f64, round: Round) -> Ordering {
        let mut f = Float::with_val(53, self.0);
        let dir = f.sub_assign_round(rhs, round);
        self.0 = f.to_f64();
        dir
    }
}
let mut f = F(3.0);
let dir = f.sub_assign_round(5.0, Round::Nearest);
// 3.0 - 5.0 = -2.0
assert_eq!(f.0, -2.0);
assert_eq!(dir, Ordering::Equal);
# }
```
*/
pub trait SubAssignRound<Rhs = Self> {
    /// The rounding method.
    type Round;
    /// The direction from rounding.
    type Ordering;
    /// Performs the subtraction.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "float")] {
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, ops::SubAssignRound, Float};
    /// // only four significant bits
    /// let mut f = Float::with_val(4, -3);
    /// let dir = f.sub_assign_round(0.3, Round::Nearest);
    /// // −3.3 rounded up to −3.25
    /// assert_eq!(f, -3.25);
    /// assert_eq!(dir, Ordering::Greater);
    /// # }
    /// ```
    fn sub_assign_round(&mut self, rhs: Rhs, round: Self::Round) -> Self::Ordering;
}

/**
Compound subtraction and assignment to the rhs operand with a
specified rounding method.

# Examples

```rust
# #[cfg(feature = "float")] {
use core::cmp::Ordering;
use rug::{
    float::Round,
    ops::{SubAssignRound, SubFromRound},
    Float,
};
struct F(f64);
impl SubFromRound<f64> for F {
    type Round = Round;
    type Ordering = Ordering;
    fn sub_from_round(&mut self, lhs: f64, round: Round) -> Ordering {
        let mut f = Float::with_val(53, lhs);
        let dir = f.sub_assign_round(self.0, round);
        self.0 = f.to_f64();
        dir
    }
}
let mut f = F(5.0);
let dir = f.sub_from_round(3.0, Round::Nearest);
// 3.0 - 5.0 = -2.0
assert_eq!(f.0, -2.0);
assert_eq!(dir, Ordering::Equal);
# }
```
*/
pub trait SubFromRound<Lhs = Self> {
    /// The rounding method.
    type Round;
    /// The direction from rounding.
    type Ordering;
    /// Performs the subtraction.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "float")] {
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, ops::SubFromRound, Float};
    /// // only four significant bits
    /// let mut f = Float::with_val(4, 0.3);
    /// let dir = f.sub_from_round(-3, Round::Nearest);
    /// // −3.3 rounded up to −3.25
    /// assert_eq!(f, -3.25);
    /// assert_eq!(dir, Ordering::Greater);
    /// # }
    /// ```
    fn sub_from_round(&mut self, lhs: Lhs, round: Self::Round) -> Self::Ordering;
}

/**
Compound multiplication and assignment with a specified rounding
method.

# Examples

```rust
# #[cfg(feature = "float")] {
use core::cmp::Ordering;
use rug::{float::Round, ops::MulAssignRound, Float};
struct F(f64);
impl MulAssignRound<f64> for F {
    type Round = Round;
    type Ordering = Ordering;
    fn mul_assign_round(&mut self, rhs: f64, round: Round) -> Ordering {
        let mut f = Float::with_val(53, self.0);
        let dir = f.mul_assign_round(rhs, round);
        self.0 = f.to_f64();
        dir
    }
}
let mut f = F(3.0);
let dir = f.mul_assign_round(5.0, Round::Nearest);
// 3.0 × 5.0 = 15.0
assert_eq!(f.0, 15.0);
assert_eq!(dir, Ordering::Equal);
# }
```
*/
pub trait MulAssignRound<Rhs = Self> {
    /// The rounding method.
    type Round;
    /// The direction from rounding.
    type Ordering;
    /// Performs the multiplication.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "float")] {
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, ops::MulAssignRound, Float};
    /// // only four significant bits
    /// let mut f = Float::with_val(4, -3);
    /// let dir = f.mul_assign_round(13, Round::Nearest);
    /// // −39 rounded down to −40
    /// assert_eq!(f, -40);
    /// assert_eq!(dir, Ordering::Less);
    /// # }
    /// ```
    fn mul_assign_round(&mut self, rhs: Rhs, round: Self::Round) -> Self::Ordering;
}

/**
Compound multiplication and assignment to the rhs operand with a
specified rounding method.

# Examples

```rust
# #[cfg(feature = "float")] {
use core::cmp::Ordering;
use rug::{
    float::Round,
    ops::{MulAssignRound, MulFromRound},
    Float,
};
struct F(f64);
impl MulFromRound<f64> for F {
    type Round = Round;
    type Ordering = Ordering;
    fn mul_from_round(&mut self, lhs: f64, round: Round) -> Ordering {
        let mut f = Float::with_val(53, lhs);
        let dir = f.mul_assign_round(self.0, round);
        self.0 = f.to_f64();
        dir
    }
}
let mut f = F(5.0);
let dir = f.mul_from_round(3.0, Round::Nearest);
// 3.0 × 5.0 = 15.0
assert_eq!(f.0, 15.0);
assert_eq!(dir, Ordering::Equal);
# }
```
*/
pub trait MulFromRound<Lhs = Self> {
    /// The rounding method.
    type Round;
    /// The direction from rounding.
    type Ordering;
    /// Performs the multiplication.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "float")] {
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, ops::MulFromRound, Float};
    /// // only four significant bits
    /// let mut f = Float::with_val(4, 13);
    /// let dir = f.mul_from_round(-3, Round::Nearest);
    /// // −39 rounded down to −40
    /// assert_eq!(f, -40);
    /// assert_eq!(dir, Ordering::Less);
    /// # }
    /// ```
    fn mul_from_round(&mut self, lhs: Lhs, round: Self::Round) -> Self::Ordering;
}

/**
Compound division and assignment with a specified rounding method.

# Examples

```rust
# #[cfg(feature = "float")] {
use core::cmp::Ordering;
use rug::{float::Round, ops::DivAssignRound, Float};
struct F(f64);
impl DivAssignRound<f64> for F {
    type Round = Round;
    type Ordering = Ordering;
    fn div_assign_round(&mut self, rhs: f64, round: Round) -> Ordering {
        let mut f = Float::with_val(53, self.0);
        let dir = f.div_assign_round(rhs, round);
        self.0 = f.to_f64();
        dir
    }
}
let mut f = F(3.0);
let dir = f.div_assign_round(4.0, Round::Nearest);
// 3.0 / 4.0 = 0.75
assert_eq!(f.0, 0.75);
assert_eq!(dir, Ordering::Equal);
# }
```
*/
pub trait DivAssignRound<Rhs = Self> {
    /// The rounding method.
    type Round;
    /// The direction from rounding.
    type Ordering;
    /// Performs the division.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "float")] {
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, ops::DivAssignRound, Float};
    /// // only four significant bits
    /// let mut f = Float::with_val(4, -3);
    /// let dir = f.div_assign_round(5, Round::Nearest);
    /// // −0.6 rounded down to −0.625
    /// assert_eq!(f, -0.625);
    /// assert_eq!(dir, Ordering::Less);
    /// # }
    /// ```
    fn div_assign_round(&mut self, rhs: Rhs, round: Self::Round) -> Self::Ordering;
}

/**
Compound division and assignment to the rhs operand with a specified
rounding method.

# Examples

```rust
# #[cfg(feature = "float")] {
use core::cmp::Ordering;
use rug::{
    float::Round,
    ops::{DivAssignRound, DivFromRound},
    Float,
};
struct F(f64);
impl DivFromRound<f64> for F {
    type Round = Round;
    type Ordering = Ordering;
    fn div_from_round(&mut self, lhs: f64, round: Round) -> Ordering {
        let mut f = Float::with_val(53, lhs);
        let dir = f.div_assign_round(self.0, round);
        self.0 = f.to_f64();
        dir
    }
}
let mut f = F(4.0);
let dir = f.div_from_round(3.0, Round::Nearest);
// 3.0 / 4.0 = 0.75
assert_eq!(f.0, 0.75);
assert_eq!(dir, Ordering::Equal);
# }
```
*/
pub trait DivFromRound<Lhs = Self> {
    /// The rounding method.
    type Round;
    /// The direction from rounding.
    type Ordering;
    /// Performs the division.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "float")] {
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, ops::DivFromRound, Float};
    /// // only four significant bits
    /// let mut f = Float::with_val(4, 5);
    /// let dir = f.div_from_round(-3, Round::Nearest);
    /// // −0.6 rounded down to −0.625
    /// assert_eq!(f, -0.625);
    /// assert_eq!(dir, Ordering::Less);
    /// # }
    /// ```
    fn div_from_round(&mut self, lhs: Lhs, round: Self::Round) -> Self::Ordering;
}

/**
Compound remainder operation and assignment with a specified rounding
method.

# Examples

```rust
# #[cfg(feature = "float")] {
use core::cmp::Ordering;
use rug::{float::Round, ops::RemAssignRound, Float};
struct F(f64);
impl RemAssignRound<f64> for F {
    type Round = Round;
    type Ordering = Ordering;
    fn rem_assign_round(&mut self, rhs: f64, round: Round) -> Ordering {
        let mut f = Float::with_val(53, self.0);
        let dir = f.rem_assign_round(rhs, round);
        self.0 = f.to_f64();
        dir
    }
}
let mut f = F(3.25);
let dir = f.rem_assign_round(1.25, Round::Nearest);
// 3.25 % 1.25 = 0.75
assert_eq!(f.0, 0.75);
assert_eq!(dir, Ordering::Equal);
# }
```
*/
pub trait RemAssignRound<Rhs = Self> {
    /// The rounding method.
    type Round;
    /// The direction from rounding.
    type Ordering;
    /// Performs the remainder operation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "float")] {
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, ops::RemAssignRound, Float};
    /// // only four significant bits
    /// let mut f = Float::with_val(4, 64);
    /// let dir = f.rem_assign_round(33, Round::Nearest);
    /// // 31 rounded up to 32
    /// assert_eq!(f, 32);
    /// assert_eq!(dir, Ordering::Greater);
    /// # }
    /// ```
    fn rem_assign_round(&mut self, rhs: Rhs, round: Self::Round) -> Self::Ordering;
}

/**
Compound remainder operation and assignment to the rhs operand with a
specified rounding method.

# Examples

```rust
# #[cfg(feature = "float")] {
use core::cmp::Ordering;
use rug::{
    float::Round,
    ops::{RemAssignRound, RemFromRound},
    Float,
};
struct F(f64);
impl RemFromRound<f64> for F {
    type Round = Round;
    type Ordering = Ordering;
    fn rem_from_round(&mut self, lhs: f64, round: Round) -> Ordering {
        let mut f = Float::with_val(53, lhs);
        let dir = f.rem_assign_round(self.0, round);
        self.0 = f.to_f64();
        dir
    }
}
let mut f = F(1.25);
let dir = f.rem_from_round(3.25, Round::Nearest);
// 3.25 % 1.25 = 0.75
assert_eq!(f.0, 0.75);
assert_eq!(dir, Ordering::Equal);
# }
```
*/
pub trait RemFromRound<Lhs = Self> {
    /// The rounding method.
    type Round;
    /// The direction from rounding.
    type Ordering;
    /// Performs the remainder operation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "float")] {
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, ops::RemFromRound, Float};
    /// // only four significant bits
    /// let mut f = Float::with_val(4, 32);
    /// let dir = f.rem_from_round(17, Round::Nearest);
    /// // 17 rounded down to 16
    /// assert_eq!(f, 16);
    /// assert_eq!(dir, Ordering::Less);
    /// # }
    /// ```
    fn rem_from_round(&mut self, lhs: Lhs, round: Self::Round) -> Self::Ordering;
}

/**
Compound power operation and assignment with a specified rounding
method.

# Examples

```rust
# #[cfg(feature = "float")] {
use core::cmp::Ordering;
use rug::{Float, float::Round, ops::PowAssignRound};
struct F(f64);
impl PowAssignRound<f64> for F {
    type Round = Round;
    type Ordering = Ordering;
    fn pow_assign_round(&mut self, rhs: f64, round: Round) -> Ordering {
        let mut f = Float::with_val(53, self.0);
        let dir = f.pow_assign_round(rhs, round);
        self.0 = f.to_f64();
        dir
    }
}
let mut f = F(3.0);
let dir = f.pow_assign_round(5.0, Round::Nearest);
// 3.0 ^ 5.0 = 243.0
assert_eq!(f.0, 243.0);
assert_eq!(dir, Ordering::Equal);
# }
```
*/
pub trait PowAssignRound<Rhs = Self> {
    /// The rounding method.
    type Round;
    /// The direction from rounding.
    type Ordering;
    /// Performs the power operation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "float")] {
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, ops::PowAssignRound, Float};
    /// // only four significant bits
    /// let mut f = Float::with_val(4, -3);
    /// let dir = f.pow_assign_round(5, Round::Nearest);
    /// // −243 rounded up to −240
    /// assert_eq!(f, -240);
    /// assert_eq!(dir, Ordering::Greater);
    /// # }
    /// ```
    fn pow_assign_round(&mut self, rhs: Rhs, round: Self::Round) -> Self::Ordering;
}

/**
Compound power operation and assignment to the rhs operand with a
specified rounding method.

# Examples

```rust
# #[cfg(feature = "float")] {
use core::cmp::Ordering;
use rug::{
    float::Round,
    ops::{PowAssignRound, PowFromRound},
    Float,
};
struct F(f64);
impl PowFromRound<f64> for F {
    type Round = Round;
    type Ordering = Ordering;
    fn pow_from_round(&mut self, lhs: f64, round: Round) -> Ordering {
        let mut f = Float::with_val(53, lhs);
        let dir = f.pow_assign_round(self.0, round);
        self.0 = f.to_f64();
        dir
    }
}
let mut f = F(5.0);
let dir = f.pow_from_round(3.0, Round::Nearest);
// 3.0 ^ 5.0 = 243.0
assert_eq!(f.0, 243.0);
assert_eq!(dir, Ordering::Equal);
# }
```
*/
pub trait PowFromRound<Lhs = Self> {
    /// The rounding method.
    type Round;
    /// The direction from rounding.
    type Ordering;
    /// Performs the power operation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "float")] {
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, ops::PowFromRound, Float};
    /// // only four significant bits
    /// let mut f = Float::with_val(4, 5);
    /// let dir = f.pow_from_round(-3, Round::Nearest);
    /// // −243 rounded up to −240
    /// assert_eq!(f, -240);
    /// assert_eq!(dir, Ordering::Greater);
    /// # }
    /// ```
    fn pow_from_round(&mut self, lhs: Lhs, round: Self::Round) -> Self::Ordering;
}

/**
Rounding variants of division.

# Examples

```rust
use rug::ops::DivRounding;
struct I(i32);
impl DivRounding<i32> for I {
    type Output = i32;
    fn div_trunc(self, rhs: i32) -> i32 {
        self.0 / rhs
    }
    fn div_ceil(self, rhs: i32) -> i32 {
        let (q, r) = (self.0 / rhs, self.0 % rhs);
        let change = if rhs > 0 { r > 0 } else { r < 0 };
        if change {
            q + 1
        } else {
            q
        }
    }
    fn div_floor(self, rhs: i32) -> i32 {
        let (q, r) = (self.0 / rhs, self.0 % rhs);
        let change = if rhs > 0 { r < 0 } else { r > 0 };
        if change {
            q - 1
        } else {
            q
        }
    }
    fn div_euc(self, rhs: i32) -> i32 {
        let (q, r) = (self.0 / rhs, self.0 % rhs);
        if r < 0 {
            if rhs < 0 {
                q + 1
            } else {
                q - 1
            }
        } else {
            q
        }
    }
}
assert_eq!(I(-10).div_trunc(-3), 3);
assert_eq!(I(-10).div_ceil(-3), 4);
assert_eq!(I(-10).div_floor(-3), 3);
assert_eq!(I(-10).div_euc(-3), 4);
```
*/
pub trait DivRounding<Rhs = Self> {
    /// The resulting type from the division operation.
    type Output;
    /// Performs division, rounding the quotient towards zero.
    fn div_trunc(self, rhs: Rhs) -> Self::Output;
    /// Performs division, rounding the quotient up.
    fn div_ceil(self, rhs: Rhs) -> Self::Output;
    /// Performs division, rounding the quotient down.
    fn div_floor(self, rhs: Rhs) -> Self::Output;
    /// Performs Euclidean division, rounding the quotient so that the
    /// remainder cannot be negative.
    fn div_euc(self, rhs: Rhs) -> Self::Output;
}

/**
Compound assignment and rounding variants of division.

# Examples

```rust
use rug::ops::DivRoundingAssign;
struct I(i32);
impl DivRoundingAssign<i32> for I {
    fn div_trunc_assign(&mut self, rhs: i32) {
        self.0 /= rhs;
    }
    fn div_ceil_assign(&mut self, rhs: i32) {
        let (q, r) = (self.0 / rhs, self.0 % rhs);
        let change = if rhs > 0 { r > 0 } else { r < 0 };
        self.0 = if change { q + 1 } else { q };
    }
    fn div_floor_assign(&mut self, rhs: i32) {
        let (q, r) = (self.0 / rhs, self.0 % rhs);
        let change = if rhs > 0 { r < 0 } else { r > 0 };
        self.0 = if change { q - 1 } else { q };
    }
    fn div_euc_assign(&mut self, rhs: i32) {
        let (q, r) = (self.0 / rhs, self.0 % rhs);
        self.0 = if r < 0 {
            if rhs < 0 {
                q + 1
            } else {
                q - 1
            }
        } else {
            q
        };
    }
}
let mut div_floor = I(-10);
div_floor.div_floor_assign(3);
assert_eq!(div_floor.0, -4);
```
*/
pub trait DivRoundingAssign<Rhs = Self> {
    /// Performs division, rounding the quotient towards zero.
    fn div_trunc_assign(&mut self, rhs: Rhs);
    /// Performs division, rounding the quotient up.
    fn div_ceil_assign(&mut self, rhs: Rhs);
    /// Performs division, rounding the quotient down.
    fn div_floor_assign(&mut self, rhs: Rhs);
    /// Performs Euclidean division, rounding the quotient so that the
    /// remainder cannot be negative.
    fn div_euc_assign(&mut self, rhs: Rhs);
}

/**
Compound assignment to the rhs operand and rounding variants of
division.

# Examples

```rust
use rug::ops::DivRoundingFrom;
struct I(i32);
impl DivRoundingFrom<i32> for I {
    fn div_trunc_from(&mut self, lhs: i32) {
        self.0 = lhs / self.0;
    }
    fn div_ceil_from(&mut self, lhs: i32) {
        let (q, r) = (lhs / self.0, lhs % self.0);
        let change = if self.0 > 0 { r > 0 } else { r < 0 };
        self.0 = if change { q + 1 } else { q };
    }
    fn div_floor_from(&mut self, lhs: i32) {
        let (q, r) = (lhs / self.0, lhs % self.0);
        let change = if self.0 > 0 { r < 0 } else { r > 0 };
        self.0 = if change { q - 1 } else { q };
    }
    fn div_euc_from(&mut self, lhs: i32) {
        let (q, r) = (lhs / self.0, lhs % self.0);
        self.0 = if r < 0 {
            if self.0 < 0 {
                q + 1
            } else {
                q - 1
            }
        } else {
            q
        };
    }
}
let mut div_ceil = I(3);
div_ceil.div_ceil_from(10);
assert_eq!(div_ceil.0, 4);
```
*/
pub trait DivRoundingFrom<Lhs = Self> {
    /// Performs division, rounding the quotient towards zero.
    fn div_trunc_from(&mut self, lhs: Lhs);
    /// Performs division, rounding the quotient up.
    fn div_ceil_from(&mut self, lhs: Lhs);
    /// Performs division, rounding the quotient down.
    fn div_floor_from(&mut self, lhs: Lhs);
    /// Performs Euclidean division, rounding the quotient so that the
    /// remainder cannot be negative.
    fn div_euc_from(&mut self, lhs: Lhs);
}

/**
Rounding variants of the remainder operation.

# Examples

```rust
use rug::ops::RemRounding;
struct I(i32);
impl RemRounding<i32> for I {
    type Output = i32;
    fn rem_trunc(self, rhs: i32) -> i32 {
        self.0 % rhs
    }
    fn rem_ceil(self, rhs: i32) -> i32 {
        let r = self.0 % rhs;
        let change = if rhs > 0 { r > 0 } else { r < 0 };
        if change {
            r - rhs
        } else {
            r
        }
    }
    fn rem_floor(self, rhs: i32) -> i32 {
        let r = self.0 % rhs;
        let change = if rhs > 0 { r < 0 } else { r > 0 };
        if change {
            r + rhs
        } else {
            r
        }
    }
    fn rem_euc(self, rhs: i32) -> i32 {
        let r = self.0 % rhs;
        if r < 0 {
            if rhs < 0 {
                r - rhs
            } else {
                r + rhs
            }
        } else {
            r
        }
    }
}
assert_eq!(I(-10).rem_trunc(-3), -1);
assert_eq!(I(-10).rem_ceil(-3), 2);
assert_eq!(I(-10).rem_floor(-3), -1);
assert_eq!(I(-10).rem_euc(-3), 2);
```
*/
pub trait RemRounding<Rhs = Self> {
    /// The resulting type from the remainder operation.
    type Output;
    /// Finds the remainder when the quotient is rounded towards zero.
    fn rem_trunc(self, rhs: Rhs) -> Self::Output;
    /// Finds the remainder when the quotient is rounded up.
    fn rem_ceil(self, rhs: Rhs) -> Self::Output;
    /// Finds the remainder when the quotient is rounded down.
    fn rem_floor(self, rhs: Rhs) -> Self::Output;
    /// Finds the positive remainder from Euclidean division.
    fn rem_euc(self, rhs: Rhs) -> Self::Output;
}

/**
Compound assignment and rounding variants of the remainder operation.

# Examples

```rust
use rug::ops::RemRoundingAssign;
struct I(i32);
impl RemRoundingAssign<i32> for I {
    fn rem_trunc_assign(&mut self, rhs: i32) {
        self.0 %= rhs;
    }
    fn rem_ceil_assign(&mut self, rhs: i32) {
        let r = self.0 % rhs;
        let change = if rhs > 0 { r > 0 } else { r < 0 };
        self.0 = if change { r - rhs } else { r };
    }
    fn rem_floor_assign(&mut self, rhs: i32) {
        let r = self.0 % rhs;
        let change = if rhs > 0 { r < 0 } else { r > 0 };
        self.0 = if change { r + rhs } else { r };
    }
    fn rem_euc_assign(&mut self, rhs: i32) {
        let r = self.0 % rhs;
        self.0 = if r < 0 {
            if rhs < 0 {
                r - rhs
            } else {
                r + rhs
            }
        } else {
            r
        };
    }
}
let mut rem_floor = I(-10);
rem_floor.rem_floor_assign(3);
assert_eq!(rem_floor.0, 2);
```
*/
pub trait RemRoundingAssign<Rhs = Self> {
    /// Finds the remainder when the quotient is rounded towards zero.
    fn rem_trunc_assign(&mut self, rhs: Rhs);
    /// Finds the remainder when the quotient is rounded up.
    fn rem_ceil_assign(&mut self, rhs: Rhs);
    /// Finds the remainder when the quotient is rounded down.
    fn rem_floor_assign(&mut self, rhs: Rhs);
    /// Finds the positive remainder from Euclidean division.
    fn rem_euc_assign(&mut self, rhs: Rhs);
}

/**
Compound assignment to the rhs operand and rounding variants of the
remainder operation.

# Examples

```rust
use rug::ops::RemRoundingFrom;
struct I(i32);
impl RemRoundingFrom<i32> for I {
    fn rem_trunc_from(&mut self, lhs: i32) {
        self.0 = lhs % self.0;
    }
    fn rem_ceil_from(&mut self, lhs: i32) {
        let r = lhs % self.0;
        let change = if self.0 > 0 { r > 0 } else { r < 0 };
        self.0 = if change { r - self.0 } else { r };
    }
    fn rem_floor_from(&mut self, lhs: i32) {
        let r = lhs % self.0;
        let change = if self.0 > 0 { r < 0 } else { r > 0 };
        self.0 = if change { r + self.0 } else { r };
    }
    fn rem_euc_from(&mut self, lhs: i32) {
        let r = lhs % self.0;
        self.0 = if r < 0 {
            if self.0 < 0 {
                r - self.0
            } else {
                r + self.0
            }
        } else {
            r
        };
    }
}
let mut rem_ceil = I(3);
rem_ceil.rem_ceil_from(10);
assert_eq!(rem_ceil.0, -2);
```
*/
pub trait RemRoundingFrom<Lhs = Self> {
    /// Finds the remainder when the quotient is rounded towards zero.
    fn rem_trunc_from(&mut self, lhs: Lhs);
    /// Finds the remainder when the quotient is rounded up.
    fn rem_ceil_from(&mut self, lhs: Lhs);
    /// Finds the remainder when the quotient is rounded down.
    fn rem_floor_from(&mut self, lhs: Lhs);
    /// Finds the positive remainder from Euclidean division.
    fn rem_euc_from(&mut self, lhs: Lhs);
}
