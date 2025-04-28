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

use crate::Complex;
use core::{
    cmp::Ordering,
    hash::{Hash, Hasher},
};

/**
A complex number that supports total ordering and hashing.

For ordering, the real part has precedence over the imaginary part.
Negative zero is ordered as less than positive zero. Negative NaN is
ordered as less than negative infinity, while positive NaN is ordered
as greater than positive infinity. Comparing two negative NaNs or two
positive NaNs produces equality.

# Examples

```rust
use core::cmp::Ordering;
use rug::{complex::OrdComplex, float::Special, Complex};

let nan_c = Complex::with_val(53, (Special::Nan, Special::Nan));
let nan = OrdComplex::from(nan_c);
assert_eq!(nan.cmp(&nan), Ordering::Equal);

let one_neg0_c = Complex::with_val(53, (1, Special::NegZero));
let one_neg0 = OrdComplex::from(one_neg0_c);
let one_pos0_c = Complex::with_val(53, (1, Special::Zero));
let one_pos0 = OrdComplex::from(one_pos0_c);
assert_eq!(one_neg0.cmp(&one_pos0), Ordering::Less);

let zero_inf_s = (Special::Zero, Special::Infinity);
let zero_inf_c = Complex::with_val(53, zero_inf_s);
let zero_inf = OrdComplex::from(zero_inf_c);
assert_eq!(one_pos0.cmp(&zero_inf), Ordering::Greater);
```
*/
#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct OrdComplex {
    inner: Complex,
}

static_assert_same_layout!(OrdComplex, Complex);

impl OrdComplex {
    /// Extracts the underlying [`Complex`].
    ///
    /// The same result can be obtained using the implementation of
    /// <code>[AsRef][`AsRef`]&lt;[Complex][`Complex`]&gt;</code>
    /// which is provided for [`OrdComplex`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{complex::OrdComplex, Complex};
    /// let c = Complex::with_val(53, (1.5, 2.5));
    /// let ord = OrdComplex::from(c);
    /// let c_ref = ord.as_complex();
    /// assert_eq!(*c_ref.real(), 1.5);
    /// assert_eq!(*c_ref.imag(), 2.5);
    /// ```
    ///
    /// [`AsRef`]: https://doc.rust-lang.org/nightly/core/convert/trait.AsRef.html
    /// [`Complex`]: ../struct.Complex.html
    /// [`OrdComplex`]: struct.OrdComplex.html
    #[inline]
    pub fn as_complex(&self) -> &Complex {
        &self.inner
    }

    /// Extracts the underlying [`Complex`].
    ///
    /// The same result can be obtained using the implementation of
    /// <code>[AsMut][`AsMut`]&lt;[Complex][`Complex`]&gt;</code>
    /// which is provided for [`OrdComplex`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{complex::OrdComplex, Complex};
    /// let c = Complex::with_val(53, (1.5, -2.5));
    /// let mut ord = OrdComplex::from(c);
    /// ord.as_complex_mut().conj_mut();
    /// let c_ref = ord.as_complex();
    /// assert_eq!(*c_ref.real(), 1.5);
    /// assert_eq!(*c_ref.imag(), 2.5);
    /// ```
    ///
    /// [`AsMut`]: https://doc.rust-lang.org/nightly/core/convert/trait.AsMut.html
    /// [`Complex`]: ../struct.Complex.html
    /// [`OrdComplex`]: struct.OrdComplex.html
    #[inline]
    pub fn as_complex_mut(&mut self) -> &mut Complex {
        &mut self.inner
    }
}

impl Hash for OrdComplex {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.real().as_ord().hash(state);
        self.inner.imag().as_ord().hash(state);
    }
}

impl Eq for OrdComplex {}

impl Ord for OrdComplex {
    #[inline]
    fn cmp(&self, other: &OrdComplex) -> Ordering {
        let real = self.inner.real().as_ord().cmp(other.inner.real().as_ord());
        let imag = self.inner.imag().as_ord().cmp(other.inner.imag().as_ord());
        real.then(imag)
    }
}

impl PartialEq for OrdComplex {
    #[inline]
    fn eq(&self, other: &OrdComplex) -> bool {
        let real = self.inner.real().as_ord().eq(other.inner.real().as_ord());
        let imag = self.inner.imag().as_ord().eq(other.inner.imag().as_ord());
        real && imag
    }
}

impl PartialOrd for OrdComplex {
    #[inline]
    fn partial_cmp(&self, other: &OrdComplex) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<Complex> for OrdComplex {
    #[inline]
    fn from(src: Complex) -> Self {
        OrdComplex { inner: src }
    }
}

impl From<OrdComplex> for Complex {
    #[inline]
    fn from(src: OrdComplex) -> Self {
        src.inner
    }
}

impl AsRef<Complex> for OrdComplex {
    #[inline]
    fn as_ref(&self) -> &Complex {
        self.as_complex()
    }
}

impl AsMut<Complex> for OrdComplex {
    #[inline]
    fn as_mut(&mut self) -> &mut Complex {
        self.as_complex_mut()
    }
}

#[allow(clippy::eq_op)]
#[cfg(test)]
mod tests {
    use crate::{
        complex::OrdComplex,
        float::{self, FreeCache, Special},
        Complex,
    };
    use core::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;

    fn calculate_hash<T: Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }

    #[test]
    fn check_zero() {
        let pp = Complex::with_val(53, (Special::Zero, Special::Zero));
        let pn = Complex::with_val(53, (Special::Zero, Special::NegZero));
        let np = Complex::with_val(53, (Special::NegZero, Special::Zero));
        let nn = Complex::with_val(53, (Special::NegZero, Special::NegZero));
        assert_eq!(pp, pn);
        assert_eq!(pn, np);
        assert_eq!(np, nn);
        assert_eq!(nn, pp);
        let ord_pp = pp.as_ord();
        let ord_pn = pn.as_ord();
        let ord_np = np.as_ord();
        let ord_nn = nn.as_ord();
        assert_eq!(ord_pp, ord_pp);
        assert_eq!(ord_pn, ord_pn);
        assert_eq!(ord_np, ord_np);
        assert_eq!(ord_nn, ord_nn);
        assert_eq!(calculate_hash(ord_pp), calculate_hash(ord_pp));
        assert_eq!(calculate_hash(ord_pn), calculate_hash(ord_pn));
        assert_eq!(calculate_hash(ord_np), calculate_hash(ord_np));
        assert_eq!(calculate_hash(ord_nn), calculate_hash(ord_nn));
        assert_ne!(ord_pp, ord_pn);
        assert_ne!(ord_pn, ord_np);
        assert_ne!(ord_np, ord_nn);
        assert_ne!(ord_nn, ord_pp);
        assert_ne!(calculate_hash(ord_pp), calculate_hash(ord_pn));
        assert_ne!(calculate_hash(ord_pn), calculate_hash(ord_np));
        assert_ne!(calculate_hash(ord_np), calculate_hash(ord_nn));
        assert_ne!(calculate_hash(ord_nn), calculate_hash(ord_pp));

        float::free_cache(FreeCache::All);
    }

    #[test]
    fn check_refs() {
        let f = Complex::with_val(53, (23.5, 32.5));
        assert_eq!(
            &f as *const Complex as *const OrdComplex,
            f.as_ord() as *const OrdComplex
        );
        assert_eq!(
            &f as *const Complex as *const OrdComplex,
            AsRef::<OrdComplex>::as_ref(&f) as *const OrdComplex
        );
        let mut o = OrdComplex::from(f);
        assert_eq!(
            &o as *const OrdComplex as *const Complex,
            o.as_complex() as *const Complex
        );
        assert_eq!(
            &o as *const OrdComplex as *const Complex,
            AsRef::<Complex>::as_ref(&o) as *const Complex
        );
        assert_eq!(
            &mut o as *mut OrdComplex as *mut Complex,
            o.as_complex_mut() as *mut Complex
        );
        assert_eq!(
            &mut o as *mut OrdComplex as *mut Complex,
            AsMut::<Complex>::as_mut(&mut o) as *mut Complex
        );
    }
}
