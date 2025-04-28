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

// unit argument useful for type-level Option types OptInteger,
// OptRational, OptFloat, OptComplex
#![allow(clippy::unit_arg)]

#[cfg(feature = "complex")]
pub mod xmpc;
#[cfg(feature = "float")]
pub mod xmpfr;
#[cfg(feature = "rational")]
pub mod xmpq;
#[cfg(feature = "integer")]
pub mod xmpz;
#[cfg(all(feature = "integer", gmp_limb_bits_32))]
mod xmpz32;
#[cfg(all(feature = "integer", gmp_limb_bits_64))]
mod xmpz64;
