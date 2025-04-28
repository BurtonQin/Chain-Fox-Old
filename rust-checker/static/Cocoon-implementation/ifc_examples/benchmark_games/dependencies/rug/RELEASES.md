<!-- Copyright © 2016–2020 University of Malta -->

<!-- Copying and distribution of this file, with or without
modification, are permitted in any medium without royalty provided the
copyright notice and this notice are preserved. This file is offered
as-is, without any warranty. -->

Version 1.12.0 (2021-03-25)
===========================

  * A new method
    <code>[Integer][int-1-12]::[as\_limbs][int-al-1-12]</code> was
    added.
  * The [*az* crate] dependency was updated to [version 1.1][az-1-1].

[az-1-1]: https://docs.rs/az/~1.1/az/index.html
[int-1-12]: https://docs.rs/rug/~1.12/rug/struct.Integer.html
[int-al-1-12]: https://docs.rs/rug/~1.12/rug/struct.Integer.html#method.as_limbs

Version 1.11.0 (2020-09-03)
===========================

  * The [gmp-mpfr-sys] dependency was updated to [version
    1.4][sys-1-4].
  * Now it is possible to display [`Float`][flo-1-11] numbers with
    only one siginificant digit.

[flo-1-11]: https://docs.rs/rug/~1.11/rug/struct.Float.html
[sys-1-4]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/index.html

Version 1.10.0 (2020-07-23)
===========================

  * The [gmp-mpfr-sys] dependency was updated to [version
    1.3][sys-1-3].
  * Now <code>[Option][`Option`]&lt;[Integer][int-1-10]&gt;</code> has
    the same size as [`Integer`][int-1-10]; and similar for
    [`Rational`][rat-1-10], [`Float`][flo-1-10],
    [`Complex`][com-1-10], [`RandState`][ras-1-10] and
    [`ThreadRandState`][trs-1-10].

[com-1-10]: https://docs.rs/rug/~1.10/rug/struct.Complex.html
[flo-1-10]: https://docs.rs/rug/~1.10/rug/struct.Float.html
[int-1-10]: https://docs.rs/rug/~1.10/rug/struct.Integer.html
[ras-1-10]: https://docs.rs/rug/~1.10/rug/rand/struct.RandState.html
[rat-1-10]: https://docs.rs/rug/~1.10/rug/struct.Rational.html
[sys-1-3]: https://docs.rs/gmp-mpfr-sys/~1.3/gmp_mpfr_sys/index.html
[trs-1-10]: https://docs.rs/rug/~1.10/rug/rand/struct.ThreadRandState.html

Version 1.9.0 (2020-06-01)
==========================

  * Displaying [`Float`][flo-1-9] and [`Complex`][com-1-9] numbers,
    and converting them to strings, now avoids outputting an exponent
    term if the radix point can be moved to the correct place without
    inserting any extra digits. For example `"42.0"` will be produced
    rather than `"4.20e1"` ([issue 18]). This change does not affect
    output when [`LowerExp`] (`"{:e}"` format) or [`UpperExp`]
    (`"{:E}"` format) is used.
  * New methods
    <code>[Float][flo-1-9]::[to\_sign\_string\_exp][flo-tsse-1-9]</code>
    and
    <code>[Float][flo-1-9]::[to\_sign\_string\_exp\_round][flo-tsser-1-9]</code>
    were added.
  * A new function
    <code>[float][flom-1-9]::[allowed\_exp\_range][flom-aer-1-9]</code>
    was added.
  * A new method
    <code>[Float][flo-1-9]::[clamp\_exp][flo-ce-1-9]</code> was added.
  * The following methods are now const functions:
      * <code>[Integer][int-1-9]::[from\_raw][int-fr-1-9]</code>,
        <code>[Rational][rat-1-9]::[from\_raw][rat-fr-1-9]</code>
  * The [*az* crate] is now a public dependency, and wrapping and
    checked casts to/from primitives and big numbers are provided
    through the traits of the crate.

Compatibility note
------------------

The output of [`Float`][flo-1-9] and [`Complex`][com-1-9] numbers was
changed as specified above.

[com-1-9]: https://docs.rs/rug/~1.9/rug/struct.Complex.html
[flo-1-9]: https://docs.rs/rug/~1.9/rug/struct.Float.html
[flo-ce-1-9]: https://docs.rs/rug/~1.9/rug/struct.Float.html#method.clamp_exp
[flo-tsse-1-9]: https://docs.rs/rug/~1.9/rug/struct.Float.html#method.to_sign_string_exp
[flo-tsser-1-9]: https://docs.rs/rug/~1.9/rug/struct.Float.html#method.to_sign_string_exp_round
[flom-1-9]: https://docs.rs/rug/~1.9/rug/float/index.html
[flom-aer-1-9]: https://docs.rs/rug/~1.9/rug/float/fn.allowed_exp_range.html
[int-1-9]: https://docs.rs/rug/~1.9/rug/struct.Integer.html
[int-fr-1-9]: https://docs.rs/rug/~1.9/rug/struct.Integer.html#method.from_raw
[issue 18]: https://gitlab.com/tspiteri/rug/-/issues/18
[rat-1-9]: https://docs.rs/rug/~1.9/rug/struct.Rational.html
[rat-fr-1-9]: https://docs.rs/rug/~1.9/rug/struct.Rational.html#method.from_raw

Version 1.8.0 (2020-04-08)
==========================

  * The following methods are now const functions:
      * <code>[Integer][int-1-8]::[new][int-n-1-8]</code>,
	    <code>[Integer][int-1-8]::[into\_raw][int-ir-1-8]</code>,
	    <code>[Integer][int-1-8]::[as\_raw][int-araw-1-8]</code>
      * <code>[SmallInteger][smi-1-8]::[new][smi-n-1-8]</code>,
        <code>[SmallRational][smr-1-8]::[new][smr-n-1-8]</code>
  * A new method
    <code>[Integer][int-1-8]::[as\_rational][int-arat-1-8]</code> was
    added.
  * A new method
    <code>[Float][flo-1-8]::[as\_complex][flo-ac-1-8]</code> was
    added.
  * [`SmallFloat`][smf-1-8] and [`SmallComplex`][smc-1-8] can now be
    initialized with [`Special`][spe-1-8].
  * New methods <code>[SmallFloat][smf-1-8]::[new][smf-n-1-8]</code>
    and <code>[SmallComplex][smc-1-8]::[new][smc-n-1-8]</code> were
    added.
  * [`SmallFloat`][smf-1-8] and [`SmallComplex`][smc-1-8] now
    implement [`Default`].
  * [`Integer`][int-1-8] now implements
    <code>[AsRef][`AsRef`]&lt;[\[][slice][limb_t][sys-limb-1-2][\]][slice]&gt;</code>.
  * [`Float`][flo-1-8] now implements
    <code>[AsRef][`AsRef`]&lt;[OrdFloat][of-1-8]&gt;</code>, and
    [`OrdFloat`][of-1-8] now implements
    <code>[AsRef][`AsRef`]&lt;[Float][flo-1-8]&gt;</code> and
    <code>[AsMut][`AsMut`]&lt;[Float][flo-1-8]&gt;</code>.
  * [`Complex`][com-1-8] now implements
    <code>[AsRef][`AsRef`]&lt;[OrdComplex][oc-1-8]&gt;</code>, and
    [`OrdComplex`][oc-1-8] now implements
    <code>[AsRef][`AsRef`]&lt;[Complex][com-1-8]&gt;</code> and
    <code>[AsMut][`AsMut`]&lt;[Complex][com-1-8]&gt;</code>.

[com-1-8]: https://docs.rs/rug/~1.8/rug/struct.Complex.html
[flo-1-8]: https://docs.rs/rug/~1.8/rug/struct.Float.html
[flo-ac-1-8]: https://docs.rs/rug/~1.8/rug/struct.Float.html#method.as_complex
[int-1-8]: https://docs.rs/rug/~1.8/rug/struct.Integer.html
[int-arat-1-8]: https://docs.rs/rug/~1.8/rug/struct.Integer.html#method.as_rational
[int-araw-1-8]: https://docs.rs/rug/~1.8/rug/struct.Integer.html#method.as_raw
[int-ir-1-8]: https://docs.rs/rug/~1.8/rug/struct.Integer.html#method.into_raw
[int-n-1-8]: https://docs.rs/rug/~1.8/rug/struct.Integer.html#method.new
[oc-1-8]: https://docs.rs/rug/~1.8/rug/complex/struct.OrdComplex.html
[of-1-8]: https://docs.rs/rug/~1.8/rug/float/struct.OrdFloat.html
[smc-1-8]: https://docs.rs/rug/~1.8/rug/complex/struct.SmallComplex.html
[smc-n-1-8]: https://docs.rs/rug/~1.8/rug/complex/struct.SmallComplex.html#method.new
[smf-1-8]: https://docs.rs/rug/~1.8/rug/float/struct.SmallFloat.html
[smf-n-1-8]: https://docs.rs/rug/~1.8/rug/float/struct.SmallFloat.html#method.new
[smi-1-8]: https://docs.rs/rug/~1.8/rug/integer/struct.SmallInteger.html
[smi-n-1-8]: https://docs.rs/rug/~1.8/rug/integer/struct.SmallInteger.html#method.new
[smr-1-8]: https://docs.rs/rug/~1.8/rug/rational/struct.SmallRational.html
[smr-n-1-8]: https://docs.rs/rug/~1.8/rug/rational/struct.SmallRational.html#method.new
[spe-1-8]: https://docs.rs/rug/~1.8/rug/float/enum.Special.html
[sys-limb-1-2]: https://docs.rs/gmp-mpfr-sys/~1.2/gmp_mpfr_sys/gmp/type.limb_t.html

Version 1.7.0 (2020-01-21)
==========================

  * The crate now requires rustc version 1.37.0 or later.
  * The [gmp-mpfr-sys] dependency was updated to [version
    1.2][sys-1-2].
  * The [`RemAssignRound`][rar-1-7] and [`RemFromRound`][rfr-1-7]
    traits were added.
  * The [`Rem`], [`RemAssign`], [`RemFrom`][rf-1-7],
    [`RemAssignRound`][rar-1-7] and [`RemFromRound`][rfr-1-7] traits
    were implemented for [`Float`][flo-1-7].
  * Arithmetic operations with one [`Integer`][int-1-7] or integer
    primitive operand and one [`Rational`][rat-1-7] operand were
    added.
  * A new method
    <code>[Integer][int-1-7]::[div\_exact\_from][int-def-1-7]</code>
    was added.
  * New methods <code>[Integer][int-1-7]::[gcd\_u][int-gu-1-7]</code>,
	<code>[Integer][int-1-7]::[gcd\_u\_mut][int-gum-1-7]</code> and
	<code>[Integer][int-1-7]::[gcd\_u\_ref][int-gur-1-7]</code>were
	added.
  * New methods <code>[Integer][int-1-7]::[lcm\_u][int-lu-1-7]</code>,
	<code>[Integer][int-1-7]::[lcm\_u\_mut][int-lum-1-7]</code> and
	<code>[Integer][int-1-7]::[lcm\_u\_ref][int-lur-1-7]</code>were
	added.
  * New methods <code>[Float][flo-1-7]::[remainder][flo-r-1-7]</code>,
    <code>[Float][flo-1-7]::[remainder\_mut][flo-rm-1-7]</code>,
    <code>[Float][flo-1-7]::[remainder\_round][flo-rr-1-7]</code>,
    <code>[Float][flo-1-7]::[remainder\_from][flo-rf-1-7]</code>,
    <code>[Float][flo-1-7]::[remainder\_from\_round][flo-rfr-1-7]</code>
    and <code>[Float][flo-1-7]::[remainder\_ref][flo-rre-1-7]</code>
    were added.

Compatibility note
------------------

  * [`SmallInteger`][smi-1-7], [`SmallRational`][smr-1-7],
    [`SmallFloat`][smf-1-7] and [`SmallComplex`][smc-1-7] are no
    longer [`Sync`] to avoid the possibility of a [data race][dr-1-7].
    References obtained by dereferencing them, for example the
    <code>&amp;[Integer][int-1-7]</code> returned from
    <code>[SmallInteger][smi-1-7]::[deref][`deref`]</code>, are still
    [`Send`] and [`Sync`].

[dr-1-7]: https://internals.rust-lang.org/t/is-this-a-data-race/11582
[flo-1-7]: https://docs.rs/rug/~1.7/rug/struct.Float.html
[flo-r-1-7]: https://docs.rs/rug/~1.7/rug/struct.Float.html#method.remainder
[flo-rf-1-7]: https://docs.rs/rug/~1.7/rug/struct.Float.html#method.remainder_from
[flo-rfr-1-7]: https://docs.rs/rug/~1.7/rug/struct.Float.html#method.remainder_from_round
[flo-rm-1-7]: https://docs.rs/rug/~1.7/rug/struct.Float.html#method.remainder_mut
[flo-rr-1-7]: https://docs.rs/rug/~1.7/rug/struct.Float.html#method.remainder_round
[flo-rre-1-7]: https://docs.rs/rug/~1.7/rug/struct.Float.html#method.remainder_ref
[int-1-7]: https://docs.rs/rug/~1.7/rug/struct.Integer.html
[int-def-1-7]: https://docs.rs/rug/~1.7/rug/struct.Integer.html#method.div_exact_from
[int-gu-1-7]: https://docs.rs/rug/~1.7/rug/struct.Integer.html#method.gcd_u
[int-gum-1-7]: https://docs.rs/rug/~1.7/rug/struct.Integer.html#method.gcd_u_mut
[int-gur-1-7]: https://docs.rs/rug/~1.7/rug/struct.Integer.html#method.gcd_u_ref
[int-lu-1-7]: https://docs.rs/rug/~1.7/rug/struct.Integer.html#method.lcm_u
[int-lum-1-7]: https://docs.rs/rug/~1.7/rug/struct.Integer.html#method.lcm_u_mut
[int-lur-1-7]: https://docs.rs/rug/~1.7/rug/struct.Integer.html#method.lcm_u_ref
[rar-1-7]: https://docs.rs/rug/~1.7/rug/ops/trait.RemAssignRound.html
[rat-1-7]: https://docs.rs/rug/~1.7/rug/struct.Rational.html
[rf-1-7]: https://docs.rs/rug/~1.7/rug/ops/trait.RemFrom.html
[rfr-1-7]: https://docs.rs/rug/~1.7/rug/ops/trait.RemFromRound.html
[smc-1-7]: https://docs.rs/rug/~1.7/rug/complex/struct.SmallComplex.html
[smf-1-7]: https://docs.rs/rug/~1.7/rug/float/struct.SmallFloat.html
[smi-1-7]: https://docs.rs/rug/~1.7/rug/integer/struct.SmallInteger.html
[smr-1-7]: https://docs.rs/rug/~1.7/rug/rational/struct.SmallRational.html
[sys-1-2]: https://docs.rs/gmp-mpfr-sys/~1.2/gmp_mpfr_sys/index.html

Version 1.6.0 (2019-09-03)
==========================

  * Arithmetic operator implementations for [`i8`], [`i16`], [`i64`],
    [`i128`], [`u8`], [`u16`], [`u64`] and [`u128`] were added to the
    existing implementations for [`i32`] and [`u32`].
  * A new function
    <code>[float][flom-1-6]::[free\_cache][fc-1-6]</code> and its
    supporting enum [`FreeCache`][fce-1-6] were added.
  * A new method
    <code>[RandState][ras-1-6]::[into\_custom\_boxed][ras-icb-1-6]</code>
    was added.
  * A new struct [`ThreadRandState`][trs-1-6] and a new trait
    [`ThreadRandGen`][trg-1-6] were added to the [`rand`][ram-1-6]
    module to enable the use of custom random generators that are not
    [`Send`] and [`Sync`].
  * Numeric type methods which take [`RandState`][ras-1-6] now can
    also take [`ThreadRandState`][trs-1-6].

Compatibility note
------------------

  * The numeric type methods which took
    <code>&mut [RandState][ras-1-6]</code> were changed to take
    <code>&mut dyn [MutRandState][mrs-1-6]</code> instead. Under
    normal use, this does not have any affect apart from allowing the
    use of <code>&mut [ThreadRandState][trs-1-6]</code> as well. With
    function inlining and optimization, the generated code should have
    the same performance.

[fc-1-6]: https://docs.rs/rug/~1.6/rug/float/fn.free_cache.html
[fce-1-6]: https://docs.rs/rug/~1.6/rug/float/enum.FreeCache.html
[flom-1-6]: https://docs.rs/rug/~1.6/rug/float/index.html
[mrs-1-6]: https://docs.rs/rug/~1.6/rug/rand/trait.MutRandState.html
[ram-1-6]: https://docs.rs/rug/~1.6/rug/rand/index.html
[ras-1-6]: https://docs.rs/rug/~1.6/rug/rand/struct.RandState.html
[ras-icb-1-6]: https://docs.rs/rug/~1.6/rug/rand/struct.RandState.html#method.into_custom_boxed
[trg-1-6]: https://docs.rs/rug/~1.6/rug/rand/trait.ThreadRandGen.html
[trs-1-6]: https://docs.rs/rug/~1.6/rug/rand/struct.ThreadRandState.html

Version 1.5.2 (2019-07-26)
==========================

  * Bug fix:
    <code>[Pow][pow-1-5]&lt;[i32][`i32`]&gt; for [Rational][rat-1-5]</code>
	was returning the reciprocal of the correct result.

Version 1.5.1 (2019-07-10)
==========================

  * Bug fix: a memory leak in conversions of [`Float`][flo-1-5] to
    string was fixed (https://gitlab.com/tspiteri/rug/-/issues/11).

Version 1.5.0 (2019-07-04)
==========================

  * A new method
    <code>[Integer][int-1-5]::[assign\_digits\_unaligned][int-adu-1-5]</code>
    was added to enable reading digits from unaligned memory.
  * A new method
    <code>[Integer][int-1-5]::[write\_digits\_unaligned][int-wdu-1-5]</code>
    was added to enable writing digits to unaligned and uninitialized
    memory.
  * New methods <code>[Float][flo-1-5]::[u\_exp][flo-ue-1-5]</code>
    and <code>[Float][flo-1-5]::[i\_exp][flo-ie-1-5]</code> were
    added.
  * A new method
    <code>[Complex][com-1-5]::[abs\_round][com-ar-1-5]</code> was
    added.
  * The documentation examples on [`from_raw`][fr-1-5] methods now use
    [`MaybeUninit`] instead of
    <code>[mem][`mem`]::[uninitialized][`uninitialized`]</code>.

[com-1-5]: https://docs.rs/rug/~1.5/rug/struct.Complex.html
[com-ar-1-5]: https://docs.rs/rug/~1.5/rug/struct.Complex.html#method.abs_round
[flo-1-5]: https://docs.rs/rug/~1.5/rug/struct.Float.html
[flo-ie-1-5]: https://docs.rs/rug/~1.5/rug/struct.Float.html#method.i_exp
[flo-ue-1-5]: https://docs.rs/rug/~1.5/rug/struct.Float.html#method.u_exp
[fr-1-5]: https://docs.rs/rug/~1.5/rug/struct.Integer.html#method.from_raw
[int-1-5]: https://docs.rs/rug/~1.5/rug/struct.Integer.html
[int-adu-1-5]: https://docs.rs/rug/~1.5/rug/struct.Integer.html#method.assign_digits_unaligned
[int-wdu-1-5]: https://docs.rs/rug/~1.5/rug/struct.Integer.html#method.write_digits_unaligned
[pow-1-5]: https://docs.rs/rug/~1.5/rug/ops/trait.Pow.html
[rat-1-5]: https://docs.rs/rug/~1.5/rug/struct.Rational.html

Version 1.4.0 (2019-04-24)
==========================

  * The crate now requires rustc version 1.31.0 or later.
  * The method
    <code>[RandState][ras-1-4]::[as\_raw][ras-ar-1-4]</code> was fixed
    to take `&self` instead of `&mut self`.
  * <code>[float][flom-1-0]::[prec\_min][flom-pmin-1-4]</code> and
    <code>[float][flom-1-0]::[prec\_max][flom-pmax-1-4]</code> are now
    const functions.
  * New methods <code>[Float][flo-1-4]::[copysign][flo-cs-1-4]</code>,
    <code>[Float][flo-1-4]::[copysign\_mut][flo-csm-1-4]</code> and
    <code>[Float][flo-1-4]::[copysign\_ref][flo-csr-1-4]</code> were
    added.

[flo-1-4]: https://docs.rs/rug/~1.4/rug/struct.Float.html
[flo-cs-1-4]: https://docs.rs/rug/~1.4/rug/struct.Float.html#method.copysign
[flo-csm-1-4]: https://docs.rs/rug/~1.4/rug/struct.Float.html#method.copysign_mut
[flo-csr-1-4]: https://docs.rs/rug/~1.4/rug/struct.Float.html#method.copysign_ref
[flom-1-4]: https://docs.rs/rug/~1.4/rug/float/index.html
[flom-pmax-1-4]: https://docs.rs/rug/~1.4/rug/float/fn.prec_max.html
[flom-pmin-1-4]: https://docs.rs/rug/~1.4/rug/float/fn.prec_min.html
[ras-1-4]: https://docs.rs/rug/~1.4/rug/rand/struct.RandState.html
[ras-ar-1-4]: https://docs.rs/rug/~1.4/rug/rand/struct.RandState.html#method.as_raw

Version 1.3.0 (2019-01-26)
==========================

  * A new method
    <code>[SmallRational][smr-1-3]::[assign\_canonical][smr-ac-1-3]</code>
    was added.

[smr-1-3]: https://docs.rs/rug/~1.3/rug/rational/struct.SmallRational.html
[smr-ac-1-3]: https://docs.rs/rug/~1.3/rug/rational/struct.SmallRational.html#method.assign_canonical

Version 1.2.3 (2019-01-21)
==========================

  * Fixed bug in
    <code>[Integer][int-1-2]::[assign\_digits][int-ad-1-2]</code>.
    (Thanks: Eric Scrivner)

Version 1.2.2 (2018-10-18)
==========================

  * The [`NotAssign`][noa-1-2], [`BitAndFrom`][baf-1-2],
    [`BitOrFrom`][bof-1-2] and [`BitXorFrom`][bxf-1-2] traits were
    implemented for [`bool`].
  * The [`NegAssign`][nea-1-2] trait was implemented for [`f32`] and
    [`f64`].

Version 1.2.1 (2018-08-16)
==========================

  * The [`Integer`][int-1-2] methods [`from_digits`][int-fd-1-2],
    [`assign_digits`][int-ad-1-2], [`significant_digits`][int-sd-1-2],
    [`to_digits`][int-td-1-2] and [`write_digits`][int-wd-1-2] now
    support [`bool`] [slices][slice].

Version 1.2.0 (2018-06-30)
==========================

  * The implementations of [`Sum`] and [`Product`] for
    [`Integer`][int-1-2] and [`Rational`][rat-1-2] were generalized to
    accept more types of elements.
  * New methods
    <code>[Integer][int-1-2]::[keep\_signed\_bits][int-ksb-1-2]</code>,
    <code>[Integer][int-1-2]::[keep\_signed\_bits\_mut][int-ksbm-1-2]</code>
    and
    <code>[Integer][int-1-2]::[keep\_signed\_bits\_ref][int-ksbr-1-2]</code>
    were added.
  * New methods <code>[Integer][int-1-2]::[sum][int-s-1-2]</code>,
    <code>[Integer][int-1-2]::[dot][int-d-1-2]</code> and
    <code>[Integer][int-1-2]::[product][int-p-1-2]</code> were added
  * New methods <code>[Rational][rat-1-2]::[sum][rat-s-1-2]</code>,
    <code>[Rational][rat-1-2]::[dot][rat-d-1-2]</code> and
    <code>[Rational][rat-1-2]::[product][rat-p-1-2]</code> were added.
  * New methods <code>[Float][flo-1-2]::[dot][flo-d-1-2]</code> and
    <code>[Complex][com-1-2]::[dot][com-d-1-2]</code> were added.

[baf-1-2]: https://docs.rs/rug/~1.2/rug/ops/trait.BitAndFrom.html
[bof-1-2]: https://docs.rs/rug/~1.2/rug/ops/trait.BitOrFrom.html
[bxf-1-2]: https://docs.rs/rug/~1.2/rug/ops/trait.BitXorFrom.html
[com-1-2]: https://docs.rs/rug/~1.2/rug/struct.Complex.html
[com-d-1-2]: https://docs.rs/rug/~1.2/rug/struct.Complex.html#method.dot
[flo-1-2]: https://docs.rs/rug/~1.2/rug/struct.Float.html
[flo-d-1-2]: https://docs.rs/rug/~1.2/rug/struct.Float.html#method.dot
[int-1-2]: https://docs.rs/rug/~1.2/rug/struct.Integer.html
[int-ad-1-2]: https://docs.rs/rug/~1.2/rug/struct.Integer.html#method.assign_digits
[int-d-1-2]: https://docs.rs/rug/~1.2/rug/struct.Integer.html#method.dot
[int-fd-1-2]: https://docs.rs/rug/~1.2/rug/struct.Integer.html#method.from_digits
[int-ksb-1-2]: https://docs.rs/rug/~1.2/rug/struct.Integer.html#method.keep_signed_bits
[int-ksbm-1-2]: https://docs.rs/rug/~1.2/rug/struct.Integer.html#method.keep_signed_bits_mut
[int-ksbr-1-2]: https://docs.rs/rug/~1.2/rug/struct.Integer.html#method.keep_signed_bits_ref
[int-p-1-2]: https://docs.rs/rug/~1.2/rug/struct.Integer.html#method.product
[int-s-1-2]: https://docs.rs/rug/~1.2/rug/struct.Integer.html#method.sum
[int-sd-1-2]: https://docs.rs/rug/~1.2/rug/struct.Integer.html#method.significant_digits
[int-td-1-2]: https://docs.rs/rug/~1.2/rug/struct.Integer.html#method.to_digits
[int-wd-1-2]: https://docs.rs/rug/~1.2/rug/struct.Integer.html#method.write_digits
[nea-1-2]: https://docs.rs/rug/~1.2/rug/ops/trait.NegAssign.html
[noa-1-2]: https://docs.rs/rug/~1.2/rug/ops/trait.NotAssign.html
[rat-1-2]: https://docs.rs/rug/~1.2/rug/struct.Rational.html
[rat-d-1-2]: https://docs.rs/rug/~1.2/rug/struct.Rational.html#method.dot
[rat-p-1-2]: https://docs.rs/rug/~1.2/rug/struct.Rational.html#method.product
[rat-s-1-2]: https://docs.rs/rug/~1.2/rug/struct.Rational.html#method.sum

Version 1.1.1 (2018-05-20)
==========================

  * Support for unstable [`i128`], [`u128`] and [`TryFrom`] was added
    in nightly.

Version 1.1.0 (2018-04-23)
==========================

  * Support for [`i128`] and [`u128`] conversions and comparisons was
    added, conditional on compiler support.
  * Conditional on compiler support, [`TryFrom`] conversions were
    implemented for conversions
      * from [`Integer`][int-1-1] values to integer primitives,
      * from floating-point primitives to [`Rational`][rat-1-1] numbers, and
      * from [`Float`][flo-1-1] values to [`Rational`][rat-1-1] numbers.
  * A new method
    <code>[Float][flo-1-1]::[get\_significand][flo-gs-1-1]</code> was
    added.
  * New methods
    <code>[Float][flo-1-1]::[u\_pow\_u][flo-upu-1-1]</code> and
    <code>[Float][flo-1-1]::[i\_pow\_u][flo-ipu-1-1]</code> were
    added.
  * New methods
    <code>[Integer][int-1-1]::[from\_digits][int-fd-1-1]</code>,
    <code>[Integer][int-1-1]::[to\_digits][int-td-1-1]</code>,
    <code>[Integer][int-1-1]::[assign\_digits][int-ad-1-1]</code>,
    <code>[Integer][int-1-1]::[write\_digits][int-wd-1-1]</code> and
    <code>[Integer][int-1-1]::[significant\_digits][int-sd-1-1]</code>
    were added, providing reading from and writing to slices of
    unsigned integer primitives.

[flo-1-1]: https://docs.rs/rug/~1.1/rug/struct.Float.html
[flo-gs-1-1]: https://docs.rs/rug/~1.1/rug/struct.Float.html#method.get_significand
[flo-ipu-1-1]: https://docs.rs/rug/~1.1/rug/struct.Float.html#method.i_pow_u
[flo-upu-1-1]: https://docs.rs/rug/~1.1/rug/struct.Float.html#method.u_pow_u
[int-1-1]: https://docs.rs/rug/~1.1/rug/struct.Integer.html
[int-ad-1-1]: https://docs.rs/rug/~1.1/rug/struct.Integer.html#method.assign_digits
[int-fd-1-1]: https://docs.rs/rug/~1.1/rug/struct.Integer.html#method.from_digits
[int-sd-1-1]: https://docs.rs/rug/~1.1/rug/struct.Integer.html#method.significant_digits
[int-td-1-1]: https://docs.rs/rug/~1.1/rug/struct.Integer.html#method.to_digits
[int-wd-1-1]: https://docs.rs/rug/~1.1/rug/struct.Integer.html#method.write_digits
[rat-1-1]: https://docs.rs/rug/~1.1/rug/struct.Rational.html

Version 1.0.2 (2018-04-09)
==========================

  * A bug in
    <code>[Integer][int-1-0]::[reserve][int-r-1-0]</code>,
    which was shrinking the capacity in some cases, was fixed.
  * The [gmp-mpfr-sys] dependency in [*Cargo.toml*] was fixed to use
    tilde instead of caret, since Rug uses internal implementation
    details.

Version 1.0.1 (2018-03-10)
==========================

  * A new method
    <code>[Integer][int-1-0]::[is\_power\_of\_two][int-ipot-1-0]</code>
    was added.
  * A new method
    <code>[Integer][int-1-0]::[signed\_bits][int-sb-1-0]</code> was
    added.
  * New methods
    <code>[Integer][int-1-0]::[secure\_pow\_mod][int-spm-1-0]</code>,
    <code>[Integer][int-1-0]::[secure\_pow\_mod\_mut][int-spmm-1-0]</code>
    and
    <code>[Integer][int-1-0]::[secure\_pow\_mod\_ref][int-spmr-1-0]</code>
    were added.
  * New methods
    <code>[Integer][int-1-0]::[div\_rem\_round][int-drr-1-0]</code>,
    <code>[Integer][int-1-0]::[div\_rem\_round\_mut][int-drrm-1-0]</code>
    and
    <code>[Integer][int-1-0]::[div\_rem\_round\_ref][int-drrr-1-0]</code>
    were added.
  * A new method <code>[Complex][com-1-0]::[eq0][com-e-1-0]</code> was
    added.
  * Documentation was improved.

Version 1.0.0 (2018-03-03)
==========================

  * The methods
    <code>[Integer][int-1-0]::[invert\_mut][int-im-1-0]</code> and
    <code>[Integer][int-1-0]::[pow\_mod\_mut][int-pmm-1-0]</code> were
    changed to return <code>[Result][`Result`]&lt;(), ()&gt;</code>
    instead of [`bool`].
  * The <code>[float][flom-1-0]::[Round][rou-1-0]</code>,
    <code>[float][flom-1-0]::[Constant][con-1-0]</code> and
    <code>[float][flom-1-0]::[Special][spe-1-0]</code> enums are now
    marked as non-exhaustive.
  * All deprecated items were removed.
  * Unsound blanket implementations constrained on
    <code>T where [SmallInteger][smi-1-0]: [Assign][ass-1-0]&lt;T&gt;</code>
	inside [`SmallRational`][smr-1-0] and on
    <code>T where [SmallFloat][smf-1-0]: [Assign][ass-1-0]&lt;T&gt;</code>
	inside [`SmallComplex`][smc-1-0] were removed.

[ass-1-0]: https://docs.rs/rug/~1.0/rug/trait.Assign.html
[com-1-0]: https://docs.rs/rug/~1.0/rug/struct.Complex.html
[com-e-1-0]: https://docs.rs/rug/~1.0/rug/struct.Complex.html#method.eq0
[con-1-0]: https://docs.rs/rug/~1.0/rug/float/enum.Constant.html
[flom-1-0]: https://docs.rs/rug/~1.0/rug/float/index.html
[int-1-0]: https://docs.rs/rug/~1.0/rug/struct.Integer.html
[int-drr-1-0]: https://docs.rs/rug/~1.0/rug/struct.Integer.html#method.div_rem_round
[int-drrm-1-0]: https://docs.rs/rug/~1.0/rug/struct.Integer.html#method.div_rem_round_mut
[int-drrr-1-0]: https://docs.rs/rug/~1.0/rug/struct.Integer.html#method.div_rem_round_ref
[int-im-1-0]: https://docs.rs/rug/~1.0/rug/struct.Integer.html#method.invert_mut
[int-ipot-1-0]: https://docs.rs/rug/~1.0/rug/struct.Integer.html#method.is_power_of_two
[int-pmm-1-0]: https://docs.rs/rug/~1.0/rug/struct.Integer.html#method.pow_mod_mut
[int-r-1-0]: https://docs.rs/rug/~1.0/rug/struct.Integer.html#method.reserve
[int-sb-1-0]: https://docs.rs/rug/~1.0/rug/struct.Integer.html#method.signed_bits
[int-spm-1-0]: https://docs.rs/rug/~1.0/rug/struct.Integer.html#method.secure_pow_mod
[int-spmm-1-0]: https://docs.rs/rug/~1.0/rug/struct.Integer.html#method.secure_pow_mod_mut
[int-spmr-1-0]: https://docs.rs/rug/~1.0/rug/struct.Integer.html#method.secure_pow_mod_ref
[rou-1-0]: https://docs.rs/rug/~1.0/rug/float/enum.Round.html
[smc-1-0]: https://docs.rs/rug/~1.0/rug/complex/struct.SmallComplex.html
[smf-1-0]: https://docs.rs/rug/~1.0/rug/float/struct.SmallFloat.html
[smi-1-0]: https://docs.rs/rug/~1.0/rug/integer/struct.SmallInteger.html
[smr-1-0]: https://docs.rs/rug/~1.0/rug/rational/struct.SmallRational.html
[spe-1-0]: https://docs.rs/rug/~1.0/rug/float/enum.Special.html

Version 0.10.0 (2018-02-17)
===========================

  * `Integer::invert_ref` and `Integer::pow_mod_ref` now return an
    `Option`, not an object that is assignable to `Result`.
  * `Float::random_bits` and `Complex::random_bits` are now assignable
    to the number values, not to `Result` objects.
  * `Rational::signum`, `Rational::trunc`, `Rational::ceil`,
    `Rational::floor` and `Rational::round` now return `Rational`.
  * `Complex::abs`, `Complex::arg` and `Complex::norm` now return
    `Complex`.
  * Remove `Default` implementations from all types of `Float` and
    `Complex`; now the precision always has to be specified.
  * Remove `Sum` and `Product` implementations for `Float` and
    `Complex`.
  * Remove `Clone` and `Copy` implementations from all incomplete
    computation types.
  * Revamp top-level crate documentation.
  * Add `Integer::parse` and `Rational::parse`, and deprecate
    `ValidInteger`, `ValidRational`, `valid_str_radix` methods, and
    `assign_str*` methods.
  * Add `Float::parse` and `Complex::parse`, and deprecate
    `ValidFloat`, `ValidComplex`, `from_str*` methods,
    `valid_str_radix` methods, and `assign_str*` methods.
  * Rename `Integer::gcd_coeffs*` methods to
    `Integer::gcd_cofactors*`.
  * `Integer::gcd_cofactors_ref` now supports computing only one
    cofactor.
  * Deprecate `Rational::to_integer` and `Rational::as_numer_denom`.
  * Deprecate `Rational::as_mut_numer_denom` and replace with
    `Rational::mutate_numer_denom`.
  * Deprecate `Complex::as_real_imag`.

Version 0.9.3 (2018-02-09)
==========================

  * Add `Integer::square` and `Rational::square` methods.
  * Add `Rational::cmp_abs` method.
  * Add `Float::sum` and `Complex::sum` methods.
  * Add `from_raw`, `into_raw`, `as_raw` and `as_raw_mut` to
    `RandState`.
  * Add `RandGen::boxed_clone` and `RandState::new_custom_boxed`, and
    thus support for cloning custom random generators.
  * Fix `Float::PartialOrd<f32>` (and `<f64>`) to return `None` when
    the primitive is NaN.

Version 0.9.2 (2018-01-12)
==========================

  * Require rustc version 1.18.0.
  * Require gmp-mpfr-sys version 1.1.0.
  * Deprecate most `assign_*` methods, and replace with static methods
    that return an assignable object.
  * Deprecate `Rational::copy_to_integer` method.
  * Add `Rational::assign_canonical` and `Rational::from_canonical`
    methods.
  * Add `Float::ln_u` method.
  * Add `Float::round_even` methods.
  * Add `Float::gamma_inc` methods.
  * Add `Float::random_normal` and `Float::random_exp` methods.
  * Deprecate `Float::assign_random_gaussian` methods.
  * Add `Complex::cmp_abs` method.
  * Add `Complex::root_of_unity` method.
  * Deprecate `SmallRational::from_canonicalized_*` methods and
    replace with `SmallRational::from_canonical` method.
  * Deprecate `SmallRational::assign_canonicalized_*` methods.
  * Add `as_nonreallocating_*` methods to `SmallInteger`,
    `SmallRational`, `SmallFloat` and `SmallComplex`.
  * Fix `SmallFloat::new` and `SmallComplex::new` to produce numbers
    with a precision of 53.
  * Deprecate and hide `float::Round::AwayFromZero`.
  * Add `Integer::signum`, `Rational::signum` and `Float::signum`
    methods.
  * Add missing conversion to/from and comparisons to primitive types.
  * Add `from_raw`, `into_raw`, `as_raw` and `as_raw_mut` to
    `Integer`, `Rational`, `Float` and `Complex`.
  * Add `Float::classify` method.
  * Add `Float::mul_add`, `Float::mul_sub`, `Float::mul_add_mul` and
    `Float::mul_sub_mul` methods.
  * Add `Complex::mul_add` and `Complex::mul_sub` methods.

Version 0.9.1 (2017-11-27)
==========================

  * Implement mathematical operations where operands include
    references to primitives.
  * Remove undefined behaviour: replace
    `mem::swap(&mut src, &mut uninitialized)` with
    `ptr::copy_nonoverlapping(&src, &mut uninitialized, 1)`.

Version 0.9.0 (2017-11-16)
==========================

  * Move `rug::float::AssignRound` to `rug::ops::AssignRound`.
  * `OrdFloat` now orders +NaN above +∞, while −NaN is still below −∞.
  * Change `Float::subnormalize` methods to require explicit minimum
    normal exponent.
  * Add `Float::subnormalize_ieee` methods to deduce exponent range
    from precision, like old `Float::subnormalize`. The new method
    also supports all IEEE 754-2008 precisions corresponding to k
    storage bits where k ≥ 128 and k is a multiple of 32.
  * Deprecate `Rational::fract` methods and replace with
    `Rational::rem_trunc` methods.
  * Add `Rational::rem_ceil` and `Rational::rem_floor` methods.
  * Add `Rational::rem_round` and `Rational::fract_round` methods.
  * Add `Float::next_toward`, `Float::next_up` and `Float::next_down`.
  * Add optional serde support.

Version 0.8.0 (2017-10-26)
==========================

  * Rename `Integer::sign`, `Rational::sign` and `Float::sign` methods
    as `Integer::cmp0`, `Rational::cmp0` and `Float::cmp0`.
  * Rename `Float::pos_diff` as `Float::positive_diff`.
  * Move `rug::AssignRound` to `rug::float::AssignRound`.
  * Add `Integer::clamp`, `Rational::clamp` and `Float::clamp`
    methods.
  * Add `Integer::div_rem_ceil`, `Integer::div_rem_floor` and
    `Integer::div_rem_euc` methods.
  * Add `DivRounding`, `DivRoundingAssign` and `DivRoundingFrom`
    traits, and their `Rem` counterparts, and implement them for
    `Integer`, and for combinations of `Integer` with `i32` or `u32`.
  * Add `Rational::fract_floor` and `Rational::fract_ceil` methods.

Version 0.7.0 (2017-09-30)
==========================

  * Fix swapped `Float::sin_cos_mut` and `Float::sin_cos_round`,
    `Float::sinh_cosh_mut` and `Float::sinh_cosh_round`, and
    `Float::trunc_fract_mut` and `Float::trunc_fract_round`.
  * Fix `Float::to_f32_round`.
  * Now `Float::subnormalize` only works for precisions defined in
    IEEE 754.
  * Add `Integer::gcd_coeffs` methods.

Version 0.6.0 (2017-08-09)
==========================

  * Requires rustc version 1.17.0.
  * Rename `Float::abs_diff` as `Float::pos_diff`.
  * Replace `Float::get_sign` with `Float::is_sign_positive` and
    `Float::is_sign_negative`.
  * Add various `as_neg`, `as_abs` and `as_conj` methods.
  * Add `OrdFloat` and `OrdComplex` for complete ordering.

[*Cargo.toml*]: https://doc.rust-lang.org/cargo/guide/dependencies.html
[*az* crate]: https://crates.io/crates/az
[`AsMut`]: https://doc.rust-lang.org/nightly/core/convert/trait.AsMut.html
[`AsRef`]: https://doc.rust-lang.org/nightly/core/convert/trait.AsRef.html
[`Default`]: https://doc.rust-lang.org/nightly/core/default/trait.Default.html
[`LowerExp`]: https://doc.rust-lang.org/nightly/core/fmt/trait.LowerExp.html
[`MaybeUninit`]: https://doc.rust-lang.org/nightly/core/mem/union.MaybeUninit.html
[`Option`]: https://doc.rust-lang.org/nightly/core/option/enum.Option.html
[`Product`]: https://doc.rust-lang.org/nightly/core/iter/trait.Product.html
[`RemAssign`]: https://doc.rust-lang.org/nightly/core/ops/trait.RemAssign.html
[`Rem`]: https://doc.rust-lang.org/nightly/core/ops/trait.Rem.html
[`Result`]: https://doc.rust-lang.org/nightly/core/result/enum.Result.html
[`Send`]: https://doc.rust-lang.org/nightly/core/marker/trait.Send.html
[`Sum`]: https://doc.rust-lang.org/nightly/core/iter/trait.Sum.html
[`Sync`]: https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html
[`TryFrom`]: https://doc.rust-lang.org/nightly/std/convert/trait.TryFrom.html
[`UpperExp`]: https://doc.rust-lang.org/nightly/core/fmt/trait.UpperExp.html
[`bool`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
[`deref`]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html#tymethod.deref
[`f32`]: https://doc.rust-lang.org/nightly/std/primitive.f32.html
[`f64`]: https://doc.rust-lang.org/nightly/std/primitive.f64.html
[`i128`]: https://doc.rust-lang.org/nightly/std/primitive.i128.html
[`i16`]: https://doc.rust-lang.org/nightly/std/primitive.i16.html
[`i32`]: https://doc.rust-lang.org/nightly/std/primitive.i32.html
[`i64`]: https://doc.rust-lang.org/nightly/std/primitive.i64.html
[`i8`]: https://doc.rust-lang.org/nightly/std/primitive.i8.html
[`mem`]: https://doc.rust-lang.org/nightly/core/mem/index.html
[`u128`]: https://doc.rust-lang.org/nightly/std/primitive.u128.html
[`u16`]: https://doc.rust-lang.org/nightly/std/primitive.u16.html
[`u32`]: https://doc.rust-lang.org/nightly/std/primitive.u32.html
[`u64`]: https://doc.rust-lang.org/nightly/std/primitive.u64.html
[`u8`]: https://doc.rust-lang.org/nightly/std/primitive.u8.html
[`uninitialized`]: https://doc.rust-lang.org/nightly/core/mem/fn.uninitialized.html
[gmp-mpfr-sys]: https://crates.io/crates/gmp-mpfr-sys
[slice]: https://doc.rust-lang.org/nightly/std/primitive.slice.html
