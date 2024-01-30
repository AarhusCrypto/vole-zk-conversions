use crate::homcom::{FComProver, FComVerifier, MacProver, MacVerifier};
use eyre::Result;
use generic_array::{typenum::Unsigned, GenericArray};
use rand::{CryptoRng, Rng};
use scuttlebutt::field::{polynomial::GeneralPolynomial, Degree, FiniteField};
use scuttlebutt::ring::FiniteRing;
use scuttlebutt::AbstractChannel;
use smallvec::smallvec;

#[derive(Clone, Debug, PartialEq)]
pub struct HDMacProver<F: FiniteField, const D: usize> {
    pub poly: GeneralPolynomial<F, D>,
    pub qs_degree: usize,
}

impl<F: FiniteField, const D: usize> HDMacProver<F, D> {
    pub fn value(&self) -> F {
        if self.qs_degree > self.poly.degree() {
            F::ZERO
        } else {
            self.poly[self.qs_degree]
        }
    }

    pub fn degree(&self) -> usize {
        debug_assert!(self.qs_degree > 0);
        debug_assert!(self.qs_degree >= self.poly.degree());
        self.qs_degree
    }

    pub fn new_constant(x: F) -> Self {
        Self {
            poly: GeneralPolynomial {
                constant: F::ZERO,
                coefficients: smallvec![x],
            },
            qs_degree: 1,
        }
    }

    fn add_sub_assign_impl<const ADD: bool>(&mut self, other: &Self) {
        if other.qs_degree > self.qs_degree {
            self.poly.shift_mut(other.qs_degree - self.qs_degree);
            self.qs_degree = other.qs_degree;
        }
        debug_assert!(other.qs_degree <= self.qs_degree);
        self.poly.coefficients.resize(self.qs_degree, F::ZERO);
        let offset = self.qs_degree - other.qs_degree;
        for i in 0..=other.poly.degree() {
            if ADD {
                self.poly[offset + i] += other.poly[i];
            } else {
                self.poly[offset + i] -= other.poly[i];
            }
        }
    }

    pub fn add_assign(&mut self, other: &Self) {
        self.add_sub_assign_impl::<true>(other)
    }

    pub fn sub_assign(&mut self, other: &Self) {
        self.add_sub_assign_impl::<false>(other)
    }

    pub fn add_assign_constant(&mut self, other: F) {
        self.poly.coefficients.resize(self.qs_degree, F::ZERO);
        self.poly[self.qs_degree] += other;
    }

    pub fn sub_assign_constant(&mut self, other: F) {
        self.poly.coefficients.resize(self.qs_degree, F::ZERO);
        self.poly[self.qs_degree] -= other;
    }

    pub fn mul_assign(&mut self, other: &Self) {
        self.poly *= &other.poly;
        self.qs_degree += other.qs_degree;
    }

    pub fn mul_assign_constant(&mut self, other: F) {
        self.poly *= other;
    }

    pub fn xor_assign(&mut self, other: &Self) {
        let mut t = self.clone();
        t.mul_assign(other);
        t.mul_assign_constant(-F::ONE + -F::ONE);
        self.add_assign(other);
        self.add_assign(&t);
    }
}

impl<F: FiniteField, const D: usize> Default for HDMacProver<F, D> {
    fn default() -> Self {
        Self {
            poly: GeneralPolynomial::zero(),
            qs_degree: 1,
        }
    }
}

impl<F: FiniteField, const D: usize> From<MacProver<F>> for HDMacProver<F, D> {
    fn from(mp: MacProver<F>) -> Self {
        Self {
            poly: GeneralPolynomial {
                constant: -mp.mac(),
                coefficients: smallvec![mp.value().into()],
            },
            qs_degree: 1,
        }
    }
}

impl<F: FiniteField, const D: usize> From<HDMacProver<F, D>> for GeneralPolynomial<F, D> {
    fn from(val: HDMacProver<F, D>) -> Self {
        val.poly
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct HDMacVerifier<F: FiniteField> {
    pub mac: F,
    pub qs_degree: usize,
}

impl<F: FiniteField> HDMacVerifier<F> {
    pub fn degree(&self) -> usize {
        assert!(self.qs_degree > 0);
        self.qs_degree
    }

    pub fn new_constant(delta: F, x: F) -> Self {
        Self {
            mac: delta * x,
            qs_degree: 1,
        }
    }

    fn add_sub_assign_impl<const ADD: bool>(&mut self, delta: F, other: &Self) {
        if other.qs_degree >= self.qs_degree {
            for _ in 0..other.qs_degree - self.qs_degree {
                self.mac *= delta;
            }
            if ADD {
                self.mac += other.mac;
            } else {
                self.mac -= other.mac;
            }
            self.qs_degree = other.qs_degree;
        } else {
            let mut tmp = other.mac;
            for _ in 0..self.qs_degree - other.qs_degree {
                tmp *= delta;
            }
            if ADD {
                self.mac += tmp;
            } else {
                self.mac -= tmp;
            }
        }
    }

    pub fn add_assign(&mut self, delta: F, other: &Self) {
        self.add_sub_assign_impl::<true>(delta, other)
    }

    pub fn sub_assign(&mut self, delta: F, other: &Self) {
        self.add_sub_assign_impl::<false>(delta, other)
    }

    pub fn add_assign_constant(&mut self, delta: F, mut other: F) {
        (0..self.qs_degree).for_each(|_| other *= delta);
        self.mac += other;
    }

    pub fn sub_assign_constant(&mut self, delta: F, mut other: F) {
        (0..self.qs_degree).for_each(|_| other *= delta);
        self.mac -= other;
    }

    pub fn mul_assign(&mut self, other: &Self) {
        self.mac *= other.mac;
        self.qs_degree += other.qs_degree;
    }

    pub fn mul_assign_constant(&mut self, other: F) {
        self.mac *= other;
    }

    pub fn xor_assign(&mut self, delta: F, other: &Self) {
        let mut t = self.clone();
        t.mul_assign(other);
        t.mul_assign_constant(-F::ONE + -F::ONE);
        self.add_assign(delta, other);
        self.add_assign(delta, &t);
    }
}

impl<F: FiniteField> Default for HDMacVerifier<F> {
    fn default() -> Self {
        Self {
            mac: F::ZERO,
            qs_degree: 1,
        }
    }
}

impl<F: FiniteField> From<MacVerifier<F>> for HDMacVerifier<F> {
    fn from(mv: MacVerifier<F>) -> Self {
        Self {
            mac: -mv.mac(),
            qs_degree: 1,
        }
    }
}

pub struct QSStateProver<F: FiniteField, const D: usize> {
    chi: F,
    state: HDMacProver<F, D>,
    count: usize,
}

impl<F: FiniteField, const D: usize> QSStateProver<F, D> {
    pub fn init_with_chi(chi: F) -> Self {
        QSStateProver::<F, D> {
            chi,
            state: Default::default(),
            count: 0,
        }
    }

    pub fn check_zero(&mut self, mp: &HDMacProver<F, D>) {
        assert_eq!(mp.value(), F::ZERO, "value is non-zero");
        self.state.add_assign(mp);
        self.state.mul_assign_constant(self.chi);
        self.count += 1;
    }

    pub fn check_mult(
        &mut self,
        mp_a: &HDMacProver<F, D>,
        mp_b: &HDMacProver<F, D>,
        mp_c: &HDMacProver<F, D>,
    ) {
        assert_eq!(
            mp_a.value() * mp_b.value(),
            mp_c.value(),
            "multiplication triple incorrect"
        );
        let mut mp = mp_a.clone();
        mp.mul_assign(mp_b);
        mp.sub_assign(mp_c);
        self.check_zero(&mp);
    }

    pub fn finalize_with_mask(&mut self, mask: GeneralPolynomial<F, D>) -> GeneralPolynomial<F, D> {
        assert!(
            self.state.poly.degree() < self.state.qs_degree,
            "QS state should have a zero in the most significant coefficient"
        );
        assert!(mask.degree() < self.state.qs_degree);
        let mut proof = mask;
        proof += &self.state.poly;
        self.reset();
        proof
    }

    pub fn finalize<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        fcom: &mut FComProver<F>,
    ) -> Result<()> {
        let qs_degree = self.state.qs_degree;
        assert_ne!(qs_degree, 0);

        let mut mask: GeneralPolynomial<F, { D }> = GeneralPolynomial {
            constant: F::ZERO,
            coefficients: smallvec![F::ZERO; qs_degree - 1],
        };

        fn make_x_i<FE: FiniteField>(i: usize) -> FE {
            let mut v: GenericArray<FE::PrimeField, Degree<FE>> = GenericArray::default();
            v[i] = FE::PrimeField::ONE;
            FE::from_subfield(&v)
        }

        for j in (0..qs_degree - 1).rev() {
            for i in 0..Degree::<F>::USIZE {
                let u = fcom.random(channel, rng)?;
                let x_i: F = make_x_i(i);
                mask[j + 1] += u.value() * x_i;
                mask[j] -= u.mac() * x_i;
            }
        }

        let proof = self.finalize_with_mask(mask); // this resets self
        for j in 0..qs_degree {
            channel.write_serializable(&proof[j])?;
        }
        channel.flush()?;
        Ok(())
    }

    pub fn reset(&mut self) {
        self.state = Default::default();
        self.count = 0;
    }
}

impl<F: FiniteField, const D: usize> QSStateProver<F, D>
where
    <F as FiniteField>::PrimeField: TryInto<u128>,
    <<F as FiniteField>::PrimeField as TryInto<u128>>::Error: std::fmt::Debug,
{
    pub fn check_pow2_range(&mut self, bits: u32, mp: &HDMacProver<F, D>) {
        assert!(bits > 0);
        {
            let mp_as_prime_field_poly = mp.value().decompose();
            debug_assert!(mp_as_prime_field_poly
                .iter()
                .skip(1)
                .all(|x: &F::PrimeField| *x == F::PrimeField::ZERO));
            let mp_val_as_int: u128 = mp_as_prime_field_poly[0].try_into().expect("TODO");
            debug_assert!(mp_val_as_int < (1 << bits));
        }
        let mut acc = mp.clone();
        let mut cst = F::ZERO;
        for _ in 1..(1 << bits) {
            cst += F::ONE;
            let mut t = mp.clone();
            t.sub_assign_constant(cst);
            acc.mul_assign(&t);
        }
        assert_eq!(acc.qs_degree, 1 << bits);
        self.check_zero(&acc);
    }
}

impl<F: FiniteField, const D: usize> Drop for QSStateProver<F, D> {
    fn drop(&mut self) {
        if self.count != 0 {
            // panic!(
            eprintln!(
                "================================================================================="
            );
            eprintln!(
                "Quicksilver prover functionality dropped before check finished, mult count {:?}",
                self.count
            );
            eprintln!(
                "---------------------------------------------------------------------------------"
            );
            eprintln!("Backtrace: {}", std::backtrace::Backtrace::capture());
            eprintln!(
                "================================================================================="
            );
        }
    }
}

pub struct QSStateVerifier<F: FiniteField> {
    delta: F,
    chi: F,
    state: HDMacVerifier<F>,
    count: usize,
}

impl<F: FiniteField> QSStateVerifier<F> {
    pub fn init_with_delta_and_chi(delta: F, chi: F) -> Self {
        QSStateVerifier::<F> {
            delta,
            chi,
            state: Default::default(),
            count: 0,
        }
    }

    pub fn check_zero(&mut self, mv: &HDMacVerifier<F>) {
        self.state.add_assign(self.delta, mv);
        self.state.mul_assign_constant(self.chi);
        self.count += 1;
    }

    pub fn check_mult(
        &mut self,
        mv_a: &HDMacVerifier<F>,
        mv_b: &HDMacVerifier<F>,
        mv_c: &HDMacVerifier<F>,
    ) {
        let mut mv = mv_a.clone();
        mv.mul_assign(mv_b);
        mv.sub_assign(self.delta, mv_c);
        self.check_zero(&mv);
    }

    pub fn check_pow2_range(&mut self, bits: u32, mv: &HDMacVerifier<F>) {
        debug_assert!(bits > 0);
        let mut acc = mv.clone();
        let mut cst = F::ZERO;
        for _ in 1..(1 << bits) {
            cst += F::ONE;
            let mut t = mv.clone();
            t.sub_assign_constant(self.delta, cst);
            acc.mul_assign(&t);
        }
        debug_assert_eq!(acc.qs_degree, 1 << bits);
        self.check_zero(&acc);
    }

    pub fn finalize_with_mask_and_verify<const D: usize>(
        &mut self,
        mask: F,
        proof: &GeneralPolynomial<F, D>,
    ) -> bool {
        let result = proof.degree() < self.state.qs_degree
            && proof.eval(self.delta) == self.state.mac + mask;
        self.reset();
        result
    }

    pub fn finalize_and_verify<C: AbstractChannel, RNG: CryptoRng + Rng, const D: usize>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        fcom: &mut FComVerifier<F>,
    ) -> Result<bool> {
        assert_ne!(self.state.qs_degree, 0);

        let mut mask = F::ZERO;

        fn make_x_i<FE: FiniteField>(i: usize) -> FE {
            let mut v: GenericArray<FE::PrimeField, Degree<FE>> = GenericArray::default();
            v[i] = FE::PrimeField::ONE;
            FE::from_subfield(&v)
        }

        for _ in (0..self.state.qs_degree - 1).rev() {
            mask *= self.delta;
            for i in 0..Degree::<F>::USIZE {
                let v = fcom.random(channel, rng)?.mac();
                let x_i: F = make_x_i(i);
                mask -= v * x_i;
            }
        }

        let mut proof: GeneralPolynomial<F, { D }> = GeneralPolynomial {
            constant: F::ZERO,
            coefficients: smallvec![F::ZERO; self.state.qs_degree - 1],
        };
        for j in 0..self.state.qs_degree {
            proof[j] = channel.read_serializable()?;
        }

        Ok(self.finalize_with_mask_and_verify(mask, &proof))
    }

    pub fn reset(&mut self) {
        self.state = Default::default();
        self.count = 0;
    }
}

impl<F: FiniteField> Drop for QSStateVerifier<F> {
    fn drop(&mut self) {
        if self.count != 0 {
            // panic!(
            eprintln!(
                "================================================================================="
            );
            eprintln!(
                "Quicksilver verifier functionality dropped before check finished, mult count {:?}",
                self.count
            );
            eprintln!(
                "---------------------------------------------------------------------------------"
            );
            eprintln!("Backtrace: {}", std::backtrace::Backtrace::capture());
            eprintln!(
                "================================================================================="
            );
        }
    }
}

pub fn qs_prover_check_pow2_range_in_chunks<
    F: FiniteField,
    const D: usize,
    C: AbstractChannel,
    RNG: CryptoRng + Rng,
>(
    channel: &mut C,
    rng: &mut RNG,
    fcom: &mut FComProver<F>,
    bits: u32,
    max_chunk_size: u32,
    mps: &[HDMacProver<F, D>],
) -> Result<QSStateProver<F, D>>
where
    <F as FiniteField>::PrimeField: TryInto<u128>,
    <<F as FiniteField>::PrimeField as TryInto<u128>>::Error: std::fmt::Debug,
    <<F as FiniteField>::PrimeField as TryFrom<u128>>::Error: std::fmt::Debug,
{
    assert!(bits > 0);
    assert!(max_chunk_size > 0);

    // if the maximum chunk size is larger than the range, we do not need to split
    if max_chunk_size >= bits {
        // initialize qs state
        let chi = channel.read_serializable()?;
        let mut qs = QSStateProver::<F, { D }>::init_with_chi(chi);
        for mp in mps {
            qs.check_pow2_range(bits, mp);
        }
        return Ok(qs);
    }

    let n = mps.len();
    let num_chunks = ((bits + max_chunk_size - 1) / max_chunk_size) as usize;
    let last_chunk_size = if bits % max_chunk_size == 0 {
        max_chunk_size
    } else {
        bits % max_chunk_size
    };

    // commit to chunks
    let mut chunks: Vec<HDMacProver<F, { D }>> = Vec::with_capacity(n * num_chunks);
    for mp in mps {
        let mp_as_prime_field_poly = mp.value().decompose();
        debug_assert!(mp_as_prime_field_poly
            .iter()
            .skip(1)
            .all(|x: &F::PrimeField| *x == F::PrimeField::ZERO));
        let mp_val_as_int: u128 = mp_as_prime_field_poly[0].try_into().expect("TODO");
        debug_assert!(mp_val_as_int < (1 << bits));
        let chunk_mask = (1u128 << max_chunk_size) - 1;
        for i in 0..num_chunks - 1 {
            let chunk_val = (mp_val_as_int >> (i as u32 * max_chunk_size)) & chunk_mask;
            debug_assert!(chunk_val < (1 << max_chunk_size));
            let chunk_val = F::PrimeField::try_from(chunk_val).expect("TODO");
            chunks.push(MacProver::new(chunk_val, fcom.input1(channel, rng, chunk_val)?).into());
        }
        {
            let chunk_val = mp_val_as_int >> ((num_chunks - 1) as u32 * max_chunk_size);
            debug_assert!(chunk_val < (1 << last_chunk_size));
            let chunk_val = F::PrimeField::try_from(chunk_val).expect("TODO");
            chunks.push(MacProver::new(chunk_val, fcom.input1(channel, rng, chunk_val)?).into());
        }
    }
    channel.flush()?;
    for i in 0..num_chunks {
        eprintln!("chunks[{}] = {:#?}", i, chunks[i]);
    }

    // initialize qs state
    let chi = channel.read_serializable()?;
    let mut qs = QSStateProver::<F, { D }>::init_with_chi(chi);
    // check chunks
    for (mp, mp_chunks) in mps.iter().zip(chunks.chunks_exact(num_chunks)) {
        let mut acc = mp.clone();
        for (i, c) in mp_chunks.iter().enumerate() {
            let mut t = c.clone();
            t.mul_assign_constant(
                F::PrimeField::try_from(1u128 << (i as u32 * max_chunk_size))
                    .expect("TODO")
                    .into(),
            );
            acc.sub_assign(&t);
        }
        qs.check_zero(&acc);
    }
    // check range of chnks
    for (i, c) in chunks.iter().enumerate() {
        if i % num_chunks == num_chunks - 1 {
            qs.check_pow2_range(last_chunk_size, &c);
        } else {
            qs.check_pow2_range(max_chunk_size, &c);
        }
    }
    Ok(qs)
}

pub fn qs_verifier_check_pow2_range_in_chunks<
    F: FiniteField,
    C: AbstractChannel,
    RNG: CryptoRng + Rng,
>(
    channel: &mut C,
    rng: &mut RNG,
    fcom: &mut FComVerifier<F>,
    bits: u32,
    max_chunk_size: u32,
    mvs: &[HDMacVerifier<F>],
) -> Result<QSStateVerifier<F>>
where
    <F as FiniteField>::PrimeField: TryInto<u128>,
    <<F as FiniteField>::PrimeField as TryInto<u128>>::Error: std::fmt::Debug,
    <<F as FiniteField>::PrimeField as TryFrom<u128>>::Error: std::fmt::Debug,
{
    assert!(bits > 0);
    assert!(max_chunk_size > 0);

    // if the maximum chunk size is larger than the range, we do not need to split
    if max_chunk_size >= bits {
        // initialize qs state
        let delta = fcom.get_delta();
        let chi = F::random(rng);
        channel.write_serializable(&chi)?;
        channel.flush()?;
        let mut qs = QSStateVerifier::<F>::init_with_delta_and_chi(delta, chi);
        for mv in mvs {
            qs.check_pow2_range(bits, mv);
        }
        return Ok(qs);
    }

    let n = mvs.len();
    let num_chunks = ((bits + max_chunk_size - 1) / max_chunk_size) as usize;
    let last_chunk_size = if bits % max_chunk_size == 0 {
        max_chunk_size
    } else {
        bits % max_chunk_size
    };

    // commit to chunks
    let mut chunks: Vec<HDMacVerifier<F>> = Vec::with_capacity(n * num_chunks);
    for _ in 0..n * num_chunks {
        chunks.push(fcom.input1(channel, rng)?.into());
    }
    channel.flush()?;

    // initialize qs state
    let delta = fcom.get_delta();
    let chi = F::random(rng);
    channel.write_serializable(&chi)?;
    channel.flush()?;
    let mut qs = QSStateVerifier::<F>::init_with_delta_and_chi(delta, chi);
    // check chunk
    for (mv, mv_chunks) in mvs.iter().zip(chunks.chunks_exact_mut(num_chunks)) {
        let mut acc = mv.clone();
        for (i, c) in mv_chunks.iter_mut().enumerate() {
            let mut t = c.clone();
            t.mul_assign_constant(
                F::PrimeField::try_from(1u128 << (i as u32 * max_chunk_size))
                    .expect("TODO")
                    .into(),
            );
            acc.sub_assign(delta, &t);
        }
        qs.check_zero(&acc);
    }
    // check range of chnks
    for (i, c) in chunks.iter().enumerate() {
        if i % num_chunks == num_chunks - 1 {
            qs.check_pow2_range(last_chunk_size, &c);
        } else {
            qs.check_pow2_range(max_chunk_size, &c);
        }
    }
    Ok(qs)
}

fn qs_range_check_prepare<F: FiniteField>(
    lower_bound: i128,
    upper_bound: i128,
) -> (u32, F::PrimeField, F::PrimeField)
where
    <F as FiniteField>::PrimeField: TryInto<u128>,
    <<F as FiniteField>::PrimeField as TryInto<u128>>::Error: std::fmt::Debug,
    <<F as FiniteField>::PrimeField as TryFrom<u128>>::Error: std::fmt::Debug,
{
    // determine p as i128
    let p = (-F::PrimeField::ONE).try_into().unwrap() as i128;
    // check bounds
    assert!(p > 0);
    assert!((-p + 1) / 2 < lower_bound);
    assert!(lower_bound < upper_bound);
    assert!(upper_bound < (p - 1) / 2);
    let m = ((upper_bound - lower_bound) as u128)
        .next_power_of_two()
        .ilog2();
    assert!(upper_bound - lower_bound < (1 << m));
    assert!((1 << m) < (p - 1) / 2);
    let a = {
        let a = F::PrimeField::try_from(lower_bound.abs() as u128).unwrap();
        if lower_bound < 0 {
            -a
        } else {
            a
        }
    };
    // let c = (lower_bound + (1 << m) - upper_bound) as u128;
    // let c = F::PrimeField::try_from(c).unwrap();
    let c = {
        let c = (1 << m) - upper_bound - 1;
        let is_neg = c < 0;
        let c = F::PrimeField::try_from(c.abs() as u128).unwrap();
        if is_neg {
            -c
        } else {
            c
        }
    };
    (m, a, c)
}

pub fn qs_prover_check_range<
    F: FiniteField,
    const D: usize,
    C: AbstractChannel,
    RNG: CryptoRng + Rng,
>(
    channel: &mut C,
    rng: &mut RNG,
    fcom: &mut FComProver<F>,
    lower_bound: i128,
    upper_bound: i128,
    max_chunk_size: u32,
    mps: &[HDMacProver<F, D>],
) -> Result<QSStateProver<F, D>>
where
    <F as FiniteField>::PrimeField: TryInto<u128>,
    <<F as FiniteField>::PrimeField as TryInto<u128>>::Error: std::fmt::Debug,
    <<F as FiniteField>::PrimeField as TryFrom<u128>>::Error: std::fmt::Debug,
{
    let (m, a, c) = qs_range_check_prepare::<F>(lower_bound, upper_bound);
    let mut new_mps = Vec::with_capacity(mps.len() * 2);
    for mp in mps {
        {
            let mp_as_prime_field_poly = mp.value().decompose();
            debug_assert!(mp_as_prime_field_poly
                .iter()
                .skip(1)
                .all(|x: &F::PrimeField| *x == F::PrimeField::ZERO));
            let mp_val_as_int: u128 = mp_as_prime_field_poly[0].try_into().expect("TODO");
            debug_assert!(lower_bound < mp_val_as_int as i128);
            debug_assert!((mp_val_as_int as i128) < upper_bound);
        }
        let mut t = mp.clone();
        // t.add_assign_constant(a.into());
        t.sub_assign_constant(a.into());
        new_mps.push(t);
        let mut t = mp.clone();
        t.add_assign_constant(c.into());
        new_mps.push(t);
    }
    qs_prover_check_pow2_range_in_chunks(channel, rng, fcom, m, max_chunk_size, &new_mps)
}

pub fn qs_verifier_check_range<F: FiniteField, C: AbstractChannel, RNG: CryptoRng + Rng>(
    channel: &mut C,
    rng: &mut RNG,
    fcom: &mut FComVerifier<F>,
    lower_bound: i128,
    upper_bound: i128,
    max_chunk_size: u32,
    mvs: &[HDMacVerifier<F>],
) -> Result<QSStateVerifier<F>>
where
    <F as FiniteField>::PrimeField: TryInto<u128>,
    <<F as FiniteField>::PrimeField as TryInto<u128>>::Error: std::fmt::Debug,
    <<F as FiniteField>::PrimeField as TryFrom<u128>>::Error: std::fmt::Debug,
{
    let (m, a, c) = qs_range_check_prepare::<F>(lower_bound, upper_bound);
    let mut new_mvs = Vec::with_capacity(mvs.len() * 2);
    let delta = fcom.get_delta();
    for mv in mvs {
        let mut t = mv.clone();
        // t.add_assign_constant(delta, a.into());
        t.sub_assign_constant(delta, a.into());
        new_mvs.push(t);
        let mut t = mv.clone();
        t.add_assign_constant(delta, c.into());
        new_mvs.push(t);
    }
    qs_verifier_check_pow2_range_in_chunks(channel, rng, fcom, m, max_chunk_size, &new_mvs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use scuttlebutt::field::F61p;
    use scuttlebutt::ring::FiniteRing;

    const D: usize = 3;

    fn auth(delta: F61p, x: F61p) -> (HDMacProver<F61p, D>, HDMacVerifier<F61p>) {
        let v = F61p::random(&mut thread_rng());
        (
            MacProver::new(x, -v).into(),
            MacVerifier::new(-(delta * x + v)).into(),
        )
    }

    #[test]
    fn test_hdmacs() {
        let delta = F61p::random(&mut thread_rng());
        let a = F61p::try_from(3).unwrap();
        let b = F61p::try_from(4).unwrap();
        let (a_p, a_v) = auth(delta, a);
        let (b_p, b_v) = (
            HDMacProver::new_constant(b),
            HDMacVerifier::new_constant(delta, b),
        );
        let (c_p, c_v) = auth(delta, a * b);
        let (d_p, d_v) = {
            let mut t_p = a_p.clone();
            let mut t_v = a_v.clone();
            t_p.mul_assign(&b_p);
            t_v.mul_assign(&b_v);
            (t_p, t_v)
        };
        let (e_p, e_v) = {
            let mut t_p = d_p.clone();
            let mut t_v = d_v.clone();
            t_p.sub_assign(&c_p);
            t_v.sub_assign(delta, &c_v);
            (t_p, t_v)
        };
        let (f_p, f_v) = {
            let mut t_p = d_p.clone();
            let mut t_v = d_v.clone();
            t_p.mul_assign(&c_p);
            t_v.mul_assign(&c_v);
            (t_p, t_v)
        };
        let (g_p, g_v) = {
            let mut t_p = f_p.clone();
            let mut t_v = f_v.clone();
            t_p.mul_assign_constant(-F61p::ONE);
            t_v.mul_assign_constant(-F61p::ONE);
            t_p.add_assign_constant(F61p::try_from(144).unwrap());
            t_v.add_assign_constant(delta, F61p::try_from(144).unwrap());
            (t_p, t_v)
        };

        assert_eq!(d_p.poly[0], a_p.poly[0] * b_p.poly[0]);
        assert_eq!(
            d_p.poly[1],
            a_p.poly[1] * b_p.poly[0] + a_p.poly[0] * b_p.poly[1]
        );
        assert_eq!(d_p.poly[2], a_p.poly[1] * b_p.poly[1]);
        assert_eq!(e_p.poly[0], d_p.poly[0]);
        assert_eq!(e_p.poly[1], d_p.poly[1] - c_p.poly[0]);
        assert_eq!(e_p.poly[2], d_p.poly[2] - c_p.poly[1]);

        assert_eq!(d_p.poly[2], a * b);
        assert_eq!(e_p.poly[2], F61p::ZERO);
        assert_eq!(f_p.poly[3], F61p::try_from(144).unwrap());
        assert_eq!(g_p.poly[3], F61p::ZERO);

        assert_eq!(a_p.qs_degree, 1);
        assert_eq!(a_v.qs_degree, 1);
        assert_eq!(b_p.qs_degree, 1);
        assert_eq!(b_v.qs_degree, 1);
        assert_eq!(c_p.qs_degree, 1);
        assert_eq!(c_v.qs_degree, 1);
        assert_eq!(d_p.qs_degree, 2);
        assert_eq!(d_v.qs_degree, 2);
        assert_eq!(e_p.qs_degree, 2);
        assert_eq!(e_v.qs_degree, 2);
        assert_eq!(f_p.qs_degree, 3);
        assert_eq!(f_v.qs_degree, 3);
        assert_eq!(g_p.qs_degree, 3);
        assert_eq!(g_v.qs_degree, 3);

        assert_eq!(a_p.poly.eval(delta), a_v.mac);
        assert_eq!(b_p.poly.eval(delta), b_v.mac);
        assert_eq!(c_p.poly.eval(delta), c_v.mac);
        assert_eq!(d_p.poly.eval(delta), d_v.mac);
        assert_eq!(e_p.poly.eval(delta), e_v.mac);
        assert_eq!(f_p.poly.eval(delta), f_v.mac);
        assert_eq!(g_p.poly.eval(delta), g_v.mac);
    }

    #[test]
    fn test_hdqs() {
        const D: usize = 3;
        let mut rng = thread_rng();
        let delta = F61p::random(&mut rng);
        let chi = F61p::random(&mut rng);
        let mut qs_prover = QSStateProver::<F61p, D>::init_with_chi(chi);
        let mut qs_verifier = QSStateVerifier::init_with_delta_and_chi(delta, chi);

        let n = 10;

        for _ in 0..n {
            let a = F61p::random(&mut rng);
            let b = F61p::random(&mut rng);
            let (mut a_p, mut a_v) = auth(delta, a);
            let (b_p, b_v) = auth(delta, b);
            let (c_p, c_v) = auth(delta, a * b);
            qs_prover.check_mult(&a_p, &b_p, &c_p);
            qs_verifier.check_mult(&a_v, &b_v, &c_v);
            a_p.mul_assign(&b_p);
            a_v.mul_assign(&b_v);
            a_p.sub_assign(&c_p);
            a_v.sub_assign(delta, &c_v);
            qs_prover.check_zero(&a_p);
            qs_verifier.check_zero(&a_v);
        }
        assert_eq!(qs_prover.count, 2 * n);
        assert_eq!(qs_verifier.count, 2 * n);
        assert_eq!(qs_prover.state.qs_degree, 2);
        assert_eq!(qs_verifier.state.qs_degree, 2);

        for _ in 0..n {
            let a = F61p::random(&mut rng);
            let b = F61p::random(&mut rng);
            let c = F61p::random(&mut rng);
            let (mut a_p, mut a_v) = auth(delta, a);
            let (b_p, b_v) = auth(delta, b);
            let (c_p, c_v) = auth(delta, c);
            let (d_p, d_v) = auth(delta, a * b * c);
            a_p.mul_assign(&b_p);
            a_v.mul_assign(&b_v);
            a_p.mul_assign(&c_p);
            a_v.mul_assign(&c_v);
            a_p.sub_assign(&d_p);
            a_v.sub_assign(delta, &d_v);
            qs_prover.check_zero(&a_p);
            qs_verifier.check_zero(&a_v);
        }
        assert_eq!(qs_prover.count, 3 * n);
        assert_eq!(qs_verifier.count, 3 * n);
        assert_eq!(qs_prover.state.qs_degree, 3);
        assert_eq!(qs_verifier.state.qs_degree, 3);

        let mask_p = GeneralPolynomial::<F61p, D>::random(&mut rng, 2);
        let mask_v = mask_p.eval(delta);
        let qs_proof = qs_prover.finalize_with_mask(mask_p);
        let verified = qs_verifier.finalize_with_mask_and_verify(mask_v, &qs_proof);
        assert!(verified);
    }

    #[test]
    fn test_hdqs_pow2_range() {
        const D: usize = 3;
        let mut rng = thread_rng();
        let delta = F61p::random(&mut rng);
        let chi = F61p::random(&mut rng);
        let mut qs_prover = QSStateProver::<F61p, D>::init_with_chi(chi);
        let mut qs_verifier = QSStateVerifier::init_with_delta_and_chi(delta, chi);

        let good = [(0, 6), (1, 6), (42, 6), (63, 6), (255, 8)];

        for (c, bits) in good.iter().copied() {
            let (c_p, c_v) = auth(delta, F61p::try_from(c).unwrap());
            qs_prover.check_pow2_range(bits, &c_p);
            qs_verifier.check_pow2_range(bits, &c_v);
        }
        assert_eq!(qs_prover.count, good.len());
        assert_eq!(qs_verifier.count, good.len());
        assert_eq!(qs_prover.state.qs_degree, 256);
        assert_eq!(qs_verifier.state.qs_degree, 256);

        let mask_p = GeneralPolynomial::<F61p, D>::random(&mut rng, 255);
        let mask_v = mask_p.eval(delta);
        let qs_proof = qs_prover.finalize_with_mask(mask_p);
        let verified = qs_verifier.finalize_with_mask_and_verify(mask_v, &qs_proof);
        assert!(verified);
    }
}
