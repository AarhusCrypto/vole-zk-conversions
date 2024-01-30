use crate::conv::{HDDabitProver, HDDabitVerifier};
use crate::hd_quicksilver::{HDMacProver, HDMacVerifier};
use crate::homcom::{MacProver, MacVerifier};
use rand::{Rng, SeedableRng};
use scuttlebutt::{
    field::{F40b, F61p, FiniteField},
    ring::FiniteRing,
    AesRng,
};

const TSPA_PARAMS_SEED_LENGTH: usize = 4096;
const TSPA_PARAMS_OUTPUT_LENGTH: usize = 19893;
const XOR4MAJ7_PARAMS_SEED_LENGTH: usize = 1024;
const XOR4MAJ7_PARAMS_OUTPUT_LENGTH: usize = 1 << 20;

pub trait PredicateT<FE: FiniteField, const LOC: usize, const D2: usize, const DP: usize> {
    const LOC: usize = LOC;
    const D2: usize = D2;
    const DP: usize = DP;

    fn expand_prover_2(
        sigma: &[usize; LOC],
        seed_2: &[MacProver<F40b>],
    ) -> HDMacProver<F40b, { D2 }>;

    fn expand_prover_p(sigma: &[usize; LOC], seed_p: &[MacProver<FE>]) -> HDMacProver<FE, { DP }>;

    fn expand_prover(
        sigma: &[usize; LOC],
        seed_2: &[MacProver<F40b>],
        seed_p: &[MacProver<FE>],
    ) -> HDDabitProver<FE, { D2 }, { DP }> {
        let out_2 = Self::expand_prover_2(sigma, seed_2);
        let out_p = Self::expand_prover_p(sigma, seed_p);

        if out_p.poly[Self::DP] == FE::ZERO {
            debug_assert_eq!(out_2.poly[Self::D2], F40b::ZERO);
        } else if out_p.poly[Self::DP] == FE::ONE {
            debug_assert_eq!(out_2.poly[Self::D2], F40b::ONE);
        } else {
            debug_assert!(false);
        };

        (out_2, out_p)
    }

    fn expand_verifier_2(
        delta_2: F40b,
        sigma: &[usize; LOC],
        seed_2: &[MacVerifier<F40b>],
    ) -> HDMacVerifier<F40b>;

    fn expand_verifier_p(
        delta_p: FE,
        sigma: &[usize; LOC],
        seed_p: &[MacVerifier<FE>],
    ) -> HDMacVerifier<FE>;

    fn expand_verifier(
        delta_2: F40b,
        delta_p: FE,
        sigma: &[usize; LOC],
        seed_2: &[MacVerifier<F40b>],
        seed_p: &[MacVerifier<FE>],
    ) -> HDDabitVerifier<FE> {
        (
            Self::expand_verifier_2(delta_2, sigma, seed_2),
            Self::expand_verifier_p(delta_p, sigma, seed_p),
        )
    }
}

pub trait PrgDimensions {
    const SEED_LENGTH: usize;
    const OUTPUT_LENGTH: usize;
}

impl PrgDimensions for TSPAPredicate {
    const SEED_LENGTH: usize = TSPA_PARAMS_SEED_LENGTH;
    const OUTPUT_LENGTH: usize = TSPA_PARAMS_OUTPUT_LENGTH;
}

impl PrgDimensions for Xor4Maj7Predicate {
    const SEED_LENGTH: usize = XOR4MAJ7_PARAMS_SEED_LENGTH;
    const OUTPUT_LENGTH: usize = XOR4MAJ7_PARAMS_OUTPUT_LENGTH;
}

// TSPA(x) := x1 ⊕ (x2 + x3 + x4x5 − x2x3 − x3x4 − x2x5)
// ≡ x1 + x2 + x3 + (x2 + x4)(x3 + x5)
pub struct TSPAPredicate {}

impl TSPAPredicate {
    pub const LOC: usize = 5;
    pub const D2: usize = 2;
    pub const DP: usize = 3;
}

impl<FE: FiniteField> PredicateT<FE, { Self::LOC }, { Self::D2 }, { Self::DP }> for TSPAPredicate {
    fn expand_prover_2(
        sigma: &[usize; Self::LOC],
        seed_2: &[MacProver<F40b>],
    ) -> HDMacProver<F40b, { Self::D2 }> {
        let x1 = HDMacProver::<F40b, { Self::D2 }>::from(seed_2[sigma[0]]);
        let x2 = HDMacProver::<F40b, { Self::D2 }>::from(seed_2[sigma[1]]);
        let x3 = HDMacProver::<F40b, { Self::D2 }>::from(seed_2[sigma[2]]);
        let x4 = HDMacProver::<F40b, { Self::D2 }>::from(seed_2[sigma[3]]);
        let x5 = HDMacProver::<F40b, { Self::D2 }>::from(seed_2[sigma[4]]);

        let mut out = x1;
        out.add_assign(&x2);
        out.add_assign(&x3); // out = x1 ^ x2 ^ x3
        let mut t = x2;
        t.add_assign(&x4); //   t = x2 ^ x4
        let mut s = x3;
        s.add_assign(&x5); //   s = x3 ^ x5
        t.mul_assign(&s); //    t = (x2 ^ x4) * (x3 ^ x5)
        out.add_assign(&t); //  out = x1 ^ x2 ^ x3 ^ (x2 ^ x4) * (x3 ^ x5)
        out
    }

    fn expand_prover_p(
        sigma: &[usize; Self::LOC],
        seed_p: &[MacProver<FE>],
    ) -> HDMacProver<FE, { Self::DP }> {
        let x1 = HDMacProver::<FE, { Self::DP }>::from(seed_p[sigma[0]]);
        let x2 = HDMacProver::<FE, { Self::DP }>::from(seed_p[sigma[1]]);
        let x3 = HDMacProver::<FE, { Self::DP }>::from(seed_p[sigma[2]]);
        let x4 = HDMacProver::<FE, { Self::DP }>::from(seed_p[sigma[3]]);
        let x5 = HDMacProver::<FE, { Self::DP }>::from(seed_p[sigma[4]]);

        let mut out = x2.clone();
        out.add_assign(&x3); //       t = x2 + x3
        let mut s23 = x2.clone();
        s23.mul_assign(&x3); //     s23 = x2 * x3
        let mut s34 = x3.clone();
        s34.mul_assign(&x4); //     s34 = x3 * x4
        let mut s25 = x2.clone();
        s25.mul_assign(&x5); //     s25 = x2 * x4
        let mut s45 = x4.clone();
        s45.mul_assign(&x5); //     s45 = x4 * x5
        out.add_assign(&s45);
        out.sub_assign(&s23);
        out.sub_assign(&s34);
        out.sub_assign(&s25); //      t = x2 + x3 + (x4 * x5) - (x2 * x3) - (x3 * x4) - (x2 * x5)

        out.xor_assign(&x1);
        out
    }

    fn expand_verifier_2(
        delta_2: F40b,
        sigma: &[usize; Self::LOC],
        seed_2: &[MacVerifier<F40b>],
    ) -> HDMacVerifier<F40b> {
        let x1 = HDMacVerifier::<F40b>::from(seed_2[sigma[0]]);
        let x2 = HDMacVerifier::<F40b>::from(seed_2[sigma[1]]);
        let x3 = HDMacVerifier::<F40b>::from(seed_2[sigma[2]]);
        let x4 = HDMacVerifier::<F40b>::from(seed_2[sigma[3]]);
        let x5 = HDMacVerifier::<F40b>::from(seed_2[sigma[4]]);

        let mut out = x1;
        out.add_assign(delta_2, &x2);
        out.add_assign(delta_2, &x3);
        let mut t = x2;
        t.add_assign(delta_2, &x4);
        let mut s = x3;
        s.add_assign(delta_2, &x5);
        t.mul_assign(&s);
        out.add_assign(delta_2, &t);
        out
    }

    fn expand_verifier_p(
        delta_p: FE,
        sigma: &[usize; Self::LOC],
        seed_p: &[MacVerifier<FE>],
    ) -> HDMacVerifier<FE> {
        let x1 = HDMacVerifier::<FE>::from(seed_p[sigma[0]]);
        let x2 = HDMacVerifier::<FE>::from(seed_p[sigma[1]]);
        let x3 = HDMacVerifier::<FE>::from(seed_p[sigma[2]]);
        let x4 = HDMacVerifier::<FE>::from(seed_p[sigma[3]]);
        let x5 = HDMacVerifier::<FE>::from(seed_p[sigma[4]]);

        let mut out = x2.clone();
        out.add_assign(delta_p, &x3);
        let mut s23 = x2.clone();
        s23.mul_assign(&x3);
        let mut s34 = x3.clone();
        s34.mul_assign(&x4);
        let mut s25 = x2.clone();
        s25.mul_assign(&x5);
        let mut s45 = x4.clone();
        s45.mul_assign(&x5);
        out.add_assign(delta_p, &s45);
        out.sub_assign(delta_p, &s23);
        out.sub_assign(delta_p, &s34);
        out.sub_assign(delta_p, &s25);

        out.xor_assign(delta_p, &x1);
        out
    }
}

pub trait Maj7: FiniteField {
    fn maj_prover_2(xs: &[HDMacProver<F40b, 4>; 7]) -> HDMacProver<F40b, 4> {
        let mut out = HDMacProver::default();
        for i0 in 0..=3 {
            let t0 = xs[i0].clone();
            for i1 in i0 + 1..=4 {
                let mut t1 = t0.clone();
                t1.mul_assign(&xs[i1]);
                for i2 in i1 + 1..=5 {
                    let mut t2 = t1.clone();
                    t2.mul_assign(&xs[i2]);
                    for i3 in i2 + 1..=6 {
                        let mut t3 = t2.clone();
                        t3.mul_assign(&xs[i3]);
                        out.add_assign(&t3);
                    }
                }
            }
        }
        out
    }
    fn maj_verifier_2(delta: F40b, xs: &[HDMacVerifier<F40b>; 7]) -> HDMacVerifier<F40b> {
        let mut out = HDMacVerifier::default();
        for i0 in 0..=3 {
            let t0 = xs[i0].clone();
            for i1 in i0 + 1..=4 {
                let mut t1 = t0.clone();
                t1.mul_assign(&xs[i1]);
                for i2 in i1 + 1..=5 {
                    let mut t2 = t1.clone();
                    t2.mul_assign(&xs[i2]);
                    for i3 in i2 + 1..=6 {
                        let mut t3 = t2.clone();
                        t3.mul_assign(&xs[i3]);
                        out.add_assign(delta, &t3);
                    }
                }
            }
        }
        out
    }
    fn maj_prover_p(xs: &[HDMacProver<Self, 12>; 7]) -> HDMacProver<Self, 12>;
    fn maj_verifier_p(delta: Self, xs: &[HDMacVerifier<Self>; 7]) -> HDMacVerifier<Self>;
}

// 1162071675278329888∗x^7 + 1505203075458939107∗x^6 + 1582064509099395571∗x^5 + 64051194700380392∗x^4
// + 544435154953233283∗x^3 + 1889510243661221445∗x^2 + 170193174489582167∗x

impl Maj7 for F61p {
    fn maj_prover_p(xs: &[HDMacProver<Self, 12>; 7]) -> HDMacProver<Self, 12> {
        let mut x = xs[0].clone();
        for i in 1..7 {
            x.add_assign(&xs[i]);
        }
        let mut out = HDMacProver::new_constant(F61p::try_from(1162071675278329888u128).unwrap());
        out.mul_assign(&x);
        out.add_assign_constant(F61p::try_from(1505203075458939107u128).unwrap());
        out.mul_assign(&x);
        out.add_assign_constant(F61p::try_from(1582064509099395571u128).unwrap());
        out.mul_assign(&x);
        out.add_assign_constant(F61p::try_from(64051194700380392u128).unwrap());
        out.mul_assign(&x);
        out.add_assign_constant(F61p::try_from(544435154953233283u128).unwrap());
        out.mul_assign(&x);
        out.add_assign_constant(F61p::try_from(1889510243661221445u128).unwrap());
        out.mul_assign(&x);
        out.add_assign_constant(F61p::try_from(170193174489582167u128).unwrap());
        out.mul_assign(&x);
        out
    }

    fn maj_verifier_p(delta: Self, xs: &[HDMacVerifier<Self>; 7]) -> HDMacVerifier<Self> {
        let mut x = xs[0].clone();
        for i in 1..7 {
            x.add_assign(delta, &xs[i]);
        }
        let mut out =
            HDMacVerifier::new_constant(delta, F61p::try_from(1162071675278329888u128).unwrap());
        out.mul_assign(&x);
        out.add_assign_constant(delta, F61p::try_from(1505203075458939107u128).unwrap());
        out.mul_assign(&x);
        out.add_assign_constant(delta, F61p::try_from(1582064509099395571u128).unwrap());
        out.mul_assign(&x);
        out.add_assign_constant(delta, F61p::try_from(64051194700380392u128).unwrap());
        out.mul_assign(&x);
        out.add_assign_constant(delta, F61p::try_from(544435154953233283u128).unwrap());
        out.mul_assign(&x);
        out.add_assign_constant(delta, F61p::try_from(1889510243661221445u128).unwrap());
        out.mul_assign(&x);
        out.add_assign_constant(delta, F61p::try_from(170193174489582167u128).unwrap());
        out.mul_assign(&x);
        out
    }
}

// Xor4Maj7(x1, ..., x11) = x1 ^ ... x4 ^ Maj(x5, ..., x11)
pub struct Xor4Maj7Predicate {}

impl Xor4Maj7Predicate {
    pub const LOC: usize = 11;
    pub const D2: usize = 4;
    pub const DP: usize = 12;
}

impl<FE: FiniteField + Maj7> PredicateT<FE, { Self::LOC }, { Self::D2 }, { Self::DP }>
    for Xor4Maj7Predicate
{
    fn expand_prover_2(
        sigma: &[usize; Self::LOC],
        seed_2: &[MacProver<F40b>],
    ) -> HDMacProver<F40b, { Self::D2 }> {
        let xs = sigma.map(|sigma_i| HDMacProver::<F40b, { Self::D2 }>::from(seed_2[sigma_i]));
        let mut out = xs[0].clone();
        out.add_assign(&xs[1]);
        out.add_assign(&xs[2]);
        out.add_assign(&xs[3]);
        out.add_assign(&<FE as Maj7>::maj_prover_2(xs[4..].try_into().unwrap()));
        out
    }

    fn expand_prover_p(
        sigma: &[usize; Self::LOC],
        seed_p: &[MacProver<FE>],
    ) -> HDMacProver<FE, { Self::DP }> {
        let xs = sigma.map(|sigma_i| HDMacProver::<FE, { Self::DP }>::from(seed_p[sigma_i]));
        let mut out = xs[0].clone();
        out.xor_assign(&xs[1]);
        out.xor_assign(&xs[2]);
        out.xor_assign(&xs[3]);
        out.xor_assign(&<FE as Maj7>::maj_prover_p(xs[4..].try_into().unwrap()));
        out
    }

    fn expand_verifier_2(
        delta_2: F40b,
        sigma: &[usize; Self::LOC],
        seed_2: &[MacVerifier<F40b>],
    ) -> HDMacVerifier<F40b> {
        let xs = sigma.map(|sigma_i| HDMacVerifier::<F40b>::from(seed_2[sigma_i]));
        let mut out = xs[0].clone();
        out.add_assign(delta_2, &xs[1]);
        out.add_assign(delta_2, &xs[2]);
        out.add_assign(delta_2, &xs[3]);
        out.add_assign(
            delta_2,
            &<FE as Maj7>::maj_verifier_2(delta_2, xs[4..].try_into().unwrap()),
        );
        out
    }

    fn expand_verifier_p(
        delta_p: FE,
        sigma: &[usize; Self::LOC],
        seed_p: &[MacVerifier<FE>],
    ) -> HDMacVerifier<FE> {
        let xs = sigma.map(|sigma_i| HDMacVerifier::<FE>::from(seed_p[sigma_i]));
        let mut out = xs[0].clone();
        out.xor_assign(delta_p, &xs[1]);
        out.xor_assign(delta_p, &xs[2]);
        out.xor_assign(delta_p, &xs[3]);
        out.xor_assign(
            delta_p,
            &<FE as Maj7>::maj_verifier_p(delta_p, xs[4..].try_into().unwrap()),
        );
        out
    }
}

pub struct LocalPrg<
    P: PredicateT<FE, LOC, D2, DP>,
    FE: FiniteField,
    const LOC: usize,
    const D2: usize,
    const DP: usize,
> {
    prg_setup_seed: <AesRng as SeedableRng>::Seed,
    rng: AesRng,
    seed_length: usize,
    output_length: usize,
    count: usize,
    fe: std::marker::PhantomData<FE>,
    pred: std::marker::PhantomData<P>,
}

impl<
        FE: FiniteField,
        const LOC: usize,
        const D2: usize,
        const DP: usize,
        P: PredicateT<FE, LOC, D2, DP>,
    > LocalPrg<P, FE, { LOC }, { D2 }, { DP }>
{
    pub const D2: usize = D2;
    pub const DP: usize = DP;

    pub fn setup(
        prg_setup_seed: <AesRng as SeedableRng>::Seed,
        seed_length: usize,
        output_length: usize,
    ) -> Self {
        assert!(output_length > seed_length);
        Self {
            prg_setup_seed,
            rng: AesRng::from_seed(prg_setup_seed),
            seed_length,
            output_length,
            count: 0,
            pred: Default::default(),
            fe: Default::default(),
        }
    }

    pub fn get_seed_length(&self) -> usize {
        self.seed_length
    }

    pub fn get_output_length(&self) -> usize {
        self.output_length
    }

    pub fn get_count(&self) -> usize {
        self.count
    }

    pub fn get_remaining(&self) -> usize {
        self.output_length - self.count
    }

    pub fn reset(&mut self) {
        *self = Self::setup(self.prg_setup_seed, self.seed_length, self.output_length);
    }

    fn gen_sigma(&mut self) -> [usize; LOC] {
        let mut output = [0; LOC];
        loop {
            for i in 0..LOC {
                output[i] = self.rng.gen_range(0..self.seed_length);
            }
            if (1..LOC).any(|i| output[..i].contains(&output[i])) {
                continue;
            }
            break;
        }
        output
    }

    pub fn next_prover_2(
        &mut self,
        seed_2: &[MacProver<F40b>],
    ) -> Option<HDMacProver<F40b, { D2 }>> {
        if self.count == self.output_length {
            return None;
        }
        self.count += 1;
        let sigma = self.gen_sigma();
        Some(P::expand_prover_2(&sigma, seed_2))
    }

    pub fn next_prover_p(&mut self, seed_p: &[MacProver<FE>]) -> Option<HDMacProver<FE, { DP }>> {
        if self.count == self.output_length {
            return None;
        }
        self.count += 1;
        let sigma = self.gen_sigma();
        Some(P::expand_prover_p(&sigma, seed_p))
    }

    pub fn next_prover(
        &mut self,
        seed_2: &[MacProver<F40b>],
        seed_p: &[MacProver<FE>],
    ) -> Option<HDDabitProver<FE, { D2 }, { DP }>> {
        if self.count == self.output_length {
            return None;
        }
        self.count += 1;
        let sigma = self.gen_sigma();
        Some(P::expand_prover(&sigma, seed_2, seed_p))
    }

    pub fn next_verifier_2(
        &mut self,
        delta_2: F40b,
        seed_2: &[MacVerifier<F40b>],
    ) -> Option<HDMacVerifier<F40b>> {
        if self.count == self.output_length {
            return None;
        }
        self.count += 1;
        let sigma = self.gen_sigma();
        Some(P::expand_verifier_2(delta_2, &sigma, seed_2))
    }

    pub fn next_verifier_p(
        &mut self,
        delta_p: FE,
        seed_p: &[MacVerifier<FE>],
    ) -> Option<HDMacVerifier<FE>> {
        if self.count == self.output_length {
            return None;
        }
        self.count += 1;
        let sigma = self.gen_sigma();
        Some(P::expand_verifier_p(delta_p, &sigma, seed_p))
    }

    pub fn next_verifier(
        &mut self,
        delta_2: F40b,
        delta_p: FE,
        seed_2: &[MacVerifier<F40b>],
        seed_p: &[MacVerifier<FE>],
    ) -> Option<HDDabitVerifier<FE>> {
        if self.count == self.output_length {
            return None;
        }
        self.count += 1;
        let sigma = self.gen_sigma();
        Some(P::expand_verifier(delta_2, delta_p, &sigma, seed_2, seed_p))
    }
}

pub type TSPAPrg<FE> = LocalPrg<
    TSPAPredicate,
    FE,
    { TSPAPredicate::LOC },
    { TSPAPredicate::D2 },
    { TSPAPredicate::DP },
>;

pub type Xor4Maj7Prg<FE> = LocalPrg<
    Xor4Maj7Predicate,
    FE,
    { Xor4Maj7Predicate::LOC },
    { Xor4Maj7Predicate::D2 },
    { Xor4Maj7Predicate::DP },
>;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use scuttlebutt::field::{F61p, F2};

    fn auth_2(delta: F40b, x: F2) -> (MacProver<F40b>, MacVerifier<F40b>) {
        let v = F40b::random(&mut thread_rng());
        (
            MacProver::new(x, v),
            MacVerifier::new(delta * F40b::from(x) + v),
        )
    }

    fn auth_p(delta: F61p, x: F61p) -> (MacProver<F61p>, MacVerifier<F61p>) {
        let v = F61p::random(&mut thread_rng());
        (MacProver::new(x, -v), MacVerifier::new(-(delta * x + v)))
    }

    fn test_local_prg<
        PRED: PredicateT<F61p, LOC, D2, DP>,
        const LOC: usize,
        const D2: usize,
        const DP: usize,
    >(
        mut prg_prover: LocalPrg<PRED, F61p, LOC, D2, DP>,
        mut prg_verifier: LocalPrg<PRED, F61p, LOC, D2, DP>,
    ) {
        let seed_length = prg_prover.get_seed_length();
        let output_length = prg_prover.get_output_length();
        assert_eq!(prg_verifier.get_seed_length(), seed_length);
        assert_eq!(prg_verifier.get_output_length(), output_length);

        let delta_2 = F40b::random(&mut thread_rng());
        let delta_p = F61p::random(&mut thread_rng());

        let ((seed_2_p, seed_2_v), (seed_p_p, seed_p_v)) = {
            let mut seed_2_p = Vec::with_capacity(seed_length);
            let mut seed_p_p = Vec::with_capacity(seed_length);
            let mut seed_2_v = Vec::with_capacity(seed_length);
            let mut seed_p_v = Vec::with_capacity(seed_length);
            for _ in 0..seed_length {
                let x: bool = thread_rng().gen();
                let (m2_p, m2_v) = auth_2(delta_2, if x { F2::ONE } else { F2::ZERO });
                let (mp_p, mp_v) = auth_p(delta_p, if x { F61p::ONE } else { F61p::ZERO });
                seed_2_p.push(m2_p);
                seed_p_p.push(mp_p);
                seed_2_v.push(m2_v);
                seed_p_v.push(mp_v);
            }
            ((seed_2_p, seed_2_v), (seed_p_p, seed_p_v))
        };

        for _ in 0..output_length {
            let (x_2_p, x_p_p) = prg_prover
                .next_prover(&seed_2_p, &seed_p_p)
                .expect("is some");
            let (x_2_v, x_p_v) = prg_verifier
                .next_verifier(delta_2, delta_p, &seed_2_v, &seed_p_v)
                .expect("is some");
            assert_eq!(x_2_p.qs_degree, D2);
            assert_eq!(x_2_v.qs_degree, D2);
            assert_eq!(x_p_p.qs_degree, DP);
            assert_eq!(x_p_v.qs_degree, DP);
            assert_eq!(x_2_p.poly.eval(delta_2), x_2_v.mac);
            assert_eq!(x_p_p.poly.eval(delta_p), x_p_v.mac);
            if x_2_p.value() == F40b::ONE {
                assert_eq!(x_p_p.value(), F61p::ONE);
            } else if x_2_p.value() == F40b::ZERO {
                assert_eq!(x_p_p.value(), F61p::ZERO);
            } else {
                assert!(false);
            }
        }
        assert!(prg_prover.next_prover(&seed_2_p, &seed_p_p).is_none());
        assert!(prg_verifier
            .next_verifier(delta_2, delta_p, &seed_2_v, &seed_p_v)
            .is_none());
    }

    #[test]
    fn test_tspa_prg() {
        let seed_length = 50;
        let output_length = 200;
        let prg_setup_seed = thread_rng().gen();
        let prg_prover = TSPAPrg::setup(prg_setup_seed, seed_length, output_length);
        let prg_verifier = TSPAPrg::setup(prg_setup_seed, seed_length, output_length);

        test_local_prg(prg_prover, prg_verifier);
    }

    #[test]
    fn test_x4m7_prg() {
        let seed_length = 50;
        let output_length = 200;
        let prg_setup_seed = thread_rng().gen();
        let prg_prover = Xor4Maj7Prg::setup(prg_setup_seed, seed_length, output_length);
        let prg_verifier = Xor4Maj7Prg::setup(prg_setup_seed, seed_length, output_length);

        test_local_prg(prg_prover, prg_verifier);
    }
}
