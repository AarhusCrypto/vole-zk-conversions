use crate::cheddabits::{DabitGeneratorProverT, DabitGeneratorVerifierT};
use crate::cheddaprg::{
    LocalPrg, Maj7, PredicateT, PrgDimensions, TSPAPredicate, TSPAPrg, Xor4Maj7Predicate,
    Xor4Maj7Prg,
};
use crate::conv::{
    ConvProverT, ConvVerifierT, EdabitsProver, EdabitsVerifier, ProverFromHomComsT,
    VerifierFromHomComsT,
};
use crate::edabits::RcRefCell;
use crate::hd_quicksilver::{HDMacProver, HDMacVerifier, QSStateProver, QSStateVerifier};
use crate::homcom::{FComProver, FComVerifier, MacProver, MacVerifier};
use crate::trunc::{FPMProverT, FPMVerifierT, MultTripleProver, MultTripleVerifier};
use eyre::{eyre, Result};
use generic_array::typenum::Unsigned;
use itertools::izip;
use num_traits::identities::One;
use rand::{CryptoRng, Rng};
use scuttlebutt::{
    field::{Degree, F40b, FiniteField, F2},
    ring::FiniteRing,
    utils::{pack_bits, unpack_bits},
    AbstractChannel,
};

fn gen_powers_of_two<FE: FiniteField>(k: usize) -> Vec<FE> {
    let two = FE::ONE + FE::ONE;
    let mut pot = two;
    let mut powers_of_two = Vec::with_capacity(k);
    powers_of_two.push(FE::ONE);
    powers_of_two.push(two);
    for _ in 2..k {
        pot *= two;
        powers_of_two.push(pot);
    }
    powers_of_two
}

pub struct CheddaConvProver<
    FE: FiniteField,
    DGP: DabitGeneratorProverT<FE>,
    PRED: PredicateT<FE, LOC, D2, DP> + PrgDimensions,
    const LOC: usize,
    const D2: usize,
    const DP: usize,
> {
    prg: LocalPrg<PRED, FE, LOC, D2, DP>,
    fcom_f2: RcRefCell<FComProver<F40b>>,
    fcom_fe: RcRefCell<FComProver<FE>>,
    dabit_gen: DGP,
    seed_2: Vec<MacProver<F40b>>,
    seed_p: Vec<MacProver<FE>>,
}

impl<
        FE: FiniteField,
        DGP: DabitGeneratorProverT<FE>,
        PRED: PredicateT<FE, LOC, D2, DP> + PrgDimensions,
        const LOC: usize,
        const D2: usize,
        const DP: usize,
    > CheddaConvProver<FE, DGP, PRED, LOC, D2, DP>
where
    DGP: ProverFromHomComsT<FE>,
{
    pub fn new(
        prg: LocalPrg<PRED, FE, LOC, D2, DP>,
        fcom_f2: &RcRefCell<FComProver<F40b>>,
        fcom_fe: &RcRefCell<FComProver<FE>>,
    ) -> Result<Self> {
        Ok(Self {
            prg,
            fcom_f2: fcom_f2.clone(),
            fcom_fe: fcom_fe.clone(),
            dabit_gen: DGP::from_homcoms(fcom_f2, fcom_fe)?,
            seed_2: Default::default(),
            seed_p: Default::default(),
        })
    }
}

impl<
        FE: FiniteField,
        DGP: DabitGeneratorProverT<FE>,
        PRED: PredicateT<FE, LOC, D2, DP> + PrgDimensions,
        const LOC: usize,
        const D2: usize,
        const DP: usize,
    > CheddaConvProver<FE, DGP, PRED, LOC, D2, DP>
{
    fn gen_seed_fp_only<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<()> {
        let prg_seed_size = self.prg.get_seed_length();
        let mut new_seed_p_values = Vec::with_capacity(prg_seed_size);
        for _ in 0..prg_seed_size {
            new_seed_p_values.push(if rng.gen_range(0..=1) == 1 {
                FE::PrimeField::ONE
            } else {
                FE::PrimeField::ZERO
            });
        }
        let new_seed_p_macs = self
            .fcom_fe
            .get_refmut()
            .input(channel, rng, &new_seed_p_values)?;
        let new_seed_p: Vec<_> = izip!(new_seed_p_values.into_iter(), new_seed_p_macs.into_iter())
            .map(|(x, x_mac)| MacProver::new(x, x_mac))
            .collect();
        channel.flush()?;
        let chi_p = channel.read_serializable()?;
        let mut qs_state_p = QSStateProver::<FE, { DP }>::init_with_chi(chi_p);
        for i in 0..prg_seed_size {
            let mut t = HDMacProver::from(new_seed_p[i]);
            t.sub_assign_constant(FE::ONE);
            t.mul_assign(&HDMacProver::from(new_seed_p[i]));
            qs_state_p.check_zero(&t);
        }
        qs_state_p.finalize(channel, rng, &mut self.fcom_fe.get_refmut())?;
        self.prg.reset();
        self.seed_p = new_seed_p;
        self.seed_2.clear();
        Ok(())
    }

    fn gen_seed<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<()> {
        let prg_seed_size = self.prg.get_seed_length();
        if self.seed_2.is_empty() || self.prg.get_remaining() < prg_seed_size {
            (self.seed_2, self.seed_p) = self.dabit_gen.gen_dabits(channel, rng, prg_seed_size)?;
        } else {
            let mut new_seed_2_values = Vec::with_capacity(prg_seed_size);
            let mut new_seed_p_values = Vec::with_capacity(prg_seed_size);
            let mut dabits = Vec::with_capacity(prg_seed_size);
            for _ in 0..prg_seed_size {
                let dabit = self
                    .prg
                    .next_prover(&self.seed_2, &self.seed_p)
                    .expect("enough output capacity left");
                if dabit.0.value() == F40b::ZERO {
                    debug_assert_eq!(dabit.1.value(), FE::ZERO);
                    new_seed_2_values.push(F2::ZERO);
                    new_seed_p_values.push(FE::PrimeField::ZERO);
                } else if dabit.0.value() == F40b::ONE {
                    debug_assert_eq!(dabit.1.value(), FE::ONE);
                    new_seed_2_values.push(F2::ONE);
                    new_seed_p_values.push(FE::PrimeField::ONE);
                } else {
                    unreachable!();
                }
                dabits.push(dabit);
            }
            let new_seed_2: Vec<_> = {
                let new_seed_2_macs =
                    self.fcom_f2
                        .get_refmut()
                        .input(channel, rng, &new_seed_2_values)?;
                izip!(new_seed_2_values, new_seed_2_macs,)
                    .map(|(v, m)| MacProver::new(v, m))
                    .collect()
            };
            let new_seed_p: Vec<_> = {
                let new_seed_p_macs =
                    self.fcom_fe
                        .get_refmut()
                        .input(channel, rng, &new_seed_p_values)?;
                izip!(new_seed_p_values, new_seed_p_macs,)
                    .map(|(v, m)| MacProver::new(v, m))
                    .collect()
            };
            channel.flush()?;
            let chi_2 = channel.read_serializable()?;
            let chi_p = channel.read_serializable()?;
            let mut qs_state_2 = QSStateProver::<F40b, { D2 }>::init_with_chi(chi_2);
            let mut qs_state_p = QSStateProver::<FE, { DP }>::init_with_chi(chi_p);
            for i in 0..prg_seed_size {
                dabits[i].0.sub_assign(&HDMacProver::from(new_seed_2[i]));
                dabits[i].1.sub_assign(&HDMacProver::from(new_seed_p[i]));
                qs_state_2.check_zero(&dabits[i].0);
                qs_state_p.check_zero(&dabits[i].1);
            }
            qs_state_2.finalize(channel, rng, &mut self.fcom_f2.get_refmut())?;
            qs_state_p.finalize(channel, rng, &mut self.fcom_fe.get_refmut())?;
            self.prg.reset();
            self.seed_2 = new_seed_2;
            self.seed_p = new_seed_p;
        }
        Ok(())
    }

    fn gen_bit<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<HDMacProver<FE, { DP }>> {
        if self.prg.get_remaining() <= self.prg.get_seed_length() {
            self.gen_seed_fp_only(channel, rng)?;
        }
        assert!(self.prg.get_remaining() > self.prg.get_seed_length());

        self.prg
            .next_prover_p(&self.seed_p)
            .ok_or(eyre!("dabit generation failed"))
    }

    fn gen_dabit<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(HDMacProver<F40b, { D2 }>, HDMacProver<FE, { DP }>)> {
        if self.prg.get_remaining() <= self.prg.get_seed_length() {
            self.gen_seed(channel, rng)?;
        }
        assert!(self.prg.get_remaining() > self.prg.get_seed_length());

        self.prg
            .next_prover(&self.seed_2, &self.seed_p)
            .ok_or(eyre!("dabit generation failed"))
    }
}

impl<
        FE: FiniteField,
        DGP: DabitGeneratorProverT<FE>,
        PRED: PredicateT<FE, LOC, D2, DP> + PrgDimensions,
        const LOC: usize,
        const D2: usize,
        const DP: usize,
    > ConvProverT<FE> for CheddaConvProver<FE, DGP, PRED, LOC, D2, DP>
{
    fn verify_conversions<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        conversion_tuples: &[EdabitsProver<FE>],
    ) -> Result<()> {
        if conversion_tuples.is_empty() {
            return Ok(());
        }
        let num_cts = conversion_tuples.len();
        let bit_size = conversion_tuples[0].bits.len();
        debug_assert!(conversion_tuples.iter().all(|ct| ct.bits.len() == bit_size));
        let num_bits = num_cts * bit_size;

        if self.seed_2.is_empty() {
            self.gen_seed(channel, rng)?;
        }
        debug_assert!(!self.seed_2.is_empty());
        debug_assert!(!self.seed_p.is_empty());

        let mut dabits = Vec::with_capacity(num_bits);
        for _ in 0..num_bits {
            dabits.push(self.gen_dabit(channel, rng)?);
        }

        let corrections = {
            let mut corrections = Vec::<bool>::with_capacity(num_bits);
            let mut dabit_j = 0;
            for ct in conversion_tuples.iter() {
                assert_eq!(ct.bits.len(), bit_size);
                for b_i in ct.bits.iter() {
                    corrections
                        .push((F40b::from(b_i.value()) + dabits[dabit_j].0.poly[D2]).is_one());
                    dabit_j += 1;
                }
            }
            debug_assert_eq!(corrections.len(), num_bits);
            channel.write_bytes(&pack_bits(&corrections))?;
            channel.flush()?;
            corrections
        };

        let chi_2: F40b = channel.read_serializable()?;
        let chi_p: FE = channel.read_serializable()?;
        let mut qs_state_2 = QSStateProver::init_with_chi(chi_2);
        let mut qs_state_p = QSStateProver::<FE, { DP }>::init_with_chi(chi_p);

        let powers_of_two = gen_powers_of_two(bit_size);

        let mut dabit_j = 0;
        for ct in conversion_tuples.iter() {
            assert_eq!(ct.bits.len(), bit_size);
            let mut acc = HDMacProver::from(ct.value);
            for (i, b_i) in ct.bits.iter().enumerate() {
                let c = corrections[dabit_j];
                // prove correction correct
                dabits[dabit_j].0.add_assign(&HDMacProver::from(*b_i));
                dabits[dabit_j]
                    .0
                    .add_assign_constant(if c { F40b::ONE } else { F40b::ZERO });
                qs_state_2.check_zero(&dabits[dabit_j].0);
                // prove conversion
                if c {
                    dabits[dabit_j].1.sub_assign_constant(FE::ONE);
                    dabits[dabit_j].1.mul_assign_constant(-FE::ONE);
                }
                debug_assert_eq!(
                    dabits[dabit_j].1.value(),
                    if bool::from(b_i.value()) {
                        FE::ONE
                    } else {
                        FE::ZERO
                    }
                );
                dabits[dabit_j].1.mul_assign_constant(powers_of_two[i]);
                acc.sub_assign(&dabits[dabit_j].1);
                dabit_j += 1;
            }
            qs_state_p.check_zero(&acc);
        }

        qs_state_2.finalize(channel, rng, &mut self.fcom_f2.get_refmut())?;
        qs_state_p.finalize(channel, rng, &mut self.fcom_fe.get_refmut())?;

        Ok(())
    }

    fn estimate_voles(n: usize, k: u32) -> (usize, usize) {
        if n == 0 {
            return (0, 0);
        }

        let prg_seed_size = PRED::SEED_LENGTH;
        let dabits_per_expansion = PRED::OUTPUT_LENGTH - PRED::SEED_LENGTH;
        let num_expansions = (n * k as usize + dabits_per_expansion - 1) / dabits_per_expansion;

        // VOLEs for the initial seed
        let (mut num_voles_2, mut num_voles_p) = DGP::estimate_voles(prg_seed_size);
        // VOLEs for reseeding
        num_voles_2 += (num_expansions - 1) * (prg_seed_size + (D2 - 1) * Degree::<F40b>::USIZE);
        num_voles_p += (num_expansions - 1) * (prg_seed_size + (DP - 1) * Degree::<FE>::USIZE);
        // VOLEs for QS check of conversion
        num_voles_2 += (D2 - 1) * Degree::<F40b>::USIZE;
        num_voles_p += (DP - 1) * Degree::<FE>::USIZE;

        (num_voles_2, num_voles_p)
    }
}

impl<
        FE: FiniteField,
        DGP: DabitGeneratorProverT<FE>,
        PRED: PredicateT<FE, LOC, D2, DP> + PrgDimensions,
        const LOC: usize,
        const D2: usize,
        const DP: usize,
    > FPMProverT<FE> for CheddaConvProver<FE, DGP, PRED, LOC, D2, DP>
{
    fn verify_fp_mult<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        fpm_tuples: &[MultTripleProver<FE>],
        k: u32,
        f: u32,
    ) -> Result<()> {
        if fpm_tuples.is_empty() {
            return Ok(());
        }
        let num_fpmts = fpm_tuples.len();
        let bit_size = (k + 2 * f) as usize;
        let num_bits = num_fpmts * bit_size;

        if self.seed_p.is_empty() {
            self.gen_seed_fp_only(channel, rng)?;
        }
        debug_assert!(!self.seed_p.is_empty());

        let mut rbits = Vec::with_capacity(num_bits);
        for _ in 0..num_bits {
            rbits.push(self.gen_bit(channel, rng)?);
        }
        let mut zs = Vec::with_capacity(num_bits);

        let corrections = {
            let mut corrections = Vec::<bool>::with_capacity(num_bits);
            let mut rbit_j = 0;
            for (x, y, _) in fpm_tuples.iter() {
                let z = {
                    let mut z = HDMacProver::from(*x);
                    z.mul_assign(&HDMacProver::from(*y));
                    z
                };
                let z_bits = z.value().bit_decomposition();
                debug_assert!(z_bits.iter().skip(bit_size).all(|b| *b == false));
                for b_i in z_bits.iter().take(bit_size) {
                    corrections.push(*b_i ^ rbits[rbit_j].value().is_one());
                    rbit_j += 1;
                }
                zs.push(z);
            }
            debug_assert_eq!(corrections.len(), num_bits);
            channel.write_bytes(&pack_bits(&corrections))?;
            channel.flush()?;
            corrections
        };

        let chi_p: FE = channel.read_serializable()?;
        let mut qs_state_p = QSStateProver::<FE, { DP }>::init_with_chi(chi_p);

        let powers_of_two = gen_powers_of_two(bit_size);

        let mut rbit_j = 0;
        for ((_, _, z_h), z) in izip!(fpm_tuples.iter(), zs.into_iter()) {
            let mut acc_h = HDMacProver::from(*z_h);
            let mut acc = z;
            for i in 0..bit_size {
                let c = corrections[rbit_j];
                if c {
                    rbits[rbit_j].sub_assign_constant(FE::ONE);
                    rbits[rbit_j].mul_assign_constant(-FE::ONE);
                }
                if i < f as usize {
                    rbits[rbit_j].mul_assign_constant(powers_of_two[i]);
                    acc.sub_assign(&rbits[rbit_j]);
                } else {
                    rbits[rbit_j].mul_assign_constant(powers_of_two[i - f as usize]);
                    acc_h.sub_assign(&rbits[rbit_j]);
                    rbits[rbit_j].mul_assign_constant(powers_of_two[f as usize]);
                    acc.sub_assign(&rbits[rbit_j]);
                }
                rbit_j += 1;
            }
            qs_state_p.check_zero(&acc_h);
            qs_state_p.check_zero(&acc);
        }

        qs_state_p.finalize(channel, rng, &mut self.fcom_fe.get_refmut())?;

        Ok(())
    }

    fn estimate_voles(n: usize, k: u32, f: u32) -> (usize, usize) {
        if n == 0 {
            return (0, 0);
        }

        let prg_seed_size = PRED::SEED_LENGTH;
        let dabits_per_expansion = PRED::OUTPUT_LENGTH - PRED::SEED_LENGTH;
        let num_expansions =
            (n * (k + 2 * f) as usize + dabits_per_expansion - 1) / dabits_per_expansion;

        // VOLEs for the seeds
        let mut num_voles_p = num_expansions * (prg_seed_size + Degree::<FE>::USIZE);
        // VOLEs for QS check of conversion
        num_voles_p += (DP - 1) * Degree::<FE>::USIZE;

        (0, num_voles_p)
    }
}

pub struct CheddaConvVerifier<
    FE: FiniteField,
    DGV: DabitGeneratorVerifierT<FE>,
    PRED: PredicateT<FE, LOC, D2, DP> + PrgDimensions,
    const LOC: usize,
    const D2: usize,
    const DP: usize,
> {
    prg: LocalPrg<PRED, FE, LOC, D2, DP>,
    fcom_f2: RcRefCell<FComVerifier<F40b>>,
    fcom_fe: RcRefCell<FComVerifier<FE>>,
    dabit_gen: DGV,
    seed_2: Vec<MacVerifier<F40b>>,
    seed_p: Vec<MacVerifier<FE>>,
}

impl<
        FE: FiniteField,
        DGV: DabitGeneratorVerifierT<FE>,
        PRED: PredicateT<FE, LOC, D2, DP> + PrgDimensions,
        const LOC: usize,
        const D2: usize,
        const DP: usize,
    > CheddaConvVerifier<FE, DGV, PRED, LOC, D2, DP>
where
    DGV: VerifierFromHomComsT<FE>,
{
    pub fn new(
        prg: LocalPrg<PRED, FE, LOC, D2, DP>,
        fcom_f2: &RcRefCell<FComVerifier<F40b>>,
        fcom_fe: &RcRefCell<FComVerifier<FE>>,
    ) -> Result<Self> {
        Ok(Self {
            prg,
            fcom_f2: fcom_f2.clone(),
            fcom_fe: fcom_fe.clone(),
            dabit_gen: DGV::from_homcoms(fcom_f2, fcom_fe)?,
            seed_2: Default::default(),
            seed_p: Default::default(),
        })
    }
}

impl<
        FE: FiniteField,
        DGV: DabitGeneratorVerifierT<FE>,
        PRED: PredicateT<FE, LOC, D2, DP> + PrgDimensions,
        const LOC: usize,
        const D2: usize,
        const DP: usize,
    > CheddaConvVerifier<FE, DGV, PRED, LOC, D2, DP>
{
    fn gen_seed_fp_only<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<()> {
        let delta_p = self.fcom_fe.get_refmut().get_delta();
        let prg_seed_size = self.prg.get_seed_length();
        let new_seed_p = self
            .fcom_fe
            .get_refmut()
            .input(channel, rng, prg_seed_size)?;
        let chi_p = FE::random(rng);
        channel.write_serializable(&chi_p)?;
        channel.flush()?;
        let mut qs_state_p = QSStateVerifier::<FE>::init_with_delta_and_chi(delta_p, chi_p);
        for i in 0..prg_seed_size {
            let mut t = HDMacVerifier::from(new_seed_p[i]);
            t.sub_assign_constant(delta_p, FE::ONE);
            t.mul_assign(&HDMacVerifier::from(new_seed_p[i]));
            qs_state_p.check_zero(&t);
        }
        if !qs_state_p.finalize_and_verify::<C, RNG, { DP }>(
            channel,
            rng,
            &mut self.fcom_fe.get_refmut(),
        )? {
            return Err(eyre!("QS over Fp verification failed"));
        }
        self.prg.reset();
        self.seed_p = new_seed_p;
        self.seed_2.clear();
        Ok(())
    }

    fn gen_seed<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<()> {
        let prg_seed_size = self.prg.get_seed_length();
        if self.seed_2.is_empty() || self.prg.get_remaining() < prg_seed_size {
            (self.seed_2, self.seed_p) =
                self.dabit_gen
                    .gen_dabits(channel, rng, self.prg.get_seed_length())?;
        } else {
            let delta_2 = self.fcom_f2.get_refmut().get_delta();
            let delta_p = self.fcom_fe.get_refmut().get_delta();
            let mut dabits = Vec::with_capacity(prg_seed_size);
            for _ in 0..prg_seed_size {
                dabits.push(
                    self.prg
                        .next_verifier(delta_2, delta_p, &self.seed_2, &self.seed_p)
                        .expect("enough output capacity left"),
                );
            }
            let new_seed_2 = self
                .fcom_f2
                .get_refmut()
                .input(channel, rng, prg_seed_size)?;
            let new_seed_p = self
                .fcom_fe
                .get_refmut()
                .input(channel, rng, prg_seed_size)?;
            let chi_2 = F40b::random(rng);
            let chi_p = FE::random(rng);
            channel.write_serializable(&chi_2)?;
            channel.write_serializable(&chi_p)?;
            channel.flush()?;
            let mut qs_state_2 = QSStateVerifier::<F40b>::init_with_delta_and_chi(delta_2, chi_2);
            let mut qs_state_p = QSStateVerifier::<FE>::init_with_delta_and_chi(delta_p, chi_p);
            for i in 0..prg_seed_size {
                dabits[i]
                    .0
                    .sub_assign(delta_2, &HDMacVerifier::from(new_seed_2[i]));
                dabits[i]
                    .1
                    .sub_assign(delta_p, &HDMacVerifier::from(new_seed_p[i]));
                qs_state_2.check_zero(&dabits[i].0);
                qs_state_p.check_zero(&dabits[i].1);
            }
            let check_result_2 = qs_state_2.finalize_and_verify::<C, RNG, { D2 }>(
                channel,
                rng,
                &mut self.fcom_f2.get_refmut(),
            )?;
            let check_result_p = qs_state_p.finalize_and_verify::<C, RNG, { DP }>(
                channel,
                rng,
                &mut self.fcom_fe.get_refmut(),
            )?;
            if !check_result_2 {
                return Err(eyre!("QS over F2 verification failed"));
            }
            if !check_result_p {
                return Err(eyre!("QS over Fp verification failed"));
            }
            self.prg.reset();
            self.seed_2 = new_seed_2;
            self.seed_p = new_seed_p;
        }
        Ok(())
    }

    fn gen_bit<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<HDMacVerifier<FE>> {
        if self.prg.get_remaining() <= self.prg.get_seed_length() {
            self.gen_seed_fp_only(channel, rng)?;
        }
        assert!(self.prg.get_remaining() > self.prg.get_seed_length());

        let delta_p = self.fcom_fe.get_refmut().get_delta();
        self.prg
            .next_verifier_p(delta_p, &self.seed_p)
            .ok_or(eyre!("dabit generation failed"))
    }

    fn gen_dabit<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(HDMacVerifier<F40b>, HDMacVerifier<FE>)> {
        if self.prg.get_remaining() <= self.prg.get_seed_length() {
            self.gen_seed(channel, rng)?;
        }
        assert!(self.prg.get_remaining() > self.prg.get_seed_length());

        let delta_2 = self.fcom_f2.get_refmut().get_delta();
        let delta_p = self.fcom_fe.get_refmut().get_delta();
        self.prg
            .next_verifier(delta_2, delta_p, &self.seed_2, &self.seed_p)
            .ok_or(eyre!("dabit generation failed"))
    }
}

impl<
        FE: FiniteField,
        DGV: DabitGeneratorVerifierT<FE>,
        PRED: PredicateT<FE, LOC, D2, DP> + PrgDimensions,
        const LOC: usize,
        const D2: usize,
        const DP: usize,
    > ConvVerifierT<FE> for CheddaConvVerifier<FE, DGV, PRED, LOC, D2, DP>
{
    fn verify_conversions<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        conversion_tuples: &[EdabitsVerifier<FE>],
    ) -> Result<()> {
        if conversion_tuples.is_empty() {
            return Ok(());
        }
        let num_cts = conversion_tuples.len();
        let bit_size = conversion_tuples[0].bits.len();
        debug_assert!(conversion_tuples.iter().all(|ct| ct.bits.len() == bit_size));
        let num_bits = num_cts * bit_size;

        if self.seed_2.is_empty() {
            self.gen_seed(channel, rng)?;
        }

        let mut dabits = Vec::with_capacity(num_bits);
        for _ in 0..num_bits {
            dabits.push(self.gen_dabit(channel, rng)?);
        }

        let corrections = {
            let mut correction_bytes = vec![0u8; (num_bits + 7) / 8];
            channel.read_bytes(&mut correction_bytes[0..(num_bits + 7) / 8])?;
            unpack_bits(&correction_bytes[0..(num_bits + 7) / 8], num_bits)
        };

        let delta_2 = self.fcom_f2.get_refmut().get_delta();
        let delta_p = self.fcom_fe.get_refmut().get_delta();
        let chi_2 = F40b::random(rng);
        let chi_p = FE::random(rng);
        channel.write_serializable(&chi_2)?;
        channel.write_serializable(&chi_p)?;
        channel.flush()?;
        let mut qs_state_2 = QSStateVerifier::init_with_delta_and_chi(delta_2, chi_2);
        let mut qs_state_p = QSStateVerifier::<FE>::init_with_delta_and_chi(delta_p, chi_p);

        let powers_of_two = gen_powers_of_two(bit_size);

        let mut dabit_j = 0;
        for ct in conversion_tuples.iter() {
            assert_eq!(ct.bits.len(), bit_size);
            let mut acc = HDMacVerifier::from(ct.value);
            for (i, b_i) in ct.bits.iter().enumerate() {
                let c = corrections[dabit_j];
                // verify correction
                dabits[dabit_j]
                    .0
                    .add_assign(delta_2, &HDMacVerifier::from(*b_i));
                dabits[dabit_j]
                    .0
                    .add_assign_constant(delta_2, if c { F40b::ONE } else { F40b::ZERO });
                qs_state_2.check_zero(&dabits[dabit_j].0);
                // verify conversion
                if c {
                    dabits[dabit_j].1.sub_assign_constant(delta_p, FE::ONE);
                    dabits[dabit_j].1.mul_assign_constant(-FE::ONE);
                }
                dabits[dabit_j].1.mul_assign_constant(powers_of_two[i]);
                acc.sub_assign(delta_p, &dabits[dabit_j].1);
                dabit_j += 1;
            }
            qs_state_p.check_zero(&acc);
        }

        let check_result_2 = qs_state_2.finalize_and_verify::<C, RNG, { D2 }>(
            channel,
            rng,
            &mut self.fcom_f2.get_refmut(),
        )?;
        let check_result_p = qs_state_p.finalize_and_verify::<C, RNG, { DP }>(
            channel,
            rng,
            &mut self.fcom_fe.get_refmut(),
        )?;
        if !check_result_2 {
            return Err(eyre!("QS over F2 verification failed"));
        }
        if !check_result_p {
            return Err(eyre!("QS over Fp verification failed"));
        }

        Ok(())
    }

    fn estimate_voles(n: usize, k: u32) -> (usize, usize) {
        if n == 0 {
            return (0, 0);
        }

        let prg_seed_size = PRED::SEED_LENGTH;
        let dabits_per_expansion = PRED::OUTPUT_LENGTH - PRED::SEED_LENGTH;
        let num_expansions = (n * k as usize + dabits_per_expansion - 1) / dabits_per_expansion;

        // VOLEs for the initial seed
        let (mut num_voles_2, mut num_voles_p) = DGV::estimate_voles(prg_seed_size);
        // VOLEs for reseeding
        num_voles_2 += (num_expansions - 1) * (prg_seed_size + (D2 - 1) * Degree::<F40b>::USIZE);
        num_voles_p += (num_expansions - 1) * (prg_seed_size + (DP - 1) * Degree::<FE>::USIZE);
        // VOLEs for QS check of conversion
        num_voles_2 += (D2 - 1) * Degree::<F40b>::USIZE;
        num_voles_p += (DP - 1) * Degree::<FE>::USIZE;

        (num_voles_2, num_voles_p)
    }
}

impl<
        FE: FiniteField,
        DGV: DabitGeneratorVerifierT<FE>,
        PRED: PredicateT<FE, LOC, D2, DP> + PrgDimensions,
        const LOC: usize,
        const D2: usize,
        const DP: usize,
    > FPMVerifierT<FE> for CheddaConvVerifier<FE, DGV, PRED, LOC, D2, DP>
{
    fn verify_fp_mult<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        fpm_tuples: &[MultTripleVerifier<FE>],
        k: u32,
        f: u32,
    ) -> Result<()> {
        if fpm_tuples.is_empty() {
            return Ok(());
        }
        let num_fpmts = fpm_tuples.len();
        let bit_size = (k + 2 * f) as usize;
        let num_bits = num_fpmts * bit_size;

        if self.seed_p.is_empty() {
            self.gen_seed_fp_only(channel, rng)?;
        }
        debug_assert!(!self.seed_p.is_empty());

        let mut rbits = Vec::with_capacity(num_bits);
        for _ in 0..num_bits {
            rbits.push(self.gen_bit(channel, rng)?);
        }

        let corrections = {
            let mut correction_bytes = vec![0u8; (num_bits + 7) / 8];
            channel.read_bytes(&mut correction_bytes[0..(num_bits + 7) / 8])?;
            unpack_bits(&correction_bytes[0..(num_bits + 7) / 8], num_bits)
        };

        let delta_p = self.fcom_fe.get_refmut().get_delta();
        let chi_p = FE::random(rng);
        channel.write_serializable(&chi_p)?;
        channel.flush()?;
        let mut qs_state_p = QSStateVerifier::<FE>::init_with_delta_and_chi(delta_p, chi_p);

        let powers_of_two = gen_powers_of_two(bit_size);

        let mut rbit_j = 0;
        for (x, y, z_h) in fpm_tuples.iter() {
            let mut acc_h = HDMacVerifier::from(*z_h);
            let mut acc = {
                let mut z = HDMacVerifier::from(*x);
                z.mul_assign(&HDMacVerifier::from(*y));
                z
            };
            for i in 0..bit_size {
                let c = corrections[rbit_j];
                if c {
                    rbits[rbit_j].sub_assign_constant(delta_p, FE::ONE);
                    rbits[rbit_j].mul_assign_constant(-FE::ONE);
                }
                if i < f as usize {
                    rbits[rbit_j].mul_assign_constant(powers_of_two[i]);
                    acc.sub_assign(delta_p, &rbits[rbit_j]);
                } else {
                    rbits[rbit_j].mul_assign_constant(powers_of_two[i - f as usize]);
                    acc_h.sub_assign(delta_p, &rbits[rbit_j]);
                    rbits[rbit_j].mul_assign_constant(powers_of_two[f as usize]);
                    acc.sub_assign(delta_p, &rbits[rbit_j]);
                }
                rbit_j += 1;
            }
            qs_state_p.check_zero(&acc_h);
            qs_state_p.check_zero(&acc);
        }

        let check_result_p = qs_state_p.finalize_and_verify::<C, RNG, { DP }>(
            channel,
            rng,
            &mut self.fcom_fe.get_refmut(),
        )?;
        if !check_result_p {
            return Err(eyre!("QS over Fp verification failed"));
        }

        Ok(())
    }

    fn estimate_voles(n: usize, k: u32, f: u32) -> (usize, usize) {
        if n == 0 {
            return (0, 0);
        }

        let prg_seed_size = PRED::SEED_LENGTH;
        let dabits_per_expansion = PRED::OUTPUT_LENGTH - PRED::SEED_LENGTH;
        let num_expansions =
            (n * (k + 2 * f) as usize + dabits_per_expansion - 1) / dabits_per_expansion;

        // VOLEs for the seeds
        let mut num_voles_p = num_expansions * (prg_seed_size + Degree::<FE>::USIZE);
        // VOLEs for QS check of fpm check
        num_voles_p += (DP - 1) * Degree::<FE>::USIZE;

        (0, num_voles_p)
    }
}

use crate::cheddabits::{
    ChedDabitGeneratorProverV1, ChedDabitGeneratorProverV2, ChedDabitGeneratorVerifierV1,
    ChedDabitGeneratorVerifierV2,
};

pub type CheddaConvProverV1TSPA<FE> = CheddaConvProver<
    FE,
    ChedDabitGeneratorProverV1<FE>,
    TSPAPredicate,
    { TSPAPredicate::LOC },
    { TSPAPredicate::D2 },
    { TSPAPredicate::DP },
>;

impl<FE: FiniteField> ProverFromHomComsT<FE> for CheddaConvProverV1TSPA<FE>
where
    u128: From<<FE as FiniteField>::PrimeField>,
    <<FE as FiniteField>::PrimeField as TryFrom<u128>>::Error: std::fmt::Debug,
{
    fn from_homcoms(
        fcom_f2: &RcRefCell<FComProver<F40b>>,
        fcom_fe: &RcRefCell<FComProver<FE>>,
    ) -> Result<Self> {
        let prg = TSPAPrg::setup(
            Default::default(),
            TSPAPredicate::SEED_LENGTH,
            TSPAPredicate::OUTPUT_LENGTH,
        );
        CheddaConvProver::new(prg, fcom_f2, fcom_fe)
    }
}

pub type CheddaConvVerifierV1TSPA<FE> = CheddaConvVerifier<
    FE,
    ChedDabitGeneratorVerifierV1<FE>,
    TSPAPredicate,
    { TSPAPredicate::LOC },
    { TSPAPredicate::D2 },
    { TSPAPredicate::DP },
>;

impl<FE: FiniteField> VerifierFromHomComsT<FE> for CheddaConvVerifierV1TSPA<FE>
where
    u128: From<<FE as FiniteField>::PrimeField>,
    <<FE as FiniteField>::PrimeField as TryFrom<u128>>::Error: std::fmt::Debug,
{
    fn from_homcoms(
        fcom_f2: &RcRefCell<FComVerifier<F40b>>,
        fcom_fe: &RcRefCell<FComVerifier<FE>>,
    ) -> Result<Self> {
        let prg = TSPAPrg::setup(
            Default::default(),
            TSPAPredicate::SEED_LENGTH,
            TSPAPredicate::OUTPUT_LENGTH,
        );
        CheddaConvVerifier::new(prg, fcom_f2, fcom_fe)
    }
}

pub type CheddaConvProverV2TSPA<FE> = CheddaConvProver<
    FE,
    ChedDabitGeneratorProverV2<FE>,
    TSPAPredicate,
    { TSPAPredicate::LOC },
    { TSPAPredicate::D2 },
    { TSPAPredicate::DP },
>;

impl<FE: FiniteField> ProverFromHomComsT<FE> for CheddaConvProverV2TSPA<FE>
where
    u128: From<<FE as FiniteField>::PrimeField>,
    <<FE as FiniteField>::PrimeField as TryFrom<u128>>::Error: std::fmt::Debug,
{
    fn from_homcoms(
        fcom_f2: &RcRefCell<FComProver<F40b>>,
        fcom_fe: &RcRefCell<FComProver<FE>>,
    ) -> Result<Self> {
        let prg = TSPAPrg::setup(
            Default::default(),
            TSPAPredicate::SEED_LENGTH,
            TSPAPredicate::OUTPUT_LENGTH,
        );
        CheddaConvProver::new(prg, fcom_f2, fcom_fe)
    }
}

pub type CheddaConvVerifierV2TSPA<FE> = CheddaConvVerifier<
    FE,
    ChedDabitGeneratorVerifierV2<FE>,
    TSPAPredicate,
    { TSPAPredicate::LOC },
    { TSPAPredicate::D2 },
    { TSPAPredicate::DP },
>;

impl<FE: FiniteField> VerifierFromHomComsT<FE> for CheddaConvVerifierV2TSPA<FE>
where
    u128: From<<FE as FiniteField>::PrimeField>,
    <<FE as FiniteField>::PrimeField as TryFrom<u128>>::Error: std::fmt::Debug,
{
    fn from_homcoms(
        fcom_f2: &RcRefCell<FComVerifier<F40b>>,
        fcom_fe: &RcRefCell<FComVerifier<FE>>,
    ) -> Result<Self> {
        let prg = TSPAPrg::setup(
            Default::default(),
            TSPAPredicate::SEED_LENGTH,
            TSPAPredicate::OUTPUT_LENGTH,
        );
        CheddaConvVerifier::new(prg, fcom_f2, fcom_fe)
    }
}

pub type CheddaConvProverV1Xor4Maj7<FE> = CheddaConvProver<
    FE,
    ChedDabitGeneratorProverV1<FE>,
    Xor4Maj7Predicate,
    { Xor4Maj7Predicate::LOC },
    { Xor4Maj7Predicate::D2 },
    { Xor4Maj7Predicate::DP },
>;

impl<FE: FiniteField> ProverFromHomComsT<FE> for CheddaConvProverV1Xor4Maj7<FE>
where
    FE: Maj7,
    u128: From<<FE as FiniteField>::PrimeField>,
    <<FE as FiniteField>::PrimeField as TryFrom<u128>>::Error: std::fmt::Debug,
{
    fn from_homcoms(
        fcom_f2: &RcRefCell<FComProver<F40b>>,
        fcom_fe: &RcRefCell<FComProver<FE>>,
    ) -> Result<Self> {
        let prg = Xor4Maj7Prg::setup(
            Default::default(),
            Xor4Maj7Predicate::SEED_LENGTH,
            Xor4Maj7Predicate::OUTPUT_LENGTH,
        );
        CheddaConvProver::new(prg, fcom_f2, fcom_fe)
    }
}

pub type CheddaConvVerifierV1Xor4Maj7<FE> = CheddaConvVerifier<
    FE,
    ChedDabitGeneratorVerifierV1<FE>,
    Xor4Maj7Predicate,
    { Xor4Maj7Predicate::LOC },
    { Xor4Maj7Predicate::D2 },
    { Xor4Maj7Predicate::DP },
>;

impl<FE: FiniteField> VerifierFromHomComsT<FE> for CheddaConvVerifierV1Xor4Maj7<FE>
where
    FE: Maj7,
    u128: From<<FE as FiniteField>::PrimeField>,
    <<FE as FiniteField>::PrimeField as TryFrom<u128>>::Error: std::fmt::Debug,
{
    fn from_homcoms(
        fcom_f2: &RcRefCell<FComVerifier<F40b>>,
        fcom_fe: &RcRefCell<FComVerifier<FE>>,
    ) -> Result<Self> {
        let prg = Xor4Maj7Prg::setup(
            Default::default(),
            Xor4Maj7Predicate::SEED_LENGTH,
            Xor4Maj7Predicate::OUTPUT_LENGTH,
        );
        CheddaConvVerifier::new(prg, fcom_f2, fcom_fe)
    }
}

pub type CheddaConvProverV2Xor4Maj7<FE> = CheddaConvProver<
    FE,
    ChedDabitGeneratorProverV2<FE>,
    Xor4Maj7Predicate,
    { Xor4Maj7Predicate::LOC },
    { Xor4Maj7Predicate::D2 },
    { Xor4Maj7Predicate::DP },
>;

impl<FE: FiniteField> ProverFromHomComsT<FE> for CheddaConvProverV2Xor4Maj7<FE>
where
    FE: Maj7,
    u128: From<<FE as FiniteField>::PrimeField>,
    <<FE as FiniteField>::PrimeField as TryFrom<u128>>::Error: std::fmt::Debug,
{
    fn from_homcoms(
        fcom_f2: &RcRefCell<FComProver<F40b>>,
        fcom_fe: &RcRefCell<FComProver<FE>>,
    ) -> Result<Self> {
        let prg = Xor4Maj7Prg::setup(
            Default::default(),
            Xor4Maj7Predicate::SEED_LENGTH,
            Xor4Maj7Predicate::OUTPUT_LENGTH,
        );
        CheddaConvProver::new(prg, fcom_f2, fcom_fe)
    }
}

pub type CheddaConvVerifierV2Xor4Maj7<FE> = CheddaConvVerifier<
    FE,
    ChedDabitGeneratorVerifierV2<FE>,
    Xor4Maj7Predicate,
    { Xor4Maj7Predicate::LOC },
    { Xor4Maj7Predicate::D2 },
    { Xor4Maj7Predicate::DP },
>;

impl<FE: FiniteField> VerifierFromHomComsT<FE> for CheddaConvVerifierV2Xor4Maj7<FE>
where
    FE: Maj7,
    u128: From<<FE as FiniteField>::PrimeField>,
    <<FE as FiniteField>::PrimeField as TryFrom<u128>>::Error: std::fmt::Debug,
{
    fn from_homcoms(
        fcom_f2: &RcRefCell<FComVerifier<F40b>>,
        fcom_fe: &RcRefCell<FComVerifier<FE>>,
    ) -> Result<Self> {
        let prg = Xor4Maj7Prg::setup(
            Default::default(),
            Xor4Maj7Predicate::SEED_LENGTH,
            Xor4Maj7Predicate::OUTPUT_LENGTH,
        );
        CheddaConvVerifier::new(prg, fcom_f2, fcom_fe)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cheddabits::{ChedDabitGeneratorProverV1, ChedDabitGeneratorVerifierV1};
    use crate::edabits::{random_edabits_prover, random_edabits_verifier};
    use crate::trunc::{random_fpm_triples_prover, random_fpm_triples_verifier};
    use ocelot::svole::wykw::{LPN_EXTEND_SMALL, LPN_SETUP_SMALL};
    use rand::thread_rng;
    use scuttlebutt::{channel::track_unix_channel_pair, field::F61p};
    use std::thread;

    fn test_cheddaconv<
        DGP: DabitGeneratorProverT<F61p> + ProverFromHomComsT<F61p>,
        DGV: DabitGeneratorVerifierT<F61p> + VerifierFromHomComsT<F61p>,
        PRED: PredicateT<F61p, LOC, D2, DP> + PrgDimensions,
        const LOC: usize,
        const D2: usize,
        const DP: usize,
    >() {
        let n = 23;
        let bitsize = 8;
        let (mut channel_v, mut channel_p) = track_unix_channel_pair();
        let prover_thread = thread::spawn(move || {
            let mut rng = thread_rng();
            let fcom_p = RcRefCell::new(
                FComProver::<F61p>::init(
                    &mut channel_p,
                    &mut rng,
                    LPN_SETUP_SMALL,
                    LPN_EXTEND_SMALL,
                )
                .expect("FComProver::init failed"),
            );
            let fcom_2 = RcRefCell::new(
                FComProver::<F40b>::init(
                    &mut channel_p,
                    &mut rng,
                    LPN_SETUP_SMALL,
                    LPN_EXTEND_SMALL,
                )
                .expect("FComProver::init failed"),
            );
            let prg = LocalPrg::<PRED, F61p, LOC, D2, DP>::setup(Default::default(), 20, 50);
            let mut conv: CheddaConvProver<F61p, DGP, PRED, LOC, D2, DP> =
                CheddaConvProver::new(prg, &fcom_2, &fcom_p).expect("new failed");
            let cts: Vec<EdabitsProver<F61p>> = random_edabits_prover(
                &mut fcom_2.get_refmut(),
                &mut fcom_p.get_refmut(),
                &mut channel_p,
                &mut rng,
                bitsize,
                n,
            )
            .expect("random edabits gen failed");

            channel_p.flush().expect("flush failed");

            let result = conv.verify_conversions(&mut channel_p, &mut rng, &cts);
            result.expect("verification failed");
        });
        let verifier_thread = thread::spawn(move || {
            let mut rng = thread_rng();
            let fcom_p = RcRefCell::new(
                FComVerifier::<F61p>::init(
                    &mut channel_v,
                    &mut rng,
                    LPN_SETUP_SMALL,
                    LPN_EXTEND_SMALL,
                )
                .expect("FComVerifier::init failed"),
            );
            let fcom_2 = RcRefCell::new(
                FComVerifier::<F40b>::init(
                    &mut channel_v,
                    &mut rng,
                    LPN_SETUP_SMALL,
                    LPN_EXTEND_SMALL,
                )
                .expect("FComVerifier::init failed"),
            );
            let prg = LocalPrg::<PRED, F61p, LOC, D2, DP>::setup(Default::default(), 20, 50);
            let mut conv: CheddaConvVerifier<F61p, DGV, PRED, LOC, D2, DP> =
                CheddaConvVerifier::new(prg, &fcom_2, &fcom_p).expect("new failed");
            let cts: Vec<EdabitsVerifier<F61p>> = random_edabits_verifier(
                &mut fcom_2.get_refmut(),
                &mut fcom_p.get_refmut(),
                &mut channel_v,
                &mut rng,
                bitsize,
                n,
            )
            .expect("random edabits gen failed");

            channel_v.flush().expect("flush failed");

            let result = conv.verify_conversions(&mut channel_v, &mut rng, &cts);
            result.expect("verification failed");
        });

        prover_thread.join().expect("join failed");
        verifier_thread.join().expect("join failed");
    }

    fn test_cheddatrunc<
        DGP: DabitGeneratorProverT<F61p> + ProverFromHomComsT<F61p>,
        DGV: DabitGeneratorVerifierT<F61p> + VerifierFromHomComsT<F61p>,
        PRED: PredicateT<F61p, LOC, D2, DP> + PrgDimensions,
        const LOC: usize,
        const D2: usize,
        const DP: usize,
    >() {
        let n = 23;
        let integer_size: u32 = 8;
        let fraction_size: u32 = 3;
        let (mut channel_v, mut channel_p) = track_unix_channel_pair();
        let prover_thread = thread::spawn(move || {
            let mut rng = thread_rng();
            let fcom_p = RcRefCell::new(
                FComProver::<F61p>::init(
                    &mut channel_p,
                    &mut rng,
                    LPN_SETUP_SMALL,
                    LPN_EXTEND_SMALL,
                )
                .expect("FComProver::init failed"),
            );
            let fcom_2 = RcRefCell::new(
                FComProver::<F40b>::init(
                    &mut channel_p,
                    &mut rng,
                    LPN_SETUP_SMALL,
                    LPN_EXTEND_SMALL,
                )
                .expect("FComProver::init failed"),
            );
            let prg = LocalPrg::<PRED, F61p, LOC, D2, DP>::setup(Default::default(), 20, 50);
            let mut conv: CheddaConvProver<F61p, DGP, PRED, LOC, D2, DP> =
                CheddaConvProver::new(prg, &fcom_2, &fcom_p).expect("new failed");
            let fpmts: Vec<MultTripleProver<F61p>> = random_fpm_triples_prover(
                &mut fcom_p.get_refmut(),
                &mut channel_p,
                &mut rng,
                integer_size,
                fraction_size,
                n,
            )
            .expect("random fpm gen failed");

            channel_p.flush().expect("flush failed");

            let result = conv.verify_fp_mult(
                &mut channel_p,
                &mut rng,
                &fpmts,
                integer_size,
                fraction_size,
            );
            result.expect("verification failed");
        });
        let verifier_thread = thread::spawn(move || {
            let mut rng = thread_rng();
            let fcom_p = RcRefCell::new(
                FComVerifier::<F61p>::init(
                    &mut channel_v,
                    &mut rng,
                    LPN_SETUP_SMALL,
                    LPN_EXTEND_SMALL,
                )
                .expect("FComVerifier::init failed"),
            );
            let fcom_2 = RcRefCell::new(
                FComVerifier::<F40b>::init(
                    &mut channel_v,
                    &mut rng,
                    LPN_SETUP_SMALL,
                    LPN_EXTEND_SMALL,
                )
                .expect("FComVerifier::init failed"),
            );
            let prg = LocalPrg::<PRED, F61p, LOC, D2, DP>::setup(Default::default(), 20, 50);
            let mut conv: CheddaConvVerifier<F61p, DGV, PRED, LOC, D2, DP> =
                CheddaConvVerifier::new(prg, &fcom_2, &fcom_p).expect("new failed");
            let fpmts: Vec<MultTripleVerifier<F61p>> =
                random_fpm_triples_verifier(&mut fcom_p.get_refmut(), &mut channel_v, &mut rng, n)
                    .expect("random fpm gen failed");

            channel_v.flush().expect("flush failed");

            let result = conv.verify_fp_mult(
                &mut channel_v,
                &mut rng,
                &fpmts,
                integer_size,
                fraction_size,
            );
            result.expect("verification failed");
        });

        prover_thread.join().expect("join failed");
        verifier_thread.join().expect("join failed");
    }

    #[test]
    fn test_cheddaconv_tspa_dabit_v1() {
        test_cheddaconv::<
            ChedDabitGeneratorProverV1<F61p>,
            ChedDabitGeneratorVerifierV1<F61p>,
            TSPAPredicate,
            { TSPAPredicate::LOC },
            { TSPAPredicate::D2 },
            { TSPAPredicate::DP },
        >();
    }

    #[test]
    fn test_cheddaconv_x4m7_dabit_v1() {
        test_cheddaconv::<
            ChedDabitGeneratorProverV1<F61p>,
            ChedDabitGeneratorVerifierV1<F61p>,
            Xor4Maj7Predicate,
            { Xor4Maj7Predicate::LOC },
            { Xor4Maj7Predicate::D2 },
            { Xor4Maj7Predicate::DP },
        >();
    }

    #[test]
    fn test_cheddaconv_tspa_dabit_v2() {
        test_cheddaconv::<
            ChedDabitGeneratorProverV2<F61p>,
            ChedDabitGeneratorVerifierV2<F61p>,
            TSPAPredicate,
            { TSPAPredicate::LOC },
            { TSPAPredicate::D2 },
            { TSPAPredicate::DP },
        >();
    }

    #[test]
    fn test_cheddaconv_x4m7_dabit_v2() {
        test_cheddaconv::<
            ChedDabitGeneratorProverV2<F61p>,
            ChedDabitGeneratorVerifierV2<F61p>,
            Xor4Maj7Predicate,
            { Xor4Maj7Predicate::LOC },
            { Xor4Maj7Predicate::D2 },
            { Xor4Maj7Predicate::DP },
        >();
    }

    #[test]
    fn test_cheddatrunc_tspa_dabit_v1() {
        test_cheddatrunc::<
            ChedDabitGeneratorProverV1<F61p>,
            ChedDabitGeneratorVerifierV1<F61p>,
            TSPAPredicate,
            { TSPAPredicate::LOC },
            { TSPAPredicate::D2 },
            { TSPAPredicate::DP },
        >();
    }

    #[test]
    fn test_cheddatrunc_x4m7_dabit_v1() {
        test_cheddatrunc::<
            ChedDabitGeneratorProverV1<F61p>,
            ChedDabitGeneratorVerifierV1<F61p>,
            Xor4Maj7Predicate,
            { Xor4Maj7Predicate::LOC },
            { Xor4Maj7Predicate::D2 },
            { Xor4Maj7Predicate::DP },
        >();
    }

    #[test]
    fn test_cheddatrunc_tspa_dabit_v2() {
        test_cheddatrunc::<
            ChedDabitGeneratorProverV2<F61p>,
            ChedDabitGeneratorVerifierV2<F61p>,
            TSPAPredicate,
            { TSPAPredicate::LOC },
            { TSPAPredicate::D2 },
            { TSPAPredicate::DP },
        >();
    }

    #[test]
    fn test_cheddatrunc_x4m7_dabit_v2() {
        test_cheddatrunc::<
            ChedDabitGeneratorProverV2<F61p>,
            ChedDabitGeneratorVerifierV2<F61p>,
            Xor4Maj7Predicate,
            { Xor4Maj7Predicate::LOC },
            { Xor4Maj7Predicate::D2 },
            { Xor4Maj7Predicate::DP },
        >();
    }
}
