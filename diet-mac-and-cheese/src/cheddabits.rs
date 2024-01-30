use crate::conv::{DabitVecProver, DabitVecVerifier, ProverFromHomComsT, VerifierFromHomComsT};
use crate::edabits::RcRefCell;
use crate::hd_quicksilver::{qs_prover_check_range, qs_verifier_check_range};
use crate::homcom::{
    FComProver, FComVerifier, MacProver, MacVerifier, StateMultCheckProver, StateMultCheckVerifier,
};
use eyre::Result;
use generic_array::typenum::Unsigned;
use rand::{CryptoRng, Rng};
use scuttlebutt::{
    field::{Degree, F40b, FiniteField, F2},
    ring::FiniteRing,
    utils::unpack_bits,
    AbstractChannel,
};

const SEC_PARAM_KAPPA: u32 = 42;
const SEC_PARAM_S_V1: u32 = 48;
const SEC_PARAM_S_V2: u32 = 46;
const RANGE_MAX_CHUNK_SIZE: u32 = 8;

pub trait DabitGeneratorProverT<FE: FiniteField> {
    fn gen_dabits<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        n: usize,
    ) -> Result<DabitVecProver<FE>>;

    /// Estimate the number of VOLEs needed in F2 and Fp for n dabits
    fn estimate_voles(n: usize) -> (usize, usize);
}

pub trait DabitGeneratorVerifierT<FE: FiniteField> {
    fn gen_dabits<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        n: usize,
    ) -> Result<DabitVecVerifier<FE>>;

    /// Estimate the number of VOLEs needed in F2 and Fp for n dabits
    fn estimate_voles(n: usize) -> (usize, usize);
}

fn check_params_v1<FE: FiniteField>(n: usize) -> bool {
    FE::PrimeField::try_from(n as u128 * ((1 << SEC_PARAM_S_V1) + 1) - 1).is_ok()
}

fn check_params_v2<FE: FiniteField>(n: usize) -> bool {
    FE::PrimeField::try_from(n as u128).is_ok()
}

pub struct ChedDabitGeneratorProver<FE: FiniteField, const VERSION: usize> {
    fcom_f2: RcRefCell<FComProver<F40b>>,
    fcom_fe: RcRefCell<FComProver<FE>>,
}

pub type ChedDabitGeneratorProverV1<FE> = ChedDabitGeneratorProver<FE, 1>;
pub type ChedDabitGeneratorProverV2<FE> = ChedDabitGeneratorProver<FE, 2>;

impl<FE: FiniteField, const VERSION: usize> ProverFromHomComsT<FE>
    for ChedDabitGeneratorProver<FE, VERSION>
{
    fn from_homcoms(
        fcom_f2: &RcRefCell<FComProver<F40b>>,
        fcom_fe: &RcRefCell<FComProver<FE>>,
    ) -> Result<Self> {
        Ok(Self {
            fcom_f2: fcom_f2.clone(),
            fcom_fe: fcom_fe.clone(),
        })
    }
}

impl<FE: FiniteField, const VERSION: usize> ChedDabitGeneratorProver<FE, VERSION> {
    const _VERSION_CHECK: () = assert!(VERSION == 1 || VERSION == 2);
}

fn compute_v2_range_bounds(n: usize) -> (i128, i128) {
    assert!(n > 0);
    let t =
        (((SEC_PARAM_S_V2 as f64 + 1.0) * n as f64).sqrt() * 0.29435250562886867f64).ceil() as i128;
    ((n as i128 / 8) - t, (n as i128 / 8) + t)
}

impl<FE: FiniteField, const VERSION: usize> DabitGeneratorProverT<FE>
    for ChedDabitGeneratorProver<FE, VERSION>
where
    <FE as FiniteField>::PrimeField: TryInto<u128>,
    <<FE as FiniteField>::PrimeField as TryInto<u128>>::Error: std::fmt::Debug,
    <<FE as FiniteField>::PrimeField as TryFrom<u128>>::Error: std::fmt::Debug,
{
    fn gen_dabits<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        n: usize,
    ) -> Result<DabitVecProver<FE>> {
        if VERSION == 1 {
            assert!(check_params_v1::<FE>(n));
        } else if VERSION == 2 {
            assert!(check_params_v2::<FE>(n));
        }

        let mut fcom_2 = self.fcom_f2.get_refmut();
        let mut fcom_p = self.fcom_fe.get_refmut();

        let mut dabits_2 = Vec::with_capacity(n);
        let mut dabits_p = Vec::with_capacity(n);
        let mut masks_2 = Vec::with_capacity(SEC_PARAM_KAPPA as usize);
        let mut masks_p = Vec::with_capacity(SEC_PARAM_KAPPA as usize);

        // generate dabits
        for _ in 0..n {
            let db2 = fcom_2.random(channel, rng)?;
            let dbp = fcom_p.random(channel, rng)?;
            let correction = if db2.value() == F2::ZERO {
                dbp.value()
            } else {
                dbp.value() - FE::PrimeField::ONE
            };
            let dbp = fcom_p.affine_add_cst(-correction, dbp);
            debug_assert_eq!(
                dbp.value().try_into().unwrap(),
                u8::from(db2.value()) as u128
            );
            channel.write_serializable(&correction)?;
            dabits_2.push(db2);
            dabits_p.push(dbp);
        }

        // generate masks
        if VERSION == 1 {
            let mask_size = n as u128 * (1 << SEC_PARAM_S_V1);
            for _ in 0..SEC_PARAM_KAPPA as usize {
                let mut mp_val_as_int: u128 = rng.gen_range(0..mask_size);
                let m2 = fcom_2.random(channel, rng)?;
                let mp = fcom_p.random(channel, rng)?;
                mp_val_as_int ^= ((1 & mp_val_as_int as u8) ^ u8::from(m2.value())) as u128;
                let correction =
                    mp.value() - mp_val_as_int.try_into().expect("field is large enough");
                let mp = fcom_p.affine_add_cst(-correction, mp);
                debug_assert_eq!(
                    mp.value().try_into().unwrap() & 1u128,
                    u8::from(m2.value()) as u128
                );
                channel.write_serializable(&correction)?;
                masks_2.push(m2);
                masks_p.push(mp);
            }
            channel.flush()?;
        } else if VERSION == 2 {
            for _ in 0..SEC_PARAM_KAPPA as usize {
                let m2 = fcom_2.random(channel, rng)?;
                let mp_val = if m2.value() == F2::ZERO {
                    FE::PrimeField::ZERO
                } else {
                    FE::PrimeField::ONE
                };
                debug_assert_eq!(mp_val.try_into().unwrap(), u8::from(m2.value()) as u128);
                let mp_mac = fcom_p.input1(channel, rng, mp_val)?;
                masks_2.push(m2);
                masks_p.push(MacProver::new(mp_val, mp_mac));
            }
            channel.flush()?;
        }

        // consistency check
        let num_challenge_bytes = (n * SEC_PARAM_KAPPA as usize + 7) / 8;
        let challenge_bytes = channel.read_vec(num_challenge_bytes)?;
        let challenge_bits = unpack_bits(&challenge_bytes, n * SEC_PARAM_KAPPA as usize);
        for j in 0..SEC_PARAM_KAPPA as usize {
            let acc_p_j = &mut masks_p[j];
            let acc_2_j = &mut masks_2[j];
            for i in 0..n {
                if challenge_bits[j * n + i] {
                    *acc_2_j = fcom_2.add(*acc_2_j, dabits_2[i]);
                    *acc_p_j = fcom_p.add(*acc_p_j, dabits_p[i]);
                }
            }
            if VERSION == 1 {
                let a_p: u128 = acc_p_j.value().try_into().unwrap();
                let a_2 = u8::from(acc_2_j.value());
                assert!(a_p as u8 & 1 == a_2);
                assert!(a_p >= n as u128 && a_p < (1 << SEC_PARAM_S_V1) * n as u128);
            } else if VERSION == 2 {
                *acc_p_j = fcom_p.affine_mult_cst(
                    (FE::PrimeField::ONE + FE::PrimeField::ONE).inverse(),
                    fcom_p.affine_add_cst(
                        (u8::from(acc_2_j.value()) as u128).try_into().unwrap(),
                        *acc_p_j,
                    ),
                );
            }
        }
        fcom_2.open(channel, &masks_2)?;
        if VERSION == 1 {
            fcom_p.open(channel, &masks_p)?;
        } else if VERSION == 2 {
            let (v2_range_lbound, v2_range_ubound) = compute_v2_range_bounds(n);
            let hd_masks_p: Vec<_> = masks_p.iter().map(|&x| x.into()).collect();
            let mut qs_state = qs_prover_check_range::<_, 1, _, _>(
                channel,
                rng,
                &mut fcom_p,
                v2_range_lbound,
                v2_range_ubound,
                RANGE_MAX_CHUNK_SIZE,
                &hd_masks_p,
            )?;
            qs_state.finalize(channel, rng, &mut fcom_p)?;
        }

        // binary check
        {
            let mut qs = StateMultCheckProver::init(channel)?;
            for dbp in dabits_p.iter().copied() {
                let triple = (
                    dbp,
                    fcom_p.neg(fcom_p.affine_add_cst(-FE::PrimeField::ONE, dbp)),
                    MacProver::new(FE::PrimeField::ZERO, FE::ZERO),
                );
                fcom_p.quicksilver_push(&mut qs, &triple)?;
            }
            fcom_p.quicksilver_finalize(channel, rng, &mut qs)?;
        }

        Ok((dabits_2, dabits_p))
    }

    fn estimate_voles(n: usize) -> (usize, usize) {
        if VERSION == 1 {
            // generate n dabits
            // + \kappa more for the masks
            // + mask for QS check over Fp
            let num_voles_2 = n + SEC_PARAM_KAPPA as usize;
            let num_voles_p = n + SEC_PARAM_KAPPA as usize + Degree::<FE>::USIZE;
            (num_voles_2, num_voles_p)
        } else if VERSION == 2 {
            // same as above
            let num_voles_2 = n + SEC_PARAM_KAPPA as usize;
            // + QS range proof over Fp
            let num_voles_p = n + SEC_PARAM_KAPPA as usize + Degree::<FE>::USIZE + {
                let (a, b) = compute_v2_range_bounds(n);
                let range_proof_bits = ((b - a) as f64).log2().ceil() as u32;
                if RANGE_MAX_CHUNK_SIZE >= range_proof_bits {
                    ((1 << range_proof_bits) - 1) * Degree::<FE>::USIZE
                } else {
                    let num_chunks =
                        (range_proof_bits + RANGE_MAX_CHUNK_SIZE - 1) / RANGE_MAX_CHUNK_SIZE;
                    num_chunks as usize * 2 * SEC_PARAM_KAPPA as usize
                        + ((1 << RANGE_MAX_CHUNK_SIZE) - 1) * Degree::<FE>::USIZE
                }
            };
            (num_voles_2, num_voles_p)
        } else {
            unreachable!()
        }
    }
}

pub struct ChedDabitGeneratorVerifier<FE: FiniteField, const VERSION: usize> {
    fcom_f2: RcRefCell<FComVerifier<F40b>>,
    fcom_fe: RcRefCell<FComVerifier<FE>>,
}

pub type ChedDabitGeneratorVerifierV1<FE> = ChedDabitGeneratorVerifier<FE, 1>;
pub type ChedDabitGeneratorVerifierV2<FE> = ChedDabitGeneratorVerifier<FE, 2>;

impl<FE: FiniteField, const VERSION: usize> VerifierFromHomComsT<FE>
    for ChedDabitGeneratorVerifier<FE, VERSION>
{
    fn from_homcoms(
        fcom_f2: &RcRefCell<FComVerifier<F40b>>,
        fcom_fe: &RcRefCell<FComVerifier<FE>>,
    ) -> Result<Self> {
        Ok(Self {
            fcom_f2: fcom_f2.clone(),
            fcom_fe: fcom_fe.clone(),
        })
    }
}

impl<FE: FiniteField, const VERSION: usize> DabitGeneratorVerifierT<FE>
    for ChedDabitGeneratorVerifier<FE, VERSION>
where
    <FE as FiniteField>::PrimeField: TryInto<u128>,
    <<FE as FiniteField>::PrimeField as TryInto<u128>>::Error: std::fmt::Debug,
    <<FE as FiniteField>::PrimeField as TryFrom<u128>>::Error: std::fmt::Debug,
{
    fn gen_dabits<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        n: usize,
    ) -> Result<DabitVecVerifier<FE>> {
        if VERSION == 1 {
            assert!(check_params_v1::<FE>(n));
        } else if VERSION == 2 {
            assert!(check_params_v2::<FE>(n));
        }

        let mut fcom_2 = self.fcom_f2.get_refmut();
        let mut fcom_p = self.fcom_fe.get_refmut();

        let mut dabits_2 = Vec::with_capacity(n);
        let mut dabits_p = Vec::with_capacity(n);
        let mut masks_2 = Vec::with_capacity(SEC_PARAM_KAPPA as usize);
        let mut masks_p = Vec::with_capacity(SEC_PARAM_KAPPA as usize);

        // generate dabits
        for _ in 0..n {
            let db2 = fcom_2.random(channel, rng)?;
            let dbp = fcom_p.random(channel, rng)?;
            let correction: FE::PrimeField = channel.read_serializable()?;
            let dbp = fcom_p.affine_add_cst(-correction, dbp);
            dabits_2.push(db2);
            dabits_p.push(dbp);
        }

        // generate masks
        for _ in 0..SEC_PARAM_KAPPA as usize {
            let m2 = fcom_2.random(channel, rng)?;
            let mp = if VERSION == 1 {
                let mp = fcom_p.random(channel, rng)?;
                let correction: FE::PrimeField = channel.read_serializable()?;
                fcom_p.affine_add_cst(-correction, mp)
            } else if VERSION == 2 {
                fcom_p.input1(channel, rng)?
            } else {
                unreachable!()
            };
            masks_2.push(m2);
            masks_p.push(mp);
        }

        // consistency check
        let num_challenge_bytes = (n * SEC_PARAM_KAPPA as usize + 7) / 8;

        let challenge_bytes: Vec<u8> = (0..num_challenge_bytes).map(|_| rng.gen()).collect();
        channel.write_bytes(&challenge_bytes)?;
        channel.flush()?;
        let challenge_bits = unpack_bits(&challenge_bytes, n * SEC_PARAM_KAPPA as usize);
        for j in 0..SEC_PARAM_KAPPA as usize {
            let acc_p_j = &mut masks_p[j];
            let acc_2_j = &mut masks_2[j];
            for i in 0..n {
                if challenge_bits[j * n + i] {
                    *acc_2_j = fcom_2.add(*acc_2_j, dabits_2[i]);
                    *acc_p_j = fcom_p.add(*acc_p_j, dabits_p[i]);
                }
            }
            {}
        }
        let mut ds_2 = Vec::with_capacity(SEC_PARAM_KAPPA as usize);
        fcom_2.open(channel, &masks_2, &mut ds_2)?;
        if VERSION == 1 {
            let mut ds_p = Vec::with_capacity(SEC_PARAM_KAPPA as usize);
            fcom_p.open(channel, &masks_p, &mut ds_p)?;
            for j in 0..SEC_PARAM_KAPPA as usize {
                let d_p: u128 = ds_p[j].try_into().unwrap();
                let d_2 = u8::from(ds_2[j]);
                assert!(d_p as u8 & 1 == d_2);
                assert!(d_p >= n as u128 && d_p < (1 << SEC_PARAM_S_V1) * n as u128);
            }
        } else if VERSION == 2 {
            for j in 0..SEC_PARAM_KAPPA as usize {
                let acc_p_j = &mut masks_p[j];
                *acc_p_j = fcom_p.affine_mult_cst(
                    (FE::PrimeField::ONE + FE::PrimeField::ONE).inverse(),
                    fcom_p
                        .affine_add_cst((u8::from(ds_2[j]) as u128).try_into().unwrap(), *acc_p_j),
                );
            }
            let (v2_range_lbound, v2_range_ubound) = compute_v2_range_bounds(n);
            let hd_masks_p: Vec<_> = masks_p.iter().map(|&x| x.into()).collect();
            let mut qs_state = qs_verifier_check_range(
                channel,
                rng,
                &mut fcom_p,
                v2_range_lbound,
                v2_range_ubound,
                RANGE_MAX_CHUNK_SIZE,
                &hd_masks_p,
            )?;
            assert!(qs_state.finalize_and_verify::<_, _, 1>(channel, rng, &mut fcom_p)?);
        }

        // binary check
        {
            let mut qs = StateMultCheckVerifier::init(channel, rng)?;
            for dbp in dabits_p.iter().copied() {
                let triple = (
                    dbp,
                    fcom_p.neg(fcom_p.affine_add_cst(-FE::PrimeField::ONE, dbp)),
                    MacVerifier::new(FE::ZERO),
                );
                fcom_p.quicksilver_push(&mut qs, &triple)?;
            }
            fcom_p.quicksilver_finalize(channel, rng, &mut qs)?;
        }

        Ok((dabits_2, dabits_p))
    }

    fn estimate_voles(n: usize) -> (usize, usize) {
        ChedDabitGeneratorProver::<FE, VERSION>::estimate_voles(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ocelot::svole::wykw::{LPN_EXTEND_SMALL, LPN_SETUP_SMALL};
    use rand::thread_rng;
    use scuttlebutt::{channel::track_unix_channel_pair, field::F61p};
    use std::thread;

    fn test_dabit_gen<
        DGP: DabitGeneratorProverT<F61p> + ProverFromHomComsT<F61p>,
        DGV: DabitGeneratorVerifierT<F61p> + VerifierFromHomComsT<F61p>,
    >() {
        let n = 42;
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
            let mut dabit_gen = DGP::from_homcoms(&fcom_2, &fcom_p).expect("from_homcoms failed");
            dabit_gen
                .gen_dabits(&mut channel_p, &mut rng, n)
                .expect("gen_dabits failed")
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
            let mut dabit_gen = DGV::from_homcoms(&fcom_2, &fcom_p).expect("from_homcoms failed");
            let delta_2 = fcom_2.get_refmut().get_delta();
            let delta_p = fcom_p.get_refmut().get_delta();
            (
                delta_2,
                delta_p,
                dabit_gen
                    .gen_dabits(&mut channel_v, &mut rng, n)
                    .expect("gen_dabits failed"),
            )
        });

        let (d2s_p, dps_p) = prover_thread.join().unwrap();
        let (delta_2, delta_p, (d2s_v, dps_v)) = verifier_thread.join().unwrap();
        assert_eq!(d2s_p.len(), n);
        assert_eq!(dps_p.len(), n);
        assert_eq!(d2s_v.len(), n);
        assert_eq!(dps_v.len(), n);
        for i in 0..n {
            let d2_i = u8::from(d2s_p[i].value());
            let dp_i = dps_p[i].value().try_into().unwrap();
            assert_eq!(d2_i as u128, dp_i);
            assert_eq!(d2s_p[i].value() * delta_2 + d2s_v[i].mac(), d2s_p[i].mac());
            assert_eq!(dps_p[i].value() * delta_p + dps_v[i].mac(), dps_p[i].mac());
        }
    }

    #[test]
    fn test_cheddabit_dabit_gen_v1() {
        test_dabit_gen::<ChedDabitGeneratorProverV1<F61p>, ChedDabitGeneratorVerifierV1<F61p>>();
    }

    #[test]
    fn test_cheddabit_dabit_gen_v2() {
        test_dabit_gen::<ChedDabitGeneratorProverV2<F61p>, ChedDabitGeneratorVerifierV2<F61p>>();
    }
}
