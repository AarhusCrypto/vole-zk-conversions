use crate::conv::{ProverFromHomComsT, VerifierFromHomComsT};
use crate::homcom::{FComProver, FComVerifier, MacProver, MacVerifier};
use eyre::Result;
use rand::{CryptoRng, Rng};
use scuttlebutt::{field::FiniteField, AbstractChannel};

pub type MultTripleProver<FE> = (MacProver<FE>, MacProver<FE>, MacProver<FE>);
pub type MultTripleVerifier<FE> = (MacVerifier<FE>, MacVerifier<FE>, MacVerifier<FE>);

/// generate random fpm triples
pub fn random_fpm_triples_prover<FE: FiniteField, C: AbstractChannel, RNG: CryptoRng + Rng>(
    fp_prover: &mut FComProver<FE>,
    channel: &mut C,
    rng: &mut RNG,
    k: u32,
    f: u32,
    num: usize,
) -> Result<Vec<MultTripleProver<FE>>>
where
    <<FE as FiniteField>::PrimeField as TryFrom<u128>>::Error: std::fmt::Debug,
{
    let mut fpm_vec = Vec::with_capacity(num);

    for _ in 0..num {
        let x: u128 = rng.gen::<u128>() % ((1 << (k / 2 + f)) - 1);
        let y: u128 = rng.gen::<u128>() % ((1 << (k / 2 + f)) - 1);
        let z: u128 = (x * y) >> f;
        let x_val = FE::PrimeField::try_from(x).unwrap();
        let y_val = FE::PrimeField::try_from(y).unwrap();
        let z_val = FE::PrimeField::try_from(z).unwrap();
        let x_mac = fp_prover.input1(channel, rng, x_val)?;
        let y_mac = fp_prover.input1(channel, rng, y_val)?;
        let z_mac = fp_prover.input1(channel, rng, z_val)?;
        fpm_vec.push((
            MacProver::new(x_val, x_mac),
            MacProver::new(y_val, y_mac),
            MacProver::new(z_val, z_mac),
        ));
    }

    Ok(fpm_vec)
}

/// generate random edabits
pub fn random_fpm_triples_verifier<FE: FiniteField, C: AbstractChannel, RNG: CryptoRng + Rng>(
    fp_verifier: &mut FComVerifier<FE>,
    channel: &mut C,
    rng: &mut RNG,
    num: usize,
) -> Result<Vec<MultTripleVerifier<FE>>> {
    let mut fpm_vec = Vec::with_capacity(num);

    for _ in 0..num {
        let x_mac = fp_verifier.input1(channel, rng)?;
        let y_mac = fp_verifier.input1(channel, rng)?;
        let z_mac = fp_verifier.input1(channel, rng)?;
        fpm_vec.push((x_mac, y_mac, z_mac));
    }

    Ok(fpm_vec)
}

/// Interface for the prover side a fixed-point multiplication protocol.
pub trait FPMProverT<FE: FiniteField> {
    /// Prove that a list of conversion tunples is correct.
    fn verify_fp_mult<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        fpm_tuples: &[MultTripleProver<FE>],
        k: u32,
        f: u32,
    ) -> Result<()>;

    /// Estimate the number of VOLEs needed in F2 and Fp for n (k,f)-bit fixed-point
    /// multiplications
    fn estimate_voles(n: usize, k: u32, f: u32) -> (usize, usize);
}

/// Interface for the verifier side of a conversion protocol.
pub trait FPMVerifierT<FE: FiniteField> {
    /// Verify that a list of conversion tunples is correct.
    fn verify_fp_mult<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        fpm_tuples: &[MultTripleVerifier<FE>],
        k: u32,
        f: u32,
    ) -> Result<()>;

    /// Estimate the number of VOLEs needed in F2 and Fp for n (k,f)-bit fixed-point
    /// multiplications
    fn estimate_voles(n: usize, k: u32, f: u32) -> (usize, usize);
}

pub trait FPMProverFromHomComsT<FE: FiniteField>: FPMProverT<FE> + ProverFromHomComsT<FE> {}

impl<T, FE: FiniteField> FPMProverFromHomComsT<FE> for T where
    T: FPMProverT<FE> + ProverFromHomComsT<FE>
{
}

pub trait FPMVerifierFromHomComsT<FE: FiniteField>:
    FPMVerifierT<FE> + VerifierFromHomComsT<FE>
{
}

impl<T, FE: FiniteField> FPMVerifierFromHomComsT<FE> for T where
    T: FPMVerifierT<FE> + VerifierFromHomComsT<FE>
{
}
