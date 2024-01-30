use crate::edabits::RcRefCell;
use crate::hd_quicksilver::{HDMacProver, HDMacVerifier};
use crate::homcom::{FComProver, FComVerifier, MacProver, MacVerifier};
use eyre::Result;
use rand::{CryptoRng, Rng};
use scuttlebutt::{
    field::{F40b, FiniteField},
    AbstractChannel,
};

pub type DabitProver<FE> = (MacProver<F40b>, MacProver<FE>);
pub type DabitVecProver<FE> = (Vec<MacProver<F40b>>, Vec<MacProver<FE>>);
pub type DabitVerifier<FE> = (MacVerifier<F40b>, MacVerifier<FE>);
pub type DabitVecVerifier<FE> = (Vec<MacVerifier<F40b>>, Vec<MacVerifier<FE>>);

/// HDDabitProver tuple
pub type HDDabitProver<FE, const D2: usize, const DP: usize> =
    (HDMacProver<F40b, { D2 }>, HDMacProver<FE, { DP }>);

/// HDDabitVerifier tuple
pub type HDDabitVerifier<FE> = (HDMacVerifier<F40b>, HDMacVerifier<FE>);

/// EdabitsProver struct
#[derive(Clone, Debug)]
pub struct EdabitsProver<FE: FiniteField> {
    #[allow(missing_docs)]
    pub bits: Vec<MacProver<F40b>>,
    #[allow(missing_docs)]
    pub value: MacProver<FE>,
}

/// EdabitsVerifier struct
#[derive(Clone, Debug)]
pub struct EdabitsVerifier<FE: FiniteField> {
    #[allow(missing_docs)]
    pub bits: Vec<MacVerifier<F40b>>,
    #[allow(missing_docs)]
    pub value: MacVerifier<FE>,
}

/// Interface for the prover side a conversion protocol.
pub trait ConvProverT<FE: FiniteField> {
    /// Prove that a list of conversion tunples is correct.
    fn verify_conversions<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        conversion_tuples: &[EdabitsProver<FE>],
    ) -> Result<()>;
    /// Estimate the number of VOLEs needed in F2 and Fp for n k-bit conversions
    fn estimate_voles(n: usize, k: u32) -> (usize, usize);
}

/// Interface for the verifier side of a conversion protocol.
pub trait ConvVerifierT<FE: FiniteField> {
    /// Verify that a list of conversion tunples is correct.
    fn verify_conversions<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        conversion_tuples: &[EdabitsVerifier<FE>],
    ) -> Result<()>;
    /// Estimate the number of VOLEs needed in F2 and Fp for n k-bit conversions
    fn estimate_voles(n: usize, k: u32) -> (usize, usize);
}

/// A protocol that just needs HomCom functionalities for F2 and Fe.
pub trait ProverFromHomComsT<FE: FiniteField>: Sized {
    fn from_homcoms(
        fcom_f2: &RcRefCell<FComProver<F40b>>,
        fcom_fe: &RcRefCell<FComProver<FE>>,
    ) -> Result<Self>;
}

/// A protocol that just needs HomCom functionalities for F2 and Fe.
pub trait VerifierFromHomComsT<FE: FiniteField>: Sized {
    fn from_homcoms(
        fcom_f2: &RcRefCell<FComVerifier<F40b>>,
        fcom_fe: &RcRefCell<FComVerifier<FE>>,
    ) -> Result<Self>;
}

/// A conversion protocol that just needs HomCom functionalities for F2 and Fe.
pub trait ConvProverFromHomComsT<FE: FiniteField>:
    ConvProverT<FE> + ProverFromHomComsT<FE>
{
}

impl<T, FE: FiniteField> ConvProverFromHomComsT<FE> for T where
    T: ConvProverT<FE> + ProverFromHomComsT<FE>
{
}

/// A conversion protocol that just needs HomCom functionalities for F2 and Fe.
pub trait ConvVerifierFromHomComsT<FE: FiniteField>:
    ConvVerifierT<FE> + VerifierFromHomComsT<FE>
{
}

impl<T, FE: FiniteField> ConvVerifierFromHomComsT<FE> for T where
    T: ConvVerifierT<FE> + VerifierFromHomComsT<FE>
{
}
