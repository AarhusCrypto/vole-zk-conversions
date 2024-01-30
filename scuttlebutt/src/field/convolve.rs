//! TODO

use crate::ring::FiniteRing;

/// TODO
pub trait Convolve: FiniteRing {
    /// TODO
    fn convolve(z0: &mut Self, zs: &mut [Self], x0: Self, xs: &[Self], y0: Self, ys: &[Self]) {
        assert_eq!(zs.len(), xs.len() + ys.len());
        *z0 = x0 * y0;
        for i in 0..ys.len() {
            zs[i] = x0 * ys[i];
        }
        for i in 0..xs.len() {
            zs[i] += y0 * xs[i];
        }
        for i in 0..xs.len() {
            for j in 0..ys.len() {
                zs[i + j + 1] += xs[i] * ys[j];
            }
        }
    }
}
