use criterion::{black_box, criterion_group, criterion_main, Criterion};
use diet_mac_and_cheese::{
    cheddaprg::{LocalPrg, PredicateT, PrgDimensions, TSPAPredicate, Xor4Maj7Predicate},
    homcom::{MacProver, MacVerifier},
};
use rand::{thread_rng, Rng};
use scuttlebutt::{
    field::{F40b, F61p, FiniteField, F2},
    ring::FiniteRing,
};

fn create_prover<
    FE: FiniteField,
    const LOC: usize,
    const D2: usize,
    const DP: usize,
    P: PredicateT<FE, LOC, D2, DP> + PrgDimensions,
>() -> (
    LocalPrg<P, FE, { LOC }, { D2 }, { DP }>,
    Vec<MacProver<F40b>>,
    Vec<MacProver<FE>>,
) {
    let seed_length = P::SEED_LENGTH;
    let output_length = P::OUTPUT_LENGTH;
    let prg_setup_seed = thread_rng().gen();
    let prg_prover = LocalPrg::<P, FE, { LOC }, { D2 }, { DP }>::setup(
        prg_setup_seed,
        seed_length,
        output_length,
    );
    let mut seed_2 = Vec::<MacProver<F40b>>::with_capacity(seed_length);
    let mut seed_p = Vec::<MacProver<FE>>::with_capacity(seed_length);
    for _ in 0..seed_length {
        let x: bool = thread_rng().gen();
        seed_2.push(MacProver::new(
            if x { F2::ONE } else { F2::ZERO },
            thread_rng().gen(),
        ));
        seed_p.push(MacProver::new(
            if x {
                FE::PrimeField::ONE
            } else {
                FE::PrimeField::ZERO
            },
            FE::random(&mut thread_rng()),
        ));
    }
    (prg_prover, seed_2, seed_p)
}

fn create_verifier<
    FE: FiniteField,
    const LOC: usize,
    const D2: usize,
    const DP: usize,
    P: PredicateT<FE, LOC, D2, DP> + PrgDimensions,
>() -> (
    LocalPrg<P, FE, { LOC }, { D2 }, { DP }>,
    F40b,
    FE,
    Vec<MacVerifier<F40b>>,
    Vec<MacVerifier<FE>>,
) {
    let seed_length = P::SEED_LENGTH;
    let output_length = P::OUTPUT_LENGTH;
    let prg_setup_seed = thread_rng().gen();
    let prg_verifier = LocalPrg::<P, FE, { LOC }, { D2 }, { DP }>::setup(
        prg_setup_seed,
        seed_length,
        output_length,
    );
    let delta_2 = thread_rng().gen();
    let delta_p = FE::random(&mut thread_rng());
    let mut seed_2 = Vec::<MacVerifier<F40b>>::with_capacity(seed_length);
    let mut seed_p = Vec::<MacVerifier<FE>>::with_capacity(seed_length);
    for _ in 0..seed_length {
        seed_2.push(MacVerifier::new(thread_rng().gen()));
        seed_p.push(MacVerifier::new(FE::random(&mut thread_rng())));
    }
    (prg_verifier, delta_2, delta_p, seed_2, seed_p)
}

fn bench_x4mj_prover(c: &mut Criterion) {
    c.bench_function("cheddaprg::x4m7_prover", |b| {
        let (mut prg_prover, seed_2, seed_p) = create_prover::<
            F61p,
            { Xor4Maj7Predicate::LOC },
            { Xor4Maj7Predicate::D2 },
            { Xor4Maj7Predicate::DP },
            Xor4Maj7Predicate,
        >();
        b.iter(|| {
            let (x_2, x_p) = prg_prover.next_prover(&seed_2, &seed_p).expect("is some");
            black_box((x_2, x_p));
            if prg_prover.get_remaining() == 0 {
                prg_prover.reset();
            }
        });
    });
}

fn bench_x4mj_verifier(c: &mut Criterion) {
    c.bench_function("cheddaprg::x4m7_verifier", |b| {
        let (mut prg_verifier, delta_2, delta_p, seed_2, seed_p) = create_verifier::<
            F61p,
            { Xor4Maj7Predicate::LOC },
            { Xor4Maj7Predicate::D2 },
            { Xor4Maj7Predicate::DP },
            Xor4Maj7Predicate,
        >();
        b.iter(|| {
            let (x_2, x_p) = prg_verifier
                .next_verifier(delta_2, delta_p, &seed_2, &seed_p)
                .expect("is some");
            black_box((x_2, x_p));
            if prg_verifier.get_remaining() == 0 {
                prg_verifier.reset();
            }
        });
    });
}

fn bench_tspa_prover(c: &mut Criterion) {
    c.bench_function("cheddaprg::tspa_prover", |b| {
        let (mut prg_prover, seed_2, seed_p) = create_prover::<
            F61p,
            { TSPAPredicate::LOC },
            { TSPAPredicate::D2 },
            { TSPAPredicate::DP },
            TSPAPredicate,
        >();
        b.iter(|| {
            let (x_2, x_p) = prg_prover.next_prover(&seed_2, &seed_p).expect("is some");
            black_box((x_2, x_p));
            if prg_prover.get_remaining() == 0 {
                prg_prover.reset();
            }
        });
    });
}

fn bench_tspa_verifier(c: &mut Criterion) {
    c.bench_function("cheddaprg::tspa_verifier", |b| {
        let (mut prg_verifier, delta_2, delta_p, seed_2, seed_p) = create_verifier::<
            F61p,
            { TSPAPredicate::LOC },
            { TSPAPredicate::D2 },
            { TSPAPredicate::DP },
            TSPAPredicate,
        >();
        b.iter(|| {
            let (x_2, x_p) = prg_verifier
                .next_verifier(delta_2, delta_p, &seed_2, &seed_p)
                .expect("is some");
            black_box((x_2, x_p));
            if prg_verifier.get_remaining() == 0 {
                prg_verifier.reset();
            }
        });
    });
}

criterion_group! {
    name = cheddaprg;
    config = Criterion::default();
    targets = bench_x4mj_prover, bench_x4mj_verifier, bench_tspa_prover, bench_tspa_verifier
}
criterion_main!(cheddaprg);
