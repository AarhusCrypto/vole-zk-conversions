// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! `ocelot` provides oblivious transfer and oblivious PRFs, more
//! specifically an implementation of the sVOLE extension protocol.

#![allow(clippy::many_single_char_names)]
#![allow(clippy::type_complexity)]
#![cfg_attr(feature = "nightly", feature(test))]
#![cfg_attr(feature = "nightly", feature(stdsimd))]
#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![cfg_attr(feature = "nightly", deny(missing_docs))]

mod errors;
mod utils;
pub use crate::errors::Error;
pub mod oprf;
pub mod ot;
pub mod svole;
