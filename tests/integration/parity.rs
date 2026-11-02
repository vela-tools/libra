//! Parity test suite: proving that through Libra the caller sees exactly what direct
//! Scorpio returns, minus precisely what the policy removes.

pub mod harness;
mod omit;
mod passthrough;
mod pick;
mod temporal;

mod narrowing;
