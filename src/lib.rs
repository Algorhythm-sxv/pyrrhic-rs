#![allow(dead_code)]
#![allow(mutable_transmutes)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_assignments)]
#![allow(unused_mut)]

#![doc = include_str!("../README.md")]

extern crate libc;
pub mod engine_adapter;
mod tbprobe;

pub mod tablebases;
pub use tablebases::*;
pub use engine_adapter::*;

#[cfg(test)]
mod tests;
