//! Echo activation module

#![allow(deprecated)]

mod activation;
mod types;

pub use activation::{EchoActivation, EchoClient};
pub use types::{EchoEvent, Message};
