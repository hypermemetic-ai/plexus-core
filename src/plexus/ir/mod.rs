//! RETURNS-40 — **the service writes its IR.** A service answers its
//! self-description as one document: every type once (`irTypes`), each
//! method referring to them (`irMethods`) — IR 3.1 (ASK-1; 3.0 without the bidir keys) as synapse
//! defines it (`Synapse.IR.Types`, `Read`, `Builder`) and builds it from the
//! raw schemas today, so the two are held equal: `tests/ir_fixtures.rs`
//! compares this module's output with the goldens synapse's `ir3-test`
//! writes, byte for byte in synapse's [`canonical`] form.
//!
//! [`build`] folds every schema a walk from each root reads, as synapse's
//! `buildIRFromSchemas`; [`build_one`] reads one schema, as its
//! `buildIRFromSchema`. A service's `ir` method (`<service>.ir`,
//! [`DynamicHub`](super::DynamicHub)) walks itself in process and answers
//! [`build`]'s IR. Where synapse's builder does something questionable, this
//! module does the same; a difference from synapse is a bug here.

mod build;
mod json;
mod read;
mod schema;
mod serve;
mod types;

pub use build::{build, build_one, IrBuildError, TypeSource};
pub use json::canonical;
pub use serve::{answer, roots, IrCache, IrError, IrKey, ServiceIr, IR_CACHE_BYTES, IR_CACHE_ENTRIES};
pub use types::*;
