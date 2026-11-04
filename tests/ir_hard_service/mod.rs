//! RETURNS-40 review: the reviewer's service of hard shapes (xsvc) — a
//! generic page, recursion and mutual recursion, every serde enum
//! representation, a renamed string enum, a `$defs` name with a dot, deep
//! nesting, flattening, every number's default, one title with two docs in
//! two namespaces, a nested child. Its IR is held to synapse's
//! (`tests/fixtures/ir-hard/`), and it is the service the serving tests ask.
#![allow(dead_code, deprecated, non_camel_case_types, clippy::all)]

use std::collections::{BTreeMap, HashMap};
use async_stream::stream;
use futures::Stream;
use plexus_core::plexus::DynamicHub;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Oops { Bad { why: String } }
impl plexus_client::FromClientError for Oops {
    fn from_client_error(e: plexus_client::ClientError) -> Self { Oops::Bad { why: e.to_string() } }
}

/// A generic page.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Page<T> { pub items: Vec<T>, pub next: Option<String> }

/// A leaf.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Leaf { pub v: i64 }

/// A recursive tree.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Tree { pub name: String, pub kids: Vec<Tree>, pub parent: Option<Box<Tree>> }

/// Mutual recursion, one side.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Ping { pub pong: Option<Box<Pong>> }
/// Mutual recursion, other side.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Pong { pub pings: Vec<Ping>, pub by_name: BTreeMap<String, Ping> }

/// Externally tagged, every variant shape.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum Ext { Unit, New(Leaf), Tup(u32, String), Rec { a: bool, b: Option<f64> } }

/// Internally tagged with a unit and a newtype.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind")]
pub enum Int { A, B { x: u8 }, C(Leaf) }

/// Adjacently tagged.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "t", content = "c")]
pub enum Adj { One(String), Two { y: i32 }, Three }

/// Untagged with structs.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Unt { L(Leaf), T(Tree) }

/// String enum renamed.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
pub enum Shout { #[serde(rename = "x.y")] Dotted, /// documented variant
    Plain, Two_Words }

/// A type whose $defs name has a dot.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "dotted.Name")]
pub struct DottedName { pub z: u16 }

/// Nests.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Nest {
    pub a: Option<Vec<Option<HashMap<String, Vec<u8>>>>>,
    pub b: BTreeMap<String, Option<Leaf>>,
    pub c: Vec<Vec<Leaf>>,
    pub d: (u32, String, Option<Leaf>),
    pub e: serde_json::Value,
    pub f: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub g: Option<Shout>,
    #[serde(flatten)]
    pub h: Leaf,
    pub i: char,
    pub j: f32,
    pub k: u128,
    pub l: (),
    pub m: Vec<(String, i8)>,
    pub n: Option<Option<String>>,
    #[deprecated]
    pub o: bool,
    pub p: DottedName,
    pub q: [u8; 4],
    pub r: Box<Ext>,
    #[serde(rename = "with space")]
    pub s: String,
    /// Unicode — “quoted” é ü 中文 \u{2028} and a tab\t here.
    pub t: String,
}

/// Defaults of every number.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Nums {
    #[serde(default = "d1")] pub a: f64,
    #[serde(default = "d2")] pub b: f64,
    #[serde(default = "d3")] pub c: u64,
    #[serde(default = "d4")] pub d: i64,
    #[serde(default = "d5")] pub e: f64,
    #[serde(default = "d6")] pub f: f64,
    #[serde(default = "d7")] pub g: f64,
    #[schemars(range(min = -0.5, max = 12345678.9))] pub h: f64,
}
fn d1() -> f64 { 0.1 } fn d2() -> f64 { 1e21 } fn d3() -> u64 { u64::MAX } fn d4() -> i64 { i64::MIN }
fn d5() -> f64 { 1e-7 } fn d6() -> f64 { 12345678.5 } fn d7() -> f64 { -0.0 }

pub mod a_mod {
    use super::*;
    /// The note, as alpha writes it.
    #[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
    pub struct Note { /// alpha's text doc
        pub text: String }
}
pub mod b_mod {
    use super::*;
    /// The note, as beta writes it — a different doc, the same shape.
    #[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
    pub struct Note { /// beta's text doc
        pub text: String }
}

#[derive(Clone, Default)] pub struct Alpha;
#[plexus_macros::activation(namespace = "alpha", version = "1.0.0", description = "alpha", crate_path = "plexus_core")]
impl Alpha {
    /// generic page of leaves
    #[plexus_macros::method(params(cursor = "c"))]
    pub async fn leaves(&self, cursor: Option<String>) -> Result<Page<Leaf>, Oops> { let _ = cursor; Err(Oops::Bad{why: "x".into()}) }
    /// mutual
    #[plexus_macros::method]
    pub async fn ping(&self) -> Result<Pong, Oops> { Err(Oops::Bad{why: "x".into()}) }
    /// enums
    #[plexus_macros::method(params(e = "e", i = "i", a = "a"))]
    pub async fn enums(&self, e: Ext, i: Int, a: Adj) -> Result<Unt, Oops> { let _ = (e, i, a); Err(Oops::Bad{why: "x".into()}) }
    /// shout
    #[plexus_macros::method(params(s = "s", m = "m", n = "n"))]
    pub async fn shout(&self, s: Shout, m: Option<Vec<Shout>>, n: HashMap<String, Vec<Option<Leaf>>>) -> Result<Vec<Shout>, Oops> { let _ = (s, m, n); Err(Oops::Bad{why: "x".into()}) }
    /// nest
    #[plexus_macros::method]
    pub async fn nest(&self) -> Result<Nest, Oops> { Err(Oops::Bad{why: "x".into()}) }
    /// nums
    #[plexus_macros::method(params(n = "n", x = "x"))]
    pub async fn nums(&self, n: Nums, x: Option<f64>) -> Result<Nums, Oops> { let _ = x; Ok(n) }
    /// note a
    #[plexus_macros::method]
    pub async fn note(&self) -> Result<a_mod::Note, Oops> { Err(Oops::Bad{why: "x".into()}) }
    /// stream of trees
    #[plexus_macros::method]
    pub async fn stream_trees(&self) -> impl Stream<Item = Tree> + Send + 'static { stream! { yield Tree { name: "t".into(), kids: vec![], parent: None }; } }
    /// dotted
    #[plexus_macros::method(params(d = "d"))]
    pub async fn dotted(&self, d: DottedName) -> Result<DottedName, Oops> { Ok(d) }
    /// child
    #[plexus_macros::child]
    fn inner(&self) -> Inner { Inner }
}

#[derive(Clone, Default)] pub struct Inner;
#[plexus_macros::activation(namespace = "inner", version = "1.0.0", description = "inner", crate_path = "plexus_core")]
impl Inner {
    /// tree in inner
    #[plexus_macros::method]
    pub async fn tree(&self) -> Result<Tree, Oops> { Err(Oops::Bad{why: "x".into()}) }
    /// leaf page in inner
    #[plexus_macros::method]
    pub async fn leaves(&self) -> Result<Page<Leaf>, Oops> { Err(Oops::Bad{why: "x".into()}) }
    /// note b in inner
    #[plexus_macros::method]
    pub async fn note(&self) -> Result<b_mod::Note, Oops> { Err(Oops::Bad{why: "x".into()}) }
}

#[derive(Clone, Default)] pub struct Beta;
#[plexus_macros::activation(namespace = "beta", version = "1.0.0", description = "beta", crate_path = "plexus_core")]
impl Beta {
    /// note b
    #[plexus_macros::method]
    pub async fn note(&self) -> Result<b_mod::Note, Oops> { Err(Oops::Bad{why: "x".into()}) }
    /// trees again
    #[plexus_macros::method]
    pub async fn trees(&self) -> Result<Page<Tree>, Oops> { Err(Oops::Bad{why: "x".into()}) }
    /// tree twice
    #[plexus_macros::method]
    pub async fn tree(&self) -> Result<Tree, Oops> { Err(Oops::Bad{why: "x".into()}) }
    /// ext
    #[plexus_macros::method(params(e = "e"))]
    pub async fn ext(&self, e: Ext) -> Result<Ext, Oops> { Ok(e) }
    /// nest again
    #[plexus_macros::method]
    pub async fn nest(&self) -> Result<Nest, Oops> { Err(Oops::Bad{why: "x".into()}) }
    /// dotted
    #[plexus_macros::method(params(d = "d"))]
    pub async fn dotted(&self, d: DottedName) -> Result<DottedName, Oops> { Ok(d) }
}

pub fn service() -> DynamicHub {
    DynamicHub::new("xsvc").register(Alpha).register(Beta)
}
