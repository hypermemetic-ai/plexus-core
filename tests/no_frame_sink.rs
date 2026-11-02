//! PERF-27: a transport with no frame sink (stdio, a module called in memory).
//! An item reaches jsonrpsee's sink as text the pipe wrote, and no JSON check
//! stands behind it, so this file is that check: every kind of item, on the
//! real pipe, with content chosen to break a splice, reads back as the item it
//! was, and its text is one JSON value with nothing around it. In a debug
//! build serde_json parses each `Data` text as well.

use std::sync::Arc;

use bytes::Bytes;
use jsonrpsee::RpcModule;
use plexus_core::plexus::wire::{self, Content};
use plexus_core::plexus::{PlexusStream, PlexusStreamItem, StreamMetadata};
use serde_json::{json, Value};

/// A module with one subscription, piping `items` as a call does.
fn module(items: Vec<PlexusStreamItem>) -> RpcModule<()> {
    let mut m = RpcModule::new(());
    m.register_subscription("test.sub", "test.note", "test.unsub", move |_params, pending, _ctx, ext| {
        let items = items.clone();
        async move {
            let sink = pending.accept().await?;
            let stream: PlexusStream = Box::pin(futures::stream::iter(items));
            wire::pipe(sink, stream, &ext).await
        }
    })
    .unwrap();
    m
}

/// What a client with no frame sink reads of `items`: each notification's text.
async fn read(items: &[PlexusStreamItem]) -> Vec<String> {
    let m = module(items.to_vec());
    let (_, mut rx) = m.raw_json_request(r#"{"jsonrpc":"2.0","id":1,"method":"test.sub","params":[]}"#, 1024).await.unwrap();
    let mut out = Vec::new();
    while out.len() < items.len() {
        out.push(rx.recv().await.expect("every item arrives").get().to_string());
    }
    out
}

fn meta() -> StreamMetadata {
    StreamMetadata::new(vec!["a\"b\\c".into(), "日本語".into()], "h\"\\\n".into())
}

fn data(meta: &Arc<StreamMetadata>, content_type: &str, content: Content) -> PlexusStreamItem {
    PlexusStreamItem::Data { metadata: meta.clone(), content_type: content_type.to_string().into(), content }
}

fn json_bytes(text: &'static str) -> Content {
    Content::from_json(Bytes::from_static(text.as_bytes())).unwrap()
}

/// Each notification's `result` is its item, and the notification parses.
async fn holds(items: Vec<PlexusStreamItem>) {
    let got = read(&items).await;
    for (text, item) in got.iter().zip(&items) {
        assert_eq!(text, text.trim(), "nothing around it");
        let v: Value = serde_json::from_str(text).unwrap_or_else(|e| panic!("{e}: {text}"));
        assert_eq!(v["params"]["result"], serde_json::to_value(item).unwrap(), "{text}");
    }
}

#[tokio::test]
async fn data_of_every_shape_reads_as_itself() {
    let m = Arc::new(meta());
    holds(vec![
        data(&m, "t.a", Content::from_value(json!({"quote": "\"", "slash": "\\", "unicode": "日本語 🦀", "control": "\u{1}\n\t"}))),
        data(&m, "t.a", json_bytes("{\"a\":1}")),
        data(&m, "t.a", json_bytes("  {\"spaced\" : [ 1 , 2 ] , \"s\":\"x\\ny\"}\n")),
        data(&m, "t.a", json_bytes("3")),
        data(&m, "t.a", json_bytes("null")),
        data(&m, "t.a", json_bytes("\"a string\"")),
        data(&m, "t.a", json_bytes("[]")),
        data(&m, "t.a", json_bytes("{}")),
        data(&m, "t.a", json_bytes("1.5e300")),
        data(&m, "t.b\"quoted\\", Content::from_value(json!(18446744073709551615u64))),
        data(&m, "t.b\"quoted\\", Content::from_value(Value::Null)),
    ])
    .await;
}

/// A new stream's metadata mid-call: the opening written once is written again.
#[tokio::test]
async fn data_whose_metadata_changes_reads_as_itself() {
    let (a, b) = (Arc::new(meta()), Arc::new(StreamMetadata::new(vec!["other".into()], "h2".into())));
    holds(vec![data(&a, "t", json_bytes("1")), data(&b, "t", json_bytes("2")), data(&a, "u", json_bytes("3"))]).await;
}

#[tokio::test]
async fn every_other_kind_of_item_reads_as_itself() {
    holds(vec![
        PlexusStreamItem::progress(meta(), "half \"way\"".into(), Some(50.0)),
        PlexusStreamItem::error(meta(), "it broke \\ badly".into(), Some("E1".into()), true),
        PlexusStreamItem::request("r1".into(), json!({"ask": "\"this\""}), 5000),
        PlexusStreamItem::done(meta()),
    ])
    .await;
}

/// `from_json` holds text to JSON's grammar and not to UTF-8, so this is text
/// no check stands behind but the one kept: the call ends at it, and nothing
/// that is not JSON reaches the client.
#[tokio::test]
async fn text_that_is_not_utf8_ends_the_call() {
    let m = Arc::new(meta());
    let items = vec![
        data(&m, "t", json_bytes("1")),
        data(&m, "t", Content::from_json(Bytes::from_static(b"\"\xff\"")).unwrap()),
        data(&m, "t", json_bytes("3")),
    ];
    let module = module(items);
    let (_, mut rx) = module.raw_json_request(r#"{"jsonrpc":"2.0","id":1,"method":"test.sub","params":[]}"#, 1024).await.unwrap();
    let mut got = Vec::new();
    while let Some(raw) = rx.recv().await {
        got.push(serde_json::from_str::<Value>(raw.get()).unwrap());
    }
    assert_eq!(got[0]["params"]["result"]["content"], json!(1));
    assert!(got[1..].iter().all(|n| n["params"]["result"].get("content").is_none()), "{got:?}");
}

/// A large item, past any first block.
#[tokio::test]
async fn a_large_item_reads_as_itself() {
    let m = Arc::new(meta());
    let pad = "x\"".repeat(200_000);
    holds(vec![data(&m, "t", Content::from_value(json!({"pad": pad})))]).await;
}
