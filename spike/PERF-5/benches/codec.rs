//! PERF-5 (4): the codecs on our own frames — a `tickets.health` item, a
//! 1 KB item and a `tickets.list --summary` row. Encode and decode, ns per
//! item and bytes per item. JSON lines on stdout.
//!
//! The JSON rows decode the wire's own bytes (`{"type":"data", …,
//! "content":{"type":…}}`); the binary rows carry the typed item (a
//! binary framing cannot carry a `Value` or an internally tagged enum).

use std::hint::black_box;

use perf5::frames::{self, Item};
use perf5::micro::{bench, emit};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::json;

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct WireItem<T> {
    #[serde(rename = "type")]
    kind: String,
    metadata: frames::Meta,
    content_type: String,
    content: T,
}

fn run<T: Serialize + DeserializeOwned + Clone + PartialEq + std::fmt::Debug>(frame: &str, item: Item<T>, tag: &str) {
    let wire = frames::wire_json(&item, tag);
    let e = |codec: &str, op: &str, bytes: usize, m: perf5::micro::Micro| emit(&m, json!({"frame": frame, "codec": codec, "op": op, "bytes": bytes}));

    // today: the wire's JSON — encode the item as plexus-core does (event → Value → text)
    let v = serde_json::to_value(&item.content).unwrap();
    e("serde_json (today: event → Value → text)", "encode", wire.len(), bench("enc", || {
        let content = serde_json::to_value(black_box(&item.content)).unwrap();
        let it = plexus_core::plexus::PlexusStreamItem::Data {
            metadata: plexus_core::plexus::StreamMetadata { provenance: item.metadata.provenance.clone(), plexus_hash: item.metadata.plexus_hash.clone(), timestamp: 0 },
            content_type: item.content_type.clone(),
            content,
        };
        black_box(serde_json::value::to_raw_value(&it).unwrap());
    }));
    let _ = v;
    e("serde_json typed (one encode)", "encode", serde_json::to_vec(&item).unwrap().len(), bench("enc", || {
        black_box(serde_json::to_vec(black_box(&item)).unwrap());
    }));
    e("serde_json → Value (today's clients)", "decode", wire.len(), bench("dec", || {
        black_box(serde_json::from_slice::<serde_json::Value>(black_box(&wire)).unwrap());
    }));
    e("serde_json typed", "decode", wire.len(), bench("dec", || {
        black_box(serde_json::from_slice::<WireItem<serde_json::Value>>(black_box(&wire)).unwrap());
    }));
    let typed = serde_json::to_vec(&item).unwrap();
    e("serde_json typed (struct)", "decode", typed.len(), bench("dec", || {
        black_box(serde_json::from_slice::<Item<T>>(black_box(&typed)).unwrap());
    }));
    e("sonic-rs typed (struct)", "decode", typed.len(), bench("dec", || {
        black_box(sonic_rs::from_slice::<Item<T>>(black_box(&typed)).unwrap());
    }));
    e("sonic-rs → Value", "decode", wire.len(), bench("dec", || {
        black_box(sonic_rs::from_slice::<sonic_rs::Value>(black_box(&wire)).unwrap());
    }));
    e("sonic-rs typed", "encode", sonic_rs::to_vec(&item).unwrap().len(), bench("enc", || {
        black_box(sonic_rs::to_vec(black_box(&item)).unwrap());
    }));
    e("simd-json typed (struct, incl. the copy it mutates)", "decode", typed.len(), bench("dec", || {
        let mut b = black_box(&typed).clone();
        black_box(simd_json::serde::from_slice::<Item<T>>(&mut b).unwrap());
    }));
    e("simd-json → OwnedValue (incl. copy)", "decode", wire.len(), bench("dec", || {
        let mut b = black_box(&wire).clone();
        black_box(simd_json::to_owned_value(&mut b).unwrap());
    }));
    let pc = postcard::to_allocvec(&item).unwrap();
    e("postcard", "encode", pc.len(), bench("enc", || {
        black_box(postcard::to_allocvec(black_box(&item)).unwrap());
    }));
    e("postcard", "decode", pc.len(), bench("dec", || {
        black_box(postcard::from_bytes::<Item<T>>(black_box(&pc)).unwrap());
    }));
    let mut cb = Vec::new();
    ciborium::into_writer(&item, &mut cb).unwrap();
    e("CBOR (ciborium)", "encode", cb.len(), bench("enc", || {
        let mut out = Vec::with_capacity(256);
        ciborium::into_writer(black_box(&item), &mut out).unwrap();
        black_box(out);
    }));
    e("CBOR (ciborium)", "decode", cb.len(), bench("dec", || {
        black_box(ciborium::from_reader::<Item<T>, _>(black_box(&cb[..])).unwrap());
    }));
    let mp = rmp_serde::to_vec_named(&item).unwrap();
    e("msgpack (rmp-serde, named)", "encode", mp.len(), bench("enc", || {
        black_box(rmp_serde::to_vec_named(black_box(&item)).unwrap());
    }));
    e("msgpack (rmp-serde, named)", "decode", mp.len(), bench("dec", || {
        black_box(rmp_serde::from_slice::<Item<T>>(black_box(&mp)).unwrap());
    }));
    let mpc = rmp_serde::to_vec(&item).unwrap();
    e("msgpack (rmp-serde, compact)", "encode", mpc.len(), bench("enc", || {
        black_box(rmp_serde::to_vec(black_box(&item)).unwrap());
    }));
    e("msgpack (rmp-serde, compact)", "decode", mpc.len(), bench("dec", || {
        black_box(rmp_serde::from_slice::<Item<T>>(black_box(&mpc)).unwrap());
    }));
    // round-trip sanity: every codec gives back the item
    assert_eq!(postcard::from_bytes::<Item<T>>(&pc).unwrap(), item);
    assert_eq!(ciborium::from_reader::<Item<T>, _>(&cb[..]).unwrap(), item);
    assert_eq!(rmp_serde::from_slice::<Item<T>>(&mp).unwrap(), item);
    assert_eq!(sonic_rs::from_slice::<Item<T>>(&typed).unwrap(), item);
}

fn main() {
    let only = std::env::args().nth(1).filter(|a| !a.starts_with('-'));
    let want = |f: &str| only.as_deref().map_or(true, |o| f.contains(o));
    if want("health") {
        run("tickets.health", frames::health(), "health");
    }
    if want("1KB") {
        run("1KB item", frames::blob(1024 - 120), "item");
    }
    if want("summary") {
        run("summary row", frames::summary(), "summary");
    }
}
