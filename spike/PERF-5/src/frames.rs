//! Our own frames, for the codec table: the item as the wire carries it
//! (`PlexusStreamItem::Data`, content a `Value`) and the same item typed,
//! as a binary framing would carry it (postcard cannot carry a `Value` or
//! an internally tagged enum: a binary framing needs the typed item).
//! Synthetic data, in the shapes `tickets.health`, a 1 KB item and a
//! `tickets.list --summary` row take on the wire.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Meta {
    pub provenance: Vec<String>,
    pub plexus_hash: String,
    pub timestamp: i64,
}

/// The typed item: externally tagged, every codec carries it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Item<T> {
    pub metadata: Meta,
    pub content_type: String,
    pub content: T,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Health {
    pub version: String,
    pub unix_now: i64,
    pub ticket_count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Blob {
    pub n: u64,
    pub pad: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Placement {
    pub n: u32,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    pub address: String,
    pub blocked_by: Vec<String>,
    pub child_count: u64,
    pub commits: Vec<String>,
    pub created_unix: i64,
    pub epic: String,
    pub id: String,
    pub kind: String,
    pub labels: Vec<String>,
    pub parent: Option<String>,
    pub placement: Placement,
    pub seq: u32,
    pub severity: Option<String>,
    pub shortcode: String,
    pub status: String,
    pub title: String,
    pub unlocks: Vec<String>,
    pub updated_unix: i64,
}

fn meta(p: &str) -> Meta {
    Meta { provenance: vec![p.into()], plexus_hash: "ff99be732d253f90".into(), timestamp: 0 }
}

pub fn health() -> Item<Health> {
    Item { metadata: meta("tickets"), content_type: "tickets.health".into(), content: Health { version: "0.6.2".into(), unix_now: 1_793_258_669, ticket_count: 1518 } }
}

pub fn blob(size: usize) -> Item<Blob> {
    Item { metadata: meta("bench"), content_type: "bench.count".into(), content: Blob { n: 4242, pad: "x".repeat(size) } }
}

pub fn summary() -> Item<Summary> {
    Item {
        metadata: meta("tickets"),
        content_type: "tickets.list".into(),
        content: Summary {
            address: "acme:KILN/GLAZE-11".into(),
            blocked_by: vec!["GLAZE-7".into(), "GLAZE-9".into()],
            child_count: 6,
            commits: vec!["kiln@77df9a0".into()],
            created_unix: 1_788_665_667,
            epic: "GLAZE".into(),
            id: "GLAZE-11".into(),
            kind: "build".into(),
            labels: vec!["needs-you".into()],
            parent: Some("GLAZE-2".into()),
            placement: Placement { n: 3, kind: "wave".into() },
            seq: 11,
            severity: None,
            shortcode: "GLAZE".into(),
            status: "Ready".into(),
            title: "Glaze recipes keyed by cone, with the firing schedule each one needs".into(),
            unlocks: vec!["GLAZE-12".into()],
            updated_unix: 1_792_071_009,
        },
    }
}

/// The wire's JSON of a typed item: `{"type":"data", metadata, content_type,
/// content: {"type": <tag>, …}}` — what `PlexusStreamItem::Data` serializes to.
pub fn wire_json<T: Serialize>(item: &Item<T>, tag: &str) -> Vec<u8> {
    let mut content = serde_json::to_value(&item.content).unwrap();
    if let serde_json::Value::Object(m) = &mut content {
        m.insert("type".into(), tag.into());
    }
    let v = plexus_core::plexus::PlexusStreamItem::Data {
        metadata: plexus_core::plexus::StreamMetadata {
            provenance: item.metadata.provenance.clone(),
            plexus_hash: item.metadata.plexus_hash.clone(),
            timestamp: item.metadata.timestamp,
        },
        content_type: item.content_type.clone(),
        content,
    };
    serde_json::to_vec(&v).unwrap()
}
