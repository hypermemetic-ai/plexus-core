//! PERF-9: msgpack, written the way serde_json writes JSON (spec/13).
//!
//! A msgpack frame is the JSON-RPC frame's object as a msgpack map, member
//! for member, its field names kept: decoded, it is equal as JSON to the JSON
//! frame it stands for. So the values here are serde's data model as
//! serde_json reads it, put onto msgpack's formats:
//!
//! | serde | msgpack (as JSON has it) |
//! | -- | -- |
//! | a struct, a struct variant's fields | a map keyed by the field names (rmp-serde's `with_struct_map`) |
//! | an internally tagged enum | its `type` member, as in JSON |
//! | an integer | the smallest int form that holds it |
//! | `f64` | float 64; not finite: nil (serde_json writes `null`) |
//! | `f32` | float 64 of its shortest decimal, which is the number JSON reads back |
//! | a map key | a str: an integer, a bool or a char key written as JSON writes it |
//! | `()`, a unit struct, `None` | nil |
//! | bytes | an array of integers, as serde_json writes them |
//! | a unit variant · a newtype, tuple or struct variant | its name · a one-entry map `{name: value}` |
//! | serde_json's `RawValue` | the JSON it holds, as msgpack |
//!
//! rmp-serde's serializer departs from that in four places — a unit struct
//! as `[]`, an integer map key as an integer, bytes as `bin`, `i128` as
//! `bin` — and is not human-readable unless told (a `Uuid` would go as 16
//! bytes), so frames are written by this module, onto msgpack's own formats.
//! They are read by rmp-serde, into a `Value` ([`to_value`]), so a typed
//! decode ([`from_slice`]) reads as a JSON one does.
//!
//! [`frame_from_json`] and [`frame_to_json`] carry a frame across (its
//! `jsonrpc` left out, and put back): the method table's own frames, which
//! are JSON text, and a call that arrives in msgpack, whose params cross to
//! the method table as JSON text.

use std::cell::Cell;
use std::fmt;

use bytes::BufMut;
use serde::ser::{self, Serialize};
use serde_json::Value;

/// An encode or decode that failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(String);

impl Error {
    fn new(why: impl Into<String>) -> Self {
        Error(why.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "msgpack: {}", self.0)
    }
}

impl std::error::Error for Error {}

impl ser::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Error(msg.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error(format!("json: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// `value` as msgpack, appended to `out`.
pub fn write<B: BufMut, T: ?Sized + Serialize>(out: &mut B, value: &T) -> Result<(), Error> {
    let _on = Writing::on();
    value.serialize(&mut Serializer { out, raw: false })
}

/// `value` as msgpack.
pub fn to_vec<T: ?Sized + Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(128);
    write(&mut out, value)?;
    Ok(out)
}

thread_local! {
    /// This module's serializer is at work on this thread.
    static WRITING: Cell<u32> = const { Cell::new(0) };
}

/// Whether the serializer at work on this thread is this module's (so an
/// encoded [`Content`](super::wire::Content) or a [`Shared`](super::wire::Shared)
/// event may hand it msgpack bytes as they are, through [`Raw`]).
pub(crate) fn writing() -> bool {
    WRITING.with(|w| w.get() > 0)
}

struct Writing;

impl Writing {
    fn on() -> Self {
        WRITING.with(|w| w.set(w.get() + 1));
        Writing
    }
}

impl Drop for Writing {
    fn drop(&mut self) {
        WRITING.with(|w| w.set(w.get().saturating_sub(1)));
    }
}

/// The newtype name under which [`Raw`] hands this serializer bytes that are
/// already msgpack.
const RAW_TOKEN: &str = "$plexus::msgpack::Raw";
/// serde_json's `RawValue` serializes as a struct of this name.
const JSON_RAW_TOKEN: &str = "$serde_json::private::RawValue";

/// One msgpack value's bytes, written as they are — only while [`writing`]
/// (any other serializer would see bytes).
pub(crate) struct Raw<'a>(pub(crate) &'a [u8]);

impl Serialize for Raw<'_> {
    fn serialize<S: ser::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        struct Bytes<'a>(&'a [u8]);
        impl Serialize for Bytes<'_> {
            fn serialize<S: ser::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_bytes(self.0)
            }
        }
        s.serialize_newtype_struct(RAW_TOKEN, &Bytes(self.0))
    }
}

pub(crate) fn put_nil<B: BufMut>(out: &mut B) {
    out.put_u8(0xc0);
}

fn put_bool<B: BufMut>(out: &mut B, v: bool) {
    out.put_u8(if v { 0xc3 } else { 0xc2 });
}

pub(crate) fn put_uint<B: BufMut>(out: &mut B, v: u64) {
    if v < 0x80 {
        out.put_u8(v as u8);
    } else if v <= u8::MAX as u64 {
        out.put_u8(0xcc);
        out.put_u8(v as u8);
    } else if v <= u16::MAX as u64 {
        out.put_u8(0xcd);
        out.put_u16(v as u16);
    } else if v <= u32::MAX as u64 {
        out.put_u8(0xce);
        out.put_u32(v as u32);
    } else {
        out.put_u8(0xcf);
        out.put_u64(v);
    }
}

fn put_int<B: BufMut>(out: &mut B, v: i64) {
    if v >= 0 {
        put_uint(out, v as u64);
    } else if v >= -32 {
        out.put_u8(v as i8 as u8);
    } else if v >= i8::MIN as i64 {
        out.put_u8(0xd0);
        out.put_i8(v as i8);
    } else if v >= i16::MIN as i64 {
        out.put_u8(0xd1);
        out.put_i16(v as i16);
    } else if v >= i32::MIN as i64 {
        out.put_u8(0xd2);
        out.put_i32(v as i32);
    } else {
        out.put_u8(0xd3);
        out.put_i64(v);
    }
}

fn put_f64<B: BufMut>(out: &mut B, v: f64) {
    if v.is_finite() {
        out.put_u8(0xcb);
        out.put_f64(v);
    } else {
        put_nil(out);
    }
}

pub(crate) fn put_str<B: BufMut>(out: &mut B, s: &str) {
    let n = s.len();
    if n < 32 {
        out.put_u8(0xa0 | n as u8);
    } else if n <= u8::MAX as usize {
        out.put_u8(0xd9);
        out.put_u8(n as u8);
    } else if n <= u16::MAX as usize {
        out.put_u8(0xda);
        out.put_u16(n as u16);
    } else {
        out.put_u8(0xdb);
        out.put_u32(n as u32);
    }
    out.put_slice(s.as_bytes());
}

fn put_array_len<B: BufMut>(out: &mut B, n: usize) -> Result<(), Error> {
    if n < 16 {
        out.put_u8(0x90 | n as u8);
    } else if n <= u16::MAX as usize {
        out.put_u8(0xdc);
        out.put_u16(n as u16);
    } else if n <= u32::MAX as usize {
        out.put_u8(0xdd);
        out.put_u32(n as u32);
    } else {
        return Err(Error::new("an array longer than 2^32 - 1"));
    }
    Ok(())
}

pub(crate) fn put_map_len<B: BufMut>(out: &mut B, n: usize) -> Result<(), Error> {
    if n < 16 {
        out.put_u8(0x80 | n as u8);
    } else if n <= u16::MAX as usize {
        out.put_u8(0xde);
        out.put_u16(n as u16);
    } else if n <= u32::MAX as usize {
        out.put_u8(0xdf);
        out.put_u32(n as u32);
    } else {
        return Err(Error::new("a map longer than 2^32 - 1"));
    }
    Ok(())
}

/// The serializer: serde's data model, as serde_json reads it, onto msgpack.
pub struct Serializer<'a, B> {
    out: &'a mut B,
    /// The next bytes are msgpack already ([`Raw`]).
    raw: bool,
}

/// A compound value: its count written ahead (the count must be kept), or
/// gathered first when it is not known (a flattened struct, an iterator).
pub enum Compound<'s, 'a, B> {
    Known { ser: &'s mut Serializer<'a, B>, left: usize },
    Gathered { ser: &'s mut Serializer<'a, B>, buf: Vec<u8>, n: usize, map: bool },
    /// serde_json's `RawValue`: its JSON, as msgpack.
    RawJson { ser: &'s mut Serializer<'a, B> },
}

impl<'s, 'a, B: BufMut> Compound<'s, 'a, B> {
    fn element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        match self {
            Compound::Known { ser, left } => {
                *left = left.checked_sub(1).ok_or_else(|| Error::new("more elements than the length said"))?;
                value.serialize(&mut **ser)
            }
            Compound::Gathered { buf, n, .. } => {
                *n += 1;
                value.serialize(&mut Serializer { out: buf, raw: false })
            }
            Compound::RawJson { .. } => Err(Error::new("a raw JSON value has one field")),
        }
    }

    fn key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), Error> {
        match self {
            Compound::Known { ser, left } => {
                *left = left.checked_sub(1).ok_or_else(|| Error::new("more entries than the length said"))?;
                key.serialize(MapKey { out: &mut *ser.out })
            }
            Compound::Gathered { buf, n, .. } => {
                *n += 1;
                key.serialize(MapKey { out: buf })
            }
            Compound::RawJson { .. } => Err(Error::new("a raw JSON value has one field")),
        }
    }

    fn value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        match self {
            Compound::Known { ser, .. } => value.serialize(&mut **ser),
            Compound::Gathered { buf, .. } => value.serialize(&mut Serializer { out: buf, raw: false }),
            Compound::RawJson { .. } => Err(Error::new("a raw JSON value has one field")),
        }
    }

    fn field<T: ?Sized + Serialize>(&mut self, name: &'static str, value: &T) -> Result<(), Error> {
        if let Compound::RawJson { ser } = self {
            // serde_json's RawValue: its one field is the JSON text.
            let text = match serde_json::to_value(value)? {
                Value::String(s) => s,
                _ => return Err(Error::new("a raw JSON value that is not text")),
            };
            let parsed: Value = serde_json::from_str(&text)?;
            return parsed.serialize(&mut **ser);
        }
        self.key(name)?;
        self.value(value)
    }

    fn finish(self) -> Result<(), Error> {
        match self {
            Compound::Known { left: 0, .. } | Compound::RawJson { .. } => Ok(()),
            Compound::Known { left, .. } => Err(Error::new(format!("{left} fewer entries than the length said"))),
            Compound::Gathered { ser, buf, n, map } => {
                if map {
                    put_map_len(ser.out, n)?;
                } else {
                    put_array_len(ser.out, n)?;
                }
                ser.out.put_slice(&buf);
                Ok(())
            }
        }
    }
}

macro_rules! compound_impl {
    ($trait:ident, $method:ident) => {
        impl<'s, 'a, B: BufMut> ser::$trait for Compound<'s, 'a, B> {
            type Ok = ();
            type Error = Error;
            fn $method<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
                self.element(value)
            }
            fn end(self) -> Result<(), Error> {
                self.finish()
            }
        }
    };
}

compound_impl!(SerializeSeq, serialize_element);
compound_impl!(SerializeTuple, serialize_element);
compound_impl!(SerializeTupleStruct, serialize_field);
compound_impl!(SerializeTupleVariant, serialize_field);

impl<'s, 'a, B: BufMut> ser::SerializeMap for Compound<'s, 'a, B> {
    type Ok = ();
    type Error = Error;
    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), Error> {
        self.key(key)
    }
    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        self.value(value)
    }
    fn end(self) -> Result<(), Error> {
        self.finish()
    }
}

impl<'s, 'a, B: BufMut> ser::SerializeStruct for Compound<'s, 'a, B> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, key: &'static str, value: &T) -> Result<(), Error> {
        self.field(key, value)
    }
    fn end(self) -> Result<(), Error> {
        self.finish()
    }
}

impl<'s, 'a, B: BufMut> ser::SerializeStructVariant for Compound<'s, 'a, B> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, key: &'static str, value: &T) -> Result<(), Error> {
        self.field(key, value)
    }
    fn end(self) -> Result<(), Error> {
        self.finish()
    }
}

impl<'s, 'a, B: BufMut> ser::Serializer for &'s mut Serializer<'a, B> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = Compound<'s, 'a, B>;
    type SerializeTuple = Compound<'s, 'a, B>;
    type SerializeTupleStruct = Compound<'s, 'a, B>;
    type SerializeTupleVariant = Compound<'s, 'a, B>;
    type SerializeMap = Compound<'s, 'a, B>;
    type SerializeStruct = Compound<'s, 'a, B>;
    type SerializeStructVariant = Compound<'s, 'a, B>;

    fn is_human_readable(&self) -> bool {
        true
    }

    fn serialize_bool(self, v: bool) -> Result<(), Error> {
        put_bool(self.out, v);
        Ok(())
    }
    fn serialize_i8(self, v: i8) -> Result<(), Error> {
        put_int(self.out, v as i64);
        Ok(())
    }
    fn serialize_i16(self, v: i16) -> Result<(), Error> {
        put_int(self.out, v as i64);
        Ok(())
    }
    fn serialize_i32(self, v: i32) -> Result<(), Error> {
        put_int(self.out, v as i64);
        Ok(())
    }
    fn serialize_i64(self, v: i64) -> Result<(), Error> {
        put_int(self.out, v);
        Ok(())
    }
    fn serialize_i128(self, v: i128) -> Result<(), Error> {
        if let Ok(u) = u64::try_from(v) {
            put_uint(self.out, u);
        } else if let Ok(i) = i64::try_from(v) {
            put_int(self.out, i);
        } else {
            return Err(Error::new("an integer outside 64 bits"));
        }
        Ok(())
    }
    fn serialize_u8(self, v: u8) -> Result<(), Error> {
        put_uint(self.out, v as u64);
        Ok(())
    }
    fn serialize_u16(self, v: u16) -> Result<(), Error> {
        put_uint(self.out, v as u64);
        Ok(())
    }
    fn serialize_u32(self, v: u32) -> Result<(), Error> {
        put_uint(self.out, v as u64);
        Ok(())
    }
    fn serialize_u64(self, v: u64) -> Result<(), Error> {
        put_uint(self.out, v);
        Ok(())
    }
    fn serialize_u128(self, v: u128) -> Result<(), Error> {
        let u = u64::try_from(v).map_err(|_| Error::new("an integer outside 64 bits"))?;
        put_uint(self.out, u);
        Ok(())
    }
    fn serialize_f32(self, v: f32) -> Result<(), Error> {
        // JSON writes an f32 as its shortest decimal, which reads back as
        // this f64 — the number a JSON reader has.
        if v.is_finite() {
            let as_json = v.to_string().parse::<f64>().unwrap_or(v as f64);
            put_f64(self.out, as_json);
        } else {
            put_nil(self.out);
        }
        Ok(())
    }
    fn serialize_f64(self, v: f64) -> Result<(), Error> {
        put_f64(self.out, v);
        Ok(())
    }
    fn serialize_char(self, v: char) -> Result<(), Error> {
        let mut b = [0u8; 4];
        put_str(self.out, v.encode_utf8(&mut b));
        Ok(())
    }
    fn serialize_str(self, v: &str) -> Result<(), Error> {
        put_str(self.out, v);
        Ok(())
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<(), Error> {
        if std::mem::take(&mut self.raw) {
            self.out.put_slice(v);
            return Ok(());
        }
        // As serde_json writes bytes: an array of integers.
        put_array_len(self.out, v.len())?;
        for b in v {
            put_uint(self.out, *b as u64);
        }
        Ok(())
    }
    fn serialize_none(self) -> Result<(), Error> {
        put_nil(self.out);
        Ok(())
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<(), Error> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<(), Error> {
        put_nil(self.out);
        Ok(())
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), Error> {
        put_nil(self.out);
        Ok(())
    }
    fn serialize_unit_variant(self, _name: &'static str, _index: u32, variant: &'static str) -> Result<(), Error> {
        put_str(self.out, variant);
        Ok(())
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(self, name: &'static str, value: &T) -> Result<(), Error> {
        if name == RAW_TOKEN {
            self.raw = true;
            let r = value.serialize(&mut *self);
            self.raw = false;
            return r;
        }
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(self, _name: &'static str, _index: u32, variant: &'static str, value: &T) -> Result<(), Error> {
        put_map_len(self.out, 1)?;
        put_str(self.out, variant);
        value.serialize(self)
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        match len {
            Some(n) => {
                put_array_len(self.out, n)?;
                Ok(Compound::Known { ser: self, left: n })
            }
            None => Ok(Compound::Gathered { ser: self, buf: Vec::new(), n: 0, map: false }),
        }
    }
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Error> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_struct(self, _name: &'static str, len: usize) -> Result<Self::SerializeTupleStruct, Error> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_variant(self, _name: &'static str, _index: u32, variant: &'static str, len: usize) -> Result<Self::SerializeTupleVariant, Error> {
        put_map_len(self.out, 1)?;
        put_str(self.out, variant);
        self.serialize_seq(Some(len))
    }
    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Error> {
        match len {
            Some(n) => {
                put_map_len(self.out, n)?;
                Ok(Compound::Known { ser: self, left: n })
            }
            None => Ok(Compound::Gathered { ser: self, buf: Vec::new(), n: 0, map: true }),
        }
    }
    fn serialize_struct(self, name: &'static str, len: usize) -> Result<Self::SerializeStruct, Error> {
        if name == JSON_RAW_TOKEN {
            return Ok(Compound::RawJson { ser: self });
        }
        self.serialize_map(Some(len))
    }
    fn serialize_struct_variant(self, _name: &'static str, _index: u32, variant: &'static str, len: usize) -> Result<Self::SerializeStructVariant, Error> {
        put_map_len(self.out, 1)?;
        put_str(self.out, variant);
        self.serialize_map(Some(len))
    }
}

/// A map key, written as serde_json writes one: a str, with an integer, a
/// bool or a char key in its JSON spelling.
struct MapKey<'a, B> {
    out: &'a mut B,
}

fn key_must_be_a_string() -> Error {
    Error::new("a map key must be a string (as in JSON)")
}

impl<'a, B: BufMut> MapKey<'a, B> {
    fn text(self, s: &str) -> Result<(), Error> {
        put_str(self.out, s);
        Ok(())
    }
}

impl<'a, B: BufMut> ser::Serializer for MapKey<'a, B> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = ser::Impossible<(), Error>;
    type SerializeTuple = ser::Impossible<(), Error>;
    type SerializeTupleStruct = ser::Impossible<(), Error>;
    type SerializeTupleVariant = ser::Impossible<(), Error>;
    type SerializeMap = ser::Impossible<(), Error>;
    type SerializeStruct = ser::Impossible<(), Error>;
    type SerializeStructVariant = ser::Impossible<(), Error>;

    fn is_human_readable(&self) -> bool {
        true
    }
    fn serialize_bool(self, v: bool) -> Result<(), Error> {
        self.text(if v { "true" } else { "false" })
    }
    fn serialize_i8(self, v: i8) -> Result<(), Error> {
        self.text(&v.to_string())
    }
    fn serialize_i16(self, v: i16) -> Result<(), Error> {
        self.text(&v.to_string())
    }
    fn serialize_i32(self, v: i32) -> Result<(), Error> {
        self.text(&v.to_string())
    }
    fn serialize_i64(self, v: i64) -> Result<(), Error> {
        self.text(&v.to_string())
    }
    fn serialize_i128(self, v: i128) -> Result<(), Error> {
        self.text(&v.to_string())
    }
    fn serialize_u8(self, v: u8) -> Result<(), Error> {
        self.text(&v.to_string())
    }
    fn serialize_u16(self, v: u16) -> Result<(), Error> {
        self.text(&v.to_string())
    }
    fn serialize_u32(self, v: u32) -> Result<(), Error> {
        self.text(&v.to_string())
    }
    fn serialize_u64(self, v: u64) -> Result<(), Error> {
        self.text(&v.to_string())
    }
    fn serialize_u128(self, v: u128) -> Result<(), Error> {
        self.text(&v.to_string())
    }
    fn serialize_f32(self, v: f32) -> Result<(), Error> {
        if !v.is_finite() {
            return Err(Error::new("a float map key must be finite"));
        }
        self.text(&serde_json::to_string(&v)?)
    }
    fn serialize_f64(self, v: f64) -> Result<(), Error> {
        if !v.is_finite() {
            return Err(Error::new("a float map key must be finite"));
        }
        self.text(&serde_json::to_string(&v)?)
    }
    fn serialize_char(self, v: char) -> Result<(), Error> {
        let mut b = [0u8; 4];
        self.text(v.encode_utf8(&mut b))
    }
    fn serialize_str(self, v: &str) -> Result<(), Error> {
        self.text(v)
    }
    fn serialize_bytes(self, _v: &[u8]) -> Result<(), Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_none(self) -> Result<(), Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_some<T: ?Sized + Serialize>(self, _value: &T) -> Result<(), Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_unit(self) -> Result<(), Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_unit_variant(self, _name: &'static str, _index: u32, variant: &'static str) -> Result<(), Error> {
        self.text(variant)
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(self, _name: &'static str, value: &T) -> Result<(), Error> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(self, _name: &'static str, _index: u32, _variant: &'static str, _value: &T) -> Result<(), Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_tuple_struct(self, _name: &'static str, _len: usize) -> Result<Self::SerializeTupleStruct, Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_tuple_variant(self, _name: &'static str, _index: u32, _variant: &'static str, _len: usize) -> Result<Self::SerializeTupleVariant, Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Self::SerializeStruct, Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_struct_variant(self, _name: &'static str, _index: u32, _variant: &'static str, _len: usize) -> Result<Self::SerializeStructVariant, Error> {
        Err(key_must_be_a_string())
    }
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// One msgpack value (the whole of `bytes`) as a `Value`. A `bin`, an `ext`
/// and a non-str map key are refused: they are not part of the wire
/// (spec/13).
pub fn to_value(bytes: &[u8]) -> Result<Value, Error> {
    use serde::Deserialize;
    let mut de = rmp_serde::Deserializer::new(std::io::Cursor::new(bytes)).with_human_readable();
    let v = Value::deserialize(&mut de).map_err(|e| Error::new(e.to_string()))?;
    let read = de.get_ref().position() as usize;
    if read != bytes.len() {
        return Err(Error::new(format!("{} bytes after the value", bytes.len() - read)));
    }
    Ok(v)
}

/// One msgpack value as `T`, read as a JSON reader reads it (through its
/// `Value`: a map's str keys read as integer keys, as in JSON).
pub fn from_slice<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    let v = to_value(bytes)?;
    T::deserialize(v).map_err(Error::from)
}

// ---------------------------------------------------------------------------
// Frames across: JSON text ↔ msgpack
// ---------------------------------------------------------------------------

/// A JSON-RPC frame's text as its msgpack frame: the same object as a map,
/// without `jsonrpc` (spec/13). A batch (an array) is each of its objects so.
pub fn frame_from_json(json: &[u8]) -> Result<Vec<u8>, Error> {
    let mut v: Value = serde_json::from_slice(json)?;
    match &mut v {
        Value::Object(m) => {
            m.remove("jsonrpc");
        }
        Value::Array(items) => {
            for m in items.iter_mut().filter_map(Value::as_object_mut) {
                m.remove("jsonrpc");
            }
        }
        _ => {}
    }
    to_vec(&v)
}

/// A msgpack frame as its JSON-RPC text, `jsonrpc` put back (what the method
/// table reads). A batch (an array) is each of its maps so.
pub fn frame_to_json(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut v = to_value(bytes)?;
    let two = || Value::String("2.0".into());
    match &mut v {
        Value::Object(m) => {
            m.insert("jsonrpc".into(), two());
        }
        Value::Array(items) => {
            for m in items.iter_mut().filter_map(Value::as_object_mut) {
                m.insert("jsonrpc".into(), two());
            }
        }
        _ => return Err(Error::new("a frame is a map (or a batch: an array of maps)")),
    }
    Ok(serde_json::to_vec(&v)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use std::collections::{BTreeMap, HashMap};

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
    }

    fn round(v: &Value) -> Value {
        to_value(&to_vec(v).unwrap()).unwrap()
    }

    #[test]
    fn spec_13s_frames_byte_for_byte() {
        // The map's members in serde_json's `Value` order (sorted, no
        // preserve_order): `id`, `method`, `params` — the order spec/13's hex has.
        let call = frame_from_json(br#"{"jsonrpc":"2.0","id":3,"method":"menger.call","params":{"method":"tickets.health","params":{}}}"#).unwrap();
        assert_eq!(hex(&call), "83 a2 69 64 03 a6 6d 65 74 68 6f 64 ab 6d 65 6e 67 65 72 2e 63 61 6c 6c a6 70 61 72 61 6d 73 82 a6 6d 65 74 68 6f 64 ae 74 69 63 6b 65 74 73 2e 68 65 61 6c 74 68 a6 70 61 72 61 6d 73 80");
        let answer = frame_from_json(br#"{"jsonrpc":"2.0","id":3,"result":7}"#).unwrap();
        assert_eq!(hex(&answer), "82 a2 69 64 03 a6 72 65 73 75 6c 74 07");
        assert_eq!(frame_to_json(&answer).unwrap(), br#"{"id":3,"jsonrpc":"2.0","result":7}"#.to_vec());
    }

    #[test]
    fn integers_take_their_smallest_form() {
        let cases: &[(i128, &str)] = &[
            (0, "00"),
            (127, "7f"),
            (128, "cc 80"),
            (255, "cc ff"),
            (256, "cd 01 00"),
            (65535, "cd ff ff"),
            (65536, "ce 00 01 00 00"),
            (4294967295, "ce ff ff ff ff"),
            (4294967296, "cf 00 00 00 01 00 00 00 00"),
            (-1, "ff"),
            (-32, "e0"),
            (-33, "d0 df"),
            (-128, "d0 80"),
            (-129, "d1 ff 7f"),
            (-32768, "d1 80 00"),
            (-32769, "d2 ff ff 7f ff"),
            (-2147483649, "d3 ff ff ff ff 7f ff ff ff"),
        ];
        for (n, want) in cases {
            let got = if *n >= 0 { to_vec(&(*n as u64)).unwrap() } else { to_vec(&(*n as i64)).unwrap() };
            assert_eq!(hex(&got), *want, "{n}");
            assert_eq!(to_vec(&(*n as i64)).unwrap(), got, "{n} the same signed or not");
        }
    }

    #[test]
    fn values_round_trip_as_json() {
        let v = json!({
            "null": null, "t": true, "f": false, "n": -7, "big": u64::MAX, "neg": i64::MIN, "x": 1.5, "whole": 40.0,
            "s": "a \"quoted\" \u{1F600} line\nbreak", "long": "x".repeat(300), "arr": [1, "two", [3], {"four": 4}],
            "deep": {"a": {"b": {"c": [null, {"d": "e"}]}}}, "many": (0..40).map(|i| json!(i)).collect::<Vec<_>>(),
        });
        assert_eq!(round(&v), v);
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Unit;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    #[serde(tag = "type", rename_all = "snake_case")]
    enum Event {
        Said { text: String, #[serde(skip_serializing_if = "Option::is_none")] lang: Option<String> },
        Fields { #[serde(flatten)] extra: BTreeMap<String, Value>, n: u32 },
        Any { value: Value },
        Nothing,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    enum Plain {
        A,
        B(u32),
        C(u8, u8),
        D { x: i32 },
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Shapes {
        unit: Unit,
        ratio: f32,
        bytes: Vec<u8>,
        by_number: HashMap<u32, String>,
        by_bool: BTreeMap<bool, u8>,
        plain: Vec<Plain>,
        id: uuid::Uuid,
        when: chrono::DateTime<chrono::Utc>,
        /// Not finite: `null`, as serde_json writes it (an `Option` so it reads back).
        nan: Option<f64>,
        events: Vec<Event>,
    }

    #[test]
    fn serde_shapes_go_as_json_has_them() {
        let s = Shapes {
            unit: Unit,
            ratio: 33.3,
            bytes: vec![0, 1, 255],
            by_number: HashMap::from([(7, "seven".into())]),
            by_bool: BTreeMap::from([(true, 1)]),
            plain: vec![Plain::A, Plain::B(2), Plain::C(3, 4), Plain::D { x: -5 }],
            id: uuid::Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
            when: chrono::DateTime::from_timestamp(1_793_254_659, 0).unwrap(),
            nan: Some(f64::NAN),
            events: vec![
                Event::Said { text: "hi".into(), lang: None },
                Event::Said { text: "hi".into(), lang: Some("en".into()) },
                Event::Fields { extra: BTreeMap::from([("kind".into(), json!("x")), ("deep".into(), json!({"a": [1]}))]), n: 3 },
                Event::Any { value: json!({"any": ["json", 1, null, {"x": 2.5}]}) },
                Event::Nothing,
            ],
        };
        // The JSON a reader reads: the text, parsed (serde_json's `to_value`
        // widens an f32 without its shortest decimal; its text does not).
        let as_json: Value = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        let bytes = to_vec(&s).unwrap();
        // Equal as JSON, read with this module …
        assert_eq!(to_value(&bytes).unwrap(), as_json);
        // … and with rmp-serde's own reader into a Value, and back into the type.
        let theirs: Value = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(theirs, as_json);
        let back: Shapes = from_slice(&bytes).unwrap();
        assert_eq!(back.events, s.events);
        assert_eq!(back.by_number, s.by_number);
        assert_eq!(back.id, s.id);
        assert_eq!(back.bytes, s.bytes);
        // A field skipped when empty is absent, as in JSON; a flattened one is a member.
        assert_eq!(as_json["events"][0], json!({"type": "said", "text": "hi"}));
        assert_eq!(as_json["events"][2]["kind"], "x");
        assert_eq!(as_json["nan"], Value::Null);
    }

    #[test]
    fn a_count_that_lies_is_an_error_not_a_frame() {
        struct Liar;
        impl Serialize for Liar {
            fn serialize<S: ser::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                use ser::SerializeStruct;
                let mut st = s.serialize_struct("Liar", 2)?;
                st.serialize_field("one", &1)?;
                st.end()
            }
        }
        assert!(to_vec(&Liar).is_err());
    }

    #[test]
    fn a_raw_value_is_its_json() {
        let raw = serde_json::value::RawValue::from_string(r#"{"b":[1,2],"a":"x"}"#.into()).unwrap();
        assert_eq!(to_value(&to_vec(&json!({"r": raw})).unwrap()).unwrap(), json!({"r": {"a": "x", "b": [1, 2]}}));
    }

    #[test]
    fn off_wire_formats_and_trailing_bytes_are_refused() {
        assert!(to_value(&[0xc4, 0x01, 0x00]).is_err(), "bin");
        assert!(to_value(&[0xd4, 0x01, 0x00]).is_err(), "fixext 1");
        assert!(to_value(&[0x81, 0x01, 0x02]).is_err(), "an integer key");
        assert!(to_value(&[0x01, 0x02]).is_err(), "two values");
        assert!(to_value(&[0x92, 0x01]).is_err(), "cut short");
        assert!(frame_to_json(&[0x01]).is_err(), "a frame is a map");
        // Float 32 is read (a decoder accepts it).
        assert_eq!(to_value(&[0xca, 0x40, 0x20, 0x00, 0x00]).unwrap(), json!(2.5));
    }

    #[test]
    fn a_batch_crosses_each_object() {
        let m = frame_from_json(br#"[{"jsonrpc":"2.0","id":1,"method":"a"},{"jsonrpc":"2.0","id":2,"method":"b"}]"#).unwrap();
        assert_eq!(to_value(&m).unwrap(), json!([{"id": 1, "method": "a"}, {"id": 2, "method": "b"}]));
        let back: Value = serde_json::from_slice(&frame_to_json(&m).unwrap()).unwrap();
        assert_eq!(back, json!([{"jsonrpc": "2.0", "id": 1, "method": "a"}, {"jsonrpc": "2.0", "id": 2, "method": "b"}]));
    }
}
