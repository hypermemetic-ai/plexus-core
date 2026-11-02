//! PERF-34: an item's JSON, written by a real scan, not a byte at a time, with
//! the bytes serde_json writes.
//!
//! serde_json looks at every byte of every string through a table, and hands
//! each piece of an item to an `io::Write`: a call and two capacity checks for
//! each comma, each quote, each run. On a ticket body that is 11 instructions a
//! byte; on a row, the string scan is a third of it and the punctuation most
//! of the rest. Here one [`Json`] writes straight into the pipe's buffer:
//!
//! | what | how |
//! | -- | -- |
//! | a field's name | inlined with its field: the compiler sees the name, folds the scan, and writes a clean one as constants |
//! | a string under 16 bytes | loaded whole by two overlapping words, one compare, stored: no loop and no call |
//! | a longer one | one pass, each block stored as it is scanned ([`scan`]); a run between escapes takes no copy of its own |
//! | an x86-64 CPU | SSE2, which they all have; AVX2 where the CPU says so, at run time. No `target-cpu`: test and prod are other machines |
//! | any other | a byte at a time, as serde_json does |
//! | punctuation | room made once, then stored |
//! | a number | serde_json's own `Formatter`, so it cannot differ |
//!
//! A field's name is `&'static str`, but nothing says it is clean: `#[serde(rename
//! = "a\"b")]` is legal. So nothing is skipped at run time; the compiler does
//! the looking, and a name that needs escaping still gets its escape.
//!
//! Everything else mirrors `serde_json::ser`, state for state: an empty
//! sequence closes as it opens, a raw value's text goes as it is, a map key
//! that is no string is refused. `same_bytes_as_serde_json_*` in `wire.rs` hold
//! it to `serde_json::to_vec`, and the numbers that kept it are on PERF-34.

use std::fmt::{self, Write as _};
use std::io;
use std::num::FpCategory;

use bytes::{BufMut, BytesMut};
use serde::ser::{self, Impossible, Serialize};
use serde_json::ser::{CompactFormatter, Formatter};
use serde_json::Error;

/// serde_json's name for a raw value's one field, and for a number's when
/// `arbitrary_precision` is on: how its `Serialize` says "write this text".
const RAW_VALUE: &str = "$serde_json::private::RawValue";
const NUMBER: &str = "$serde_json::private::Number";

/// What a string's writer keeps room for past its contents: `":`, a key's end.
const AFTER: usize = 2;

/// The letter of an escape that has one: `\n`, `\"`; 0 for `\u00XX`.
const SHORT: [u8; 256] = {
    let mut short = [0; 256];
    short[b'"' as usize] = b'"';
    short[b'\\' as usize] = b'\\';
    short[0x08] = b'b';
    short[0x0C] = b'f';
    short[b'\n' as usize] = b'n';
    short[b'\r' as usize] = b'r';
    short[b'\t' as usize] = b't';
    short
};

/// `value`'s JSON at the end of `out`, the bytes `serde_json::to_writer` writes.
/// On an error (a `Serialize` refused, a key that is no string) `out` holds
/// what was written so far, as `to_writer`'s writer would.
pub(crate) fn write<T: Serialize + ?Sized>(out: &mut BytesMut, value: &T) -> Result<(), Error> {
    value.serialize(&mut Json { out })
}

struct Json<'b> {
    out: &'b mut BytesMut,
}

impl Json<'_> {
    /// Whether there is room for `n` more bytes.
    #[inline(always)]
    fn fits(&self, n: usize) -> bool {
        self.out.capacity() - self.out.len() >= n
    }

    /// Room for `n` more bytes.
    #[inline(always)]
    fn room(&mut self, n: usize) {
        if !self.fits(n) {
            self.out.reserve(n);
        }
    }

    /// Where the next byte goes.
    #[inline(always)]
    fn end(&mut self) -> *mut u8 {
        self.out.spare_capacity_mut().as_mut_ptr().cast()
    }

    /// `byte`, written.
    ///
    /// # Safety
    /// There is [`room`](Self::room) for it.
    #[inline(always)]
    unsafe fn push(&mut self, byte: u8) {
        unsafe {
            self.end().write(byte);
            self.written(1);
        }
    }

    /// `n` bytes written past the end are now the buffer's.
    ///
    /// # Safety
    /// They are, and there was room for them.
    #[inline(always)]
    unsafe fn written(&mut self, n: usize) {
        unsafe { self.out.set_len(self.out.len() + n) }
    }

    /// `s` as a JSON string. Short and clean, with room: what is here, and no
    /// call that would have it save a register.
    #[inline(never)]
    fn string(&mut self, s: &str) {
        let bytes = s.as_bytes();
        if self.fits(1 + bytes.len() + AFTER) {
            // SAFETY: there is room.
            unsafe {
                let end = self.end();
                if scan::short(bytes, end.add(1)) {
                    end.write(b'"');
                    end.add(1 + bytes.len()).write(b'"');
                    self.written(1 + bytes.len() + 1);
                    return;
                }
            }
        }
        self.long_string(bytes);
    }

    /// `bytes` as a JSON string, any length, any contents.
    #[inline(never)]
    fn long_string(&mut self, bytes: &[u8]) {
        self.room(1 + bytes.len() + AFTER);
        // SAFETY: the room just made, which `contents` keeps.
        unsafe {
            self.push(b'"');
            self.contents(bytes);
            self.push(b'"');
        }
    }

    /// A field's name and what is around it: `,"key":`, or `"key":` after `{`.
    /// Inlined with the field, so the compiler sees the name: it folds the
    /// scan away and writes a clean one as constants. Nothing is looked at
    /// when the service runs, and a name that needs escaping still is.
    #[inline(always)]
    fn key(&mut self, comma: bool, key: &str) {
        let bytes = key.as_bytes();
        if self.fits(2 + bytes.len() + AFTER) {
            let start = comma as usize + 1;
            // SAFETY: there is room.
            unsafe {
                let end = self.end();
                if scan::short(bytes, end.add(start)) {
                    end.write(b',');
                    end.add(start - 1).write(b'"');
                    end.add(start + bytes.len()).cast::<[u8; 2]>().write_unaligned(*b"\":");
                    self.written(start + bytes.len() + 2);
                    return;
                }
            }
        }
        self.long_key(comma, bytes);
    }

    /// [`key`](Self::key), any length, any contents.
    #[inline(never)]
    fn long_key(&mut self, comma: bool, bytes: &[u8]) {
        self.room(2 + bytes.len() + AFTER);
        // SAFETY: the room just made, which `contents` keeps.
        unsafe {
            if comma {
                self.push(b',');
            }
            self.push(b'"');
            self.contents(bytes);
            self.push(b'"');
            self.push(b':');
        }
    }

    /// `bytes` between the quotes: each run up to an escape copied as it is
    /// scanned, so a string with none is one pass.
    ///
    /// # Safety
    /// There is room for all of `bytes` and for [`AFTER`] bytes more, and
    /// there still is for those when it returns.
    #[inline(never)]
    unsafe fn contents(&mut self, mut bytes: &[u8]) {
        loop {
            // SAFETY: there is room for `bytes`, as the caller says and each pass makes sure.
            let run = unsafe { scan::copy_clean(bytes, self.end()) };
            // SAFETY: `copy_clean` wrote that many.
            unsafe { self.written(run) };
            let (_, rest) = bytes.split_at(run);
            let Some((&byte, rest)) = rest.split_first() else { return };
            // at most 6 bytes for this one, then what is left and what follows it
            self.room(6 + rest.len() + AFTER);
            // SAFETY: the room just made.
            unsafe { self.escape(byte) };
            bytes = rest;
        }
    }

    /// `byte`, escaped.
    ///
    /// # Safety
    /// There is room for 6 bytes.
    #[inline(always)]
    unsafe fn escape(&mut self, byte: u8) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let end = self.end();
        // SAFETY: the room the caller made.
        unsafe {
            match SHORT[byte as usize] {
                0 => {
                    end.cast::<[u8; 4]>().write_unaligned(*b"\\u00");
                    end.add(4).write(HEX[(byte >> 4) as usize]);
                    end.add(5).write(HEX[(byte & 15) as usize]);
                    self.written(6);
                }
                short => {
                    end.cast::<[u8; 2]>().write_unaligned([b'\\', short]);
                    self.written(2);
                }
            }
        }
    }

    /// `{"key":`
    fn open_variant(&mut self, variant: &str) {
        self.out.put_u8(b'{');
        self.string(variant);
        self.out.put_u8(b':');
    }

    fn null(&mut self) {
        self.out.put_slice(b"null");
    }
}

/// For serde_json's `Formatter`, which writes its numbers to an `io::Write`.
impl io::Write for Json<'_> {
    #[inline]
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.out.put_slice(bytes);
        Ok(bytes.len())
    }

    #[inline]
    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.out.put_slice(bytes);
        Ok(())
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// For `collect_str`, which takes a `Display` in pieces.
impl fmt::Write for Json<'_> {
    #[inline]
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.room(s.len() + AFTER);
        // SAFETY: the room just made.
        unsafe { self.contents(s.as_bytes()) };
        Ok(())
    }
}

/// `Formatter::$write`, which cannot fail: `BytesMut` grows.
macro_rules! numbers {
    ($($serialize:ident $write:ident $t:ty;)*) => {$(
        #[inline]
        fn $serialize(self, value: $t) -> Result<(), Error> {
            let _ = CompactFormatter.$write(self, value);
            Ok(())
        }
    )*};
}

impl<'a, 'b> ser::Serializer for &'a mut Json<'b> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = Group<'a, 'b>;
    type SerializeTuple = Group<'a, 'b>;
    type SerializeTupleStruct = Group<'a, 'b>;
    type SerializeTupleVariant = Group<'a, 'b>;
    type SerializeMap = Group<'a, 'b>;
    type SerializeStruct = Group<'a, 'b>;
    type SerializeStructVariant = Group<'a, 'b>;

    numbers! {
        serialize_i8 write_i8 i8;
        serialize_i16 write_i16 i16;
        serialize_i32 write_i32 i32;
        serialize_i64 write_i64 i64;
        serialize_i128 write_i128 i128;
        serialize_u8 write_u8 u8;
        serialize_u16 write_u16 u16;
        serialize_u32 write_u32 u32;
        serialize_u64 write_u64 u64;
        serialize_u128 write_u128 u128;
    }

    #[inline]
    fn serialize_bool(self, value: bool) -> Result<(), Error> {
        self.out.put_slice(if value { b"true" } else { b"false" });
        Ok(())
    }

    #[inline]
    fn serialize_f32(self, value: f32) -> Result<(), Error> {
        match value.classify() {
            FpCategory::Nan | FpCategory::Infinite => self.null(),
            _ => drop(CompactFormatter.write_f32(self, value)),
        }
        Ok(())
    }

    #[inline]
    fn serialize_f64(self, value: f64) -> Result<(), Error> {
        match value.classify() {
            FpCategory::Nan | FpCategory::Infinite => self.null(),
            _ => drop(CompactFormatter.write_f64(self, value)),
        }
        Ok(())
    }

    #[inline]
    fn serialize_char(self, value: char) -> Result<(), Error> {
        self.string(value.encode_utf8(&mut [0u8; 4]));
        Ok(())
    }

    #[inline]
    fn serialize_str(self, value: &str) -> Result<(), Error> {
        self.string(value);
        Ok(())
    }

    fn serialize_bytes(self, value: &[u8]) -> Result<(), Error> {
        let mut seq = self.serialize_seq(Some(value.len()))?;
        for byte in value {
            ser::SerializeSeq::serialize_element(&mut seq, byte)?;
        }
        ser::SerializeSeq::end(seq)
    }

    #[inline]
    fn serialize_unit(self) -> Result<(), Error> {
        self.null();
        Ok(())
    }

    #[inline]
    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), Error> {
        self.null();
        Ok(())
    }

    #[inline]
    fn serialize_unit_variant(self, _name: &'static str, _index: u32, variant: &'static str) -> Result<(), Error> {
        self.string(variant);
        Ok(())
    }

    #[inline]
    fn serialize_newtype_struct<T: Serialize + ?Sized>(self, _name: &'static str, value: &T) -> Result<(), Error> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(self, _name: &'static str, _index: u32, variant: &'static str, value: &T) -> Result<(), Error> {
        self.open_variant(variant);
        value.serialize(&mut *self)?;
        self.out.put_u8(b'}');
        Ok(())
    }

    #[inline]
    fn serialize_none(self) -> Result<(), Error> {
        self.null();
        Ok(())
    }

    #[inline]
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<(), Error> {
        value.serialize(self)
    }

    #[inline]
    fn serialize_seq(self, len: Option<usize>) -> Result<Group<'a, 'b>, Error> {
        self.out.put_u8(b'[');
        let state = if len == Some(0) {
            self.out.put_u8(b']');
            State::Empty
        } else {
            State::First
        };
        Ok(Group::Open { json: self, state })
    }

    #[inline]
    fn serialize_tuple(self, len: usize) -> Result<Group<'a, 'b>, Error> {
        self.serialize_seq(Some(len))
    }

    #[inline]
    fn serialize_tuple_struct(self, _name: &'static str, len: usize) -> Result<Group<'a, 'b>, Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(self, _name: &'static str, _index: u32, variant: &'static str, len: usize) -> Result<Group<'a, 'b>, Error> {
        self.open_variant(variant);
        self.serialize_seq(Some(len))
    }

    #[inline]
    fn serialize_map(self, len: Option<usize>) -> Result<Group<'a, 'b>, Error> {
        self.out.put_u8(b'{');
        let state = if len == Some(0) {
            self.out.put_u8(b'}');
            State::Empty
        } else {
            State::First
        };
        Ok(Group::Open { json: self, state })
    }

    #[inline]
    fn serialize_struct(self, name: &'static str, len: usize) -> Result<Group<'a, 'b>, Error> {
        match name {
            RAW_VALUE | NUMBER => Ok(Group::Raw { json: self }),
            _ => self.serialize_map(Some(len)),
        }
    }

    fn serialize_struct_variant(self, _name: &'static str, _index: u32, variant: &'static str, len: usize) -> Result<Group<'a, 'b>, Error> {
        self.open_variant(variant);
        self.serialize_map(Some(len))
    }

    fn collect_str<T: fmt::Display + ?Sized>(self, value: &T) -> Result<(), Error> {
        self.out.put_u8(b'"');
        write!(self, "{value}").map_err(ser::Error::custom)?;
        self.out.put_u8(b'"');
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq)]
enum State {
    /// Closed as it opened: `[]` or `{}`.
    Empty,
    First,
    Rest,
}

/// serde_json's `Compound`: an open array or object, or a raw value's text.
enum Group<'a, 'b> {
    Open { json: &'a mut Json<'b>, state: State },
    Raw { json: &'a mut Json<'b> },
}

impl Group<'_, '_> {
    /// The comma before an element or a key, if one is owed.
    #[inline]
    fn next(&mut self) {
        if let Group::Open { json, state } = self {
            if *state != State::First {
                json.out.put_u8(b',');
            }
            *state = State::Rest;
        }
    }

    #[inline]
    fn close(self, with: u8) {
        if let Group::Open { json, state } = self {
            if state != State::Empty {
                json.out.put_u8(with);
            }
        }
    }

    /// A variant's group closed, and the object around it.
    fn close_variant(self, with: u8) {
        if let Group::Open { json, state } = self {
            if state != State::Empty {
                json.out.put_u8(with);
            }
            json.out.put_u8(b'}');
        }
    }
}

impl ser::SerializeSeq for Group<'_, '_> {
    type Ok = ();
    type Error = Error;

    #[inline]
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.next();
        match self {
            Group::Open { json, .. } => value.serialize(&mut **json),
            Group::Raw { .. } => unreachable!("a raw value holds one field"),
        }
    }

    #[inline]
    fn end(self) -> Result<(), Error> {
        self.close(b']');
        Ok(())
    }
}

/// `SerializeTuple`, `SerializeTupleStruct`, all a sequence.
macro_rules! a_sequence {
    ($($tr:ident $method:ident;)*) => {$(
        impl ser::$tr for Group<'_, '_> {
            type Ok = ();
            type Error = Error;

            #[inline]
            fn $method<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
                ser::SerializeSeq::serialize_element(self, value)
            }

            #[inline]
            fn end(self) -> Result<(), Error> {
                ser::SerializeSeq::end(self)
            }
        }
    )*};
}

a_sequence! {
    SerializeTuple serialize_element;
    SerializeTupleStruct serialize_field;
}

impl ser::SerializeTupleVariant for Group<'_, '_> {
    type Ok = ();
    type Error = Error;

    #[inline]
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        ser::SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<(), Error> {
        self.close_variant(b']');
        Ok(())
    }
}

impl ser::SerializeMap for Group<'_, '_> {
    type Ok = ();
    type Error = Error;

    #[inline]
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Error> {
        self.next();
        match self {
            Group::Open { json, .. } => key.serialize(Key { json }),
            Group::Raw { .. } => unreachable!("a raw value holds one field"),
        }
    }

    #[inline]
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        match self {
            Group::Open { json, .. } => {
                json.out.put_u8(b':');
                value.serialize(&mut **json)
            }
            Group::Raw { .. } => unreachable!("a raw value holds one field"),
        }
    }

    #[inline]
    fn end(self) -> Result<(), Error> {
        self.close(b'}');
        Ok(())
    }
}

impl ser::SerializeStruct for Group<'_, '_> {
    type Ok = ();
    type Error = Error;

    // always: with the name in sight, [`Json::key`] folds to constants
    #[inline(always)]
    fn serialize_field<T: Serialize + ?Sized>(&mut self, key: &'static str, value: &T) -> Result<(), Error> {
        match self {
            Group::Open { json, state } => {
                json.key(*state != State::First, key);
                *state = State::Rest;
                value.serialize(&mut **json)
            }
            Group::Raw { json } if key == RAW_VALUE || key == NUMBER => value.serialize(RawText { json }),
            Group::Raw { .. } => Err(ser::Error::custom("not a raw value")),
        }
    }

    #[inline]
    fn end(self) -> Result<(), Error> {
        self.close(b'}');
        Ok(())
    }
}

impl ser::SerializeStructVariant for Group<'_, '_> {
    type Ok = ();
    type Error = Error;

    #[inline]
    fn serialize_field<T: Serialize + ?Sized>(&mut self, key: &'static str, value: &T) -> Result<(), Error> {
        ser::SerializeStruct::serialize_field(self, key, value)
    }

    fn end(self) -> Result<(), Error> {
        self.close_variant(b'}');
        Ok(())
    }
}

/// Every `Serializer` method but the ones named, refusing what it is given.
macro_rules! refuse {
    ($why:expr; $($method:ident($($arg:ty),*);)*) => {
        $(fn $method(self, $(_: $arg),*) -> Result<(), Error> {
            Err(ser::Error::custom($why))
        })*
        fn serialize_unit_struct(self, _: &'static str) -> Result<(), Error> {
            Err(ser::Error::custom($why))
        }
        fn serialize_newtype_variant<T: Serialize + ?Sized>(self, _: &'static str, _: u32, _: &'static str, _: &T) -> Result<(), Error> {
            Err(ser::Error::custom($why))
        }
        fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, Error> {
            Err(ser::Error::custom($why))
        }
        fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, Error> {
            Err(ser::Error::custom($why))
        }
        fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Self::SerializeTupleStruct, Error> {
            Err(ser::Error::custom($why))
        }
        fn serialize_tuple_variant(self, _: &'static str, _: u32, _: &'static str, _: usize) -> Result<Self::SerializeTupleVariant, Error> {
            Err(ser::Error::custom($why))
        }
        fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, Error> {
            Err(ser::Error::custom($why))
        }
        fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self::SerializeStruct, Error> {
            Err(ser::Error::custom($why))
        }
        fn serialize_struct_variant(self, _: &'static str, _: u32, _: &'static str, _: usize) -> Result<Self::SerializeStructVariant, Error> {
            Err(ser::Error::custom($why))
        }
    };
}

const NO_KEY: &str = "key must be a string";

/// serde_json's `MapKeySerializer`: a string, or what reads as one, quoted.
struct Key<'a, 'b> {
    json: &'a mut Json<'b>,
}

/// A number or a bool as a key: its text, in quotes.
macro_rules! quoted {
    ($($serialize:ident $t:ty;)*) => {$(
        fn $serialize(self, value: $t) -> Result<(), Error> {
            self.json.out.put_u8(b'"');
            (&mut *self.json).$serialize(value)?;
            self.json.out.put_u8(b'"');
            Ok(())
        }
    )*};
}

impl ser::Serializer for Key<'_, '_> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = Impossible<(), Error>;
    type SerializeTuple = Impossible<(), Error>;
    type SerializeTupleStruct = Impossible<(), Error>;
    type SerializeTupleVariant = Impossible<(), Error>;
    type SerializeMap = Impossible<(), Error>;
    type SerializeStruct = Impossible<(), Error>;
    type SerializeStructVariant = Impossible<(), Error>;

    quoted! {
        serialize_bool bool;
        serialize_i8 i8;
        serialize_i16 i16;
        serialize_i32 i32;
        serialize_i64 i64;
        serialize_i128 i128;
        serialize_u8 u8;
        serialize_u16 u16;
        serialize_u32 u32;
        serialize_u64 u64;
        serialize_u128 u128;
    }

    fn serialize_f32(self, value: f32) -> Result<(), Error> {
        if !value.is_finite() {
            return Err(ser::Error::custom("float key must be finite"));
        }
        self.json.out.put_u8(b'"');
        let _ = CompactFormatter.write_f32(self.json, value);
        self.json.out.put_u8(b'"');
        Ok(())
    }

    fn serialize_f64(self, value: f64) -> Result<(), Error> {
        if !value.is_finite() {
            return Err(ser::Error::custom("float key must be finite"));
        }
        self.json.out.put_u8(b'"');
        let _ = CompactFormatter.write_f64(self.json, value);
        self.json.out.put_u8(b'"');
        Ok(())
    }

    fn serialize_char(self, value: char) -> Result<(), Error> {
        self.json.string(value.encode_utf8(&mut [0u8; 4]));
        Ok(())
    }

    #[inline]
    fn serialize_str(self, value: &str) -> Result<(), Error> {
        self.json.string(value);
        Ok(())
    }

    fn serialize_unit_variant(self, _name: &'static str, _index: u32, variant: &'static str) -> Result<(), Error> {
        self.json.string(variant);
        Ok(())
    }

    #[inline]
    fn serialize_newtype_struct<T: Serialize + ?Sized>(self, _name: &'static str, value: &T) -> Result<(), Error> {
        value.serialize(self)
    }

    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<(), Error> {
        value.serialize(self)
    }

    fn collect_str<T: fmt::Display + ?Sized>(self, value: &T) -> Result<(), Error> {
        ser::Serializer::collect_str(self.json, value)
    }

    refuse! { NO_KEY;
        serialize_bytes(&[u8]);
        serialize_unit();
        serialize_none();
    }
}

/// serde_json's `RawValueStrEmitter`: the one string a raw value holds, as it is.
struct RawText<'a, 'b> {
    json: &'a mut Json<'b>,
}

impl ser::Serializer for RawText<'_, '_> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = Impossible<(), Error>;
    type SerializeTuple = Impossible<(), Error>;
    type SerializeTupleStruct = Impossible<(), Error>;
    type SerializeTupleVariant = Impossible<(), Error>;
    type SerializeMap = Impossible<(), Error>;
    type SerializeStruct = Impossible<(), Error>;
    type SerializeStructVariant = Impossible<(), Error>;

    #[inline]
    fn serialize_str(self, value: &str) -> Result<(), Error> {
        self.json.out.put_slice(value.as_bytes());
        Ok(())
    }

    fn serialize_unit_variant(self, _: &'static str, _: u32, _: &'static str) -> Result<(), Error> {
        Err(ser::Error::custom(NOT_TEXT))
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(self, _: &'static str, _: &T) -> Result<(), Error> {
        Err(ser::Error::custom(NOT_TEXT))
    }

    fn serialize_some<T: Serialize + ?Sized>(self, _: &T) -> Result<(), Error> {
        Err(ser::Error::custom(NOT_TEXT))
    }

    refuse! { NOT_TEXT;
        serialize_bool(bool);
        serialize_i8(i8);
        serialize_i16(i16);
        serialize_i32(i32);
        serialize_i64(i64);
        serialize_u8(u8);
        serialize_u16(u16);
        serialize_u32(u32);
        serialize_u64(u64);
        serialize_f32(f32);
        serialize_f64(f64);
        serialize_char(char);
        serialize_bytes(&[u8]);
        serialize_unit();
        serialize_none();
    }
}

const NOT_TEXT: &str = "a raw value is text";

/// The clean run at the head of a string, found and copied in one pass.
pub(crate) mod scan {
    #[inline]
    fn escaped(byte: u8) -> bool {
        byte < 0x20 || byte == b'"' || byte == b'\\'
    }

    /// The run of `src` JSON does not escape, up to the first byte it does,
    /// copied to `dst`; its length. A store may go past the run, within
    /// `src.len()` bytes of `dst`.
    ///
    /// # Safety
    /// `dst` is good for `src.len()` bytes and does not overlap `src`.
    #[inline(always)]
    pub(crate) unsafe fn copy_clean(src: &[u8], dst: *mut u8) -> usize {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: as this function's own.
        unsafe {
            x86::copy_clean(src, dst)
        }
        #[cfg(not(target_arch = "x86_64"))]
        // SAFETY: as this function's own.
        unsafe {
            one_at_a_time(src, dst)
        }
    }

    /// Whether `src` is under 16 bytes and has nothing to escape, and if so it
    /// is copied to `dst`, with no loop. If not, what `dst` holds means nothing.
    ///
    /// # Safety
    /// `dst` is good for `src.len()` bytes and does not overlap `src`.
    #[inline(always)]
    pub(super) unsafe fn short(src: &[u8], dst: *mut u8) -> bool {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: as this function's own.
        unsafe {
            src.len() < 16 && x86::tail(src, dst) == src.len()
        }
        #[cfg(not(target_arch = "x86_64"))]
        // SAFETY: as this function's own.
        unsafe {
            src.len() < 16 && one_at_a_time(src, dst) == src.len()
        }
    }

    /// The same, a byte at a time: what is not x86-64, and the tail of what is.
    ///
    /// # Safety
    /// As [`copy_clean`].
    #[inline]
    pub(crate) unsafe fn one_at_a_time(src: &[u8], dst: *mut u8) -> usize {
        let run = src.iter().position(|&b| escaped(b)).unwrap_or(src.len());
        // SAFETY: `run` is at most `src.len()`, which the caller says `dst` is good for.
        unsafe { dst.copy_from_nonoverlapping(src.as_ptr(), run) };
        run
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) mod x86 {
        use std::arch::x86_64::*;

        /// The bytes of `block` JSON escapes, a bit each.
        #[inline(always)]
        fn hits128(block: __m128i) -> u32 {
            // SAFETY: SSE2 is every x86-64's.
            unsafe {
                let control = _mm_cmpeq_epi8(_mm_min_epu8(block, _mm_set1_epi8(0x1f)), block);
                let quote = _mm_cmpeq_epi8(block, _mm_set1_epi8(b'"' as i8));
                let backslash = _mm_cmpeq_epi8(block, _mm_set1_epi8(b'\\' as i8));
                _mm_movemask_epi8(_mm_or_si128(control, _mm_or_si128(quote, backslash))) as u32
            }
        }

        /// As [`super::copy_clean`]: AVX2 for a long string on a CPU that has it.
        ///
        /// # Safety
        /// As [`super::copy_clean`].
        #[inline(always)]
        pub(crate) unsafe fn copy_clean(src: &[u8], dst: *mut u8) -> usize {
            if src.len() >= 32 && std::is_x86_feature_detected!("avx2") {
                // SAFETY: the CPU says it has AVX2, and the rest is as this function's own.
                let (at, hit) = unsafe { avx2(src, dst) };
                if hit {
                    return at;
                }
                // SAFETY: the rest of what the caller gave, a block in.
                return at + unsafe { sse2(&src[at..], dst.add(at)) };
            }
            // SAFETY: as this function's own.
            unsafe { sse2(src, dst) }
        }

        /// The same, 16 bytes at a time, and the tail.
        ///
        /// # Safety
        /// As [`super::copy_clean`].
        #[inline(always)]
        pub(crate) unsafe fn sse2(src: &[u8], dst: *mut u8) -> usize {
            let len = src.len();
            let mut at = 0;
            while len - at >= 16 {
                // SAFETY: 16 bytes of `src` from `at`, and `dst` is good for as many.
                let hit = unsafe {
                    let block = _mm_loadu_si128(src.as_ptr().add(at).cast());
                    _mm_storeu_si128(dst.add(at).cast(), block);
                    hits128(block)
                };
                if hit != 0 {
                    return at + hit.trailing_zeros() as usize;
                }
                at += 16;
            }
            // SAFETY: fewer than 16 of `src` from `at`, and `dst` is good for as many.
            unsafe { at + tail(&src[at..], dst.add(at)) }
        }

        /// What [`copy_clean`] does, 32 bytes at a time, until fewer are left.
        /// How far it got, and whether that is a byte to escape.
        ///
        /// # Safety
        /// As [`super::copy_clean`], on a CPU with AVX2.
        #[target_feature(enable = "avx2")]
        unsafe fn avx2(src: &[u8], dst: *mut u8) -> (usize, bool) {
            let len = src.len();
            let mut at = 0;
            while len - at >= 32 {
                // SAFETY: 32 bytes of `src` from `at`, and `dst` is good for as many.
                let block = unsafe {
                    let block = _mm256_loadu_si256(src.as_ptr().add(at).cast());
                    _mm256_storeu_si256(dst.add(at).cast(), block);
                    block
                };
                let control = _mm256_cmpeq_epi8(_mm256_min_epu8(block, _mm256_set1_epi8(0x1f)), block);
                let quote = _mm256_cmpeq_epi8(block, _mm256_set1_epi8(b'"' as i8));
                let backslash = _mm256_cmpeq_epi8(block, _mm256_set1_epi8(b'\\' as i8));
                let hit = _mm256_movemask_epi8(_mm256_or_si256(control, _mm256_or_si256(quote, backslash))) as u32;
                if hit != 0 {
                    return (at + hit.trailing_zeros() as usize, true);
                }
                at += 32;
            }
            (at, false)
        }

        /// Fewer than 16 bytes, loaded and stored whole by two overlapping
        /// words: no loop, and no read past the end.
        ///
        /// # Safety
        /// `src` is under 16 bytes; `dst` is good for as many.
        #[inline(always)]
        pub(in super::super) unsafe fn tail(src: &[u8], dst: *mut u8) -> usize {
            let (len, p) = (src.len(), src.as_ptr());
            // SAFETY: each load and store is within the `len` bytes its branch tests for.
            unsafe {
                let (lo, hi) = if len >= 8 {
                    let (lo, hi) = (p.cast::<u64>().read_unaligned(), p.add(len - 8).cast::<u64>().read_unaligned());
                    dst.cast::<u64>().write_unaligned(lo);
                    dst.add(len - 8).cast::<u64>().write_unaligned(hi);
                    (lo, hi)
                } else if len >= 4 {
                    let (lo, hi) = (p.cast::<u32>().read_unaligned(), p.add(len - 4).cast::<u32>().read_unaligned());
                    dst.cast::<u32>().write_unaligned(lo);
                    dst.add(len - 4).cast::<u32>().write_unaligned(hi);
                    (lo as u64 | (lo as u64) << 32, hi as u64 | (hi as u64) << 32)
                } else if len > 0 {
                    let (a, b, c) = (*p, *p.add(len / 2), *p.add(len - 1));
                    *dst = a;
                    *dst.add(len / 2) = b;
                    *dst.add(len - 1) = c;
                    let word = u32::from_le_bytes([a, b, c, a]) as u64;
                    (word | word << 32, 0x2020_2020_2020_2020)
                } else {
                    return 0;
                };
                if hits128(_mm_set_epi64x(hi as i64, lo as i64)) == 0 {
                    len
                } else {
                    super::one_at_a_time(src, dst)
                }
            }
        }
    }
}
