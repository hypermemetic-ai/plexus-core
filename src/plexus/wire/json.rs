//! PERF-34: a skeleton, the tests first. Nothing is written yet.

use bytes::BytesMut;
use serde::Serialize;
use serde_json::Error;

/// `value`'s JSON at the end of `out`.
pub(crate) fn write<T: Serialize + ?Sized>(_out: &mut BytesMut, _value: &T) -> Result<(), Error> {
    Ok(())
}

/// The clean run at the head of a string, found and copied in one pass.
pub(crate) mod scan {
    /// Skeleton: nothing is found, nothing copied.
    ///
    /// # Safety
    /// `dst` is good for `src.len()` bytes.
    pub(crate) unsafe fn one_at_a_time(src: &[u8], _dst: *mut u8) -> usize {
        src.len()
    }

    /// Skeleton.
    ///
    /// # Safety
    /// As [`one_at_a_time`].
    pub(crate) unsafe fn copy_clean(src: &[u8], _dst: *mut u8) -> usize {
        src.len()
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) mod x86 {
        /// Skeleton.
        ///
        /// # Safety
        /// As [`super::one_at_a_time`].
        pub(crate) unsafe fn sse2(src: &[u8], _dst: *mut u8) -> usize {
            src.len()
        }
    }
}
