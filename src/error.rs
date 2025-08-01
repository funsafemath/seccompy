//! Internal module for error handling

use std::io;

use libc::c_int;

/// Get the last errno. As per rust std docs, this function never panics:
///
/// If this Error was constructed via [`io::Error::last_os_error`] or [`io::Error::from_raw_os_error`],
/// then this function will return Some, otherwise it will return None.
pub fn errno() -> c_int {
    io::Error::last_os_error().raw_os_error().unwrap()
}

pub fn format_unknown_error(error_code: c_int) -> String {
    format!("{}", io::Error::from_raw_os_error(error_code))
}
