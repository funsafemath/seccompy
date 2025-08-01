use core::ffi::c_int;
use std::{error::Error, fmt::Display};

use libc::ENOENT;

use crate::unotify::{SeccompNotif, UnotifyOperation};

#[derive(Debug)]
pub enum CheckValidityError {
    /// Any error that's generally not returned for a given operation as per the seccomp_unotify(2) manpage
    Unknown(c_int),
}

impl Display for CheckValidityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(error_code) => {
                write!(f, "{}", crate::error::format_unknown_error(*error_code))
            }
        }
    }
}

impl Error for CheckValidityError {}

/// Check if a notification is still valid
///
/// Returns false if the target has died or the system call was interrupted by a signal
///
/// To make the target ignore all signals, except for SIGKILL, until the supervisor returns, use
/// [FilterWithListenerFlags::ignore_non_fatal_signals](crate::FilterWithListenerFlags)
pub fn check_validity(
    descriptor: i32,
    notification: &SeccompNotif,
) -> Result<bool, CheckValidityError> {
    match unsafe {
        libc::ioctl(
            descriptor,
            UnotifyOperation::CheckValidity as u64,
            // Kernel only copies the data, so a const pointer is ok
            &notification.id as *const u64,
        )
    } {
        0 => Ok(true),
        -1 => match crate::error::errno() {
            ENOENT => Ok(false),
            other => Err(CheckValidityError::Unknown(other as c_int)),
        },
        _ => unreachable!(),
    }
}
