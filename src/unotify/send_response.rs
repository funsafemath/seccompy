use core::ffi::c_int;
use std::{error::Error, fmt::Display};

use libc::{ENOENT, SECCOMP_USER_NOTIF_FLAG_CONTINUE};

use crate::unotify::{SeccompNotif, SeccompNotifResponse, UnotifyOperation};

#[derive(Debug)]
pub enum SendResponseError {
    /// The blocked system call in the target has been interrupted by a signal handler or the target has terminated.
    Interrupted,

    /// Any error that's generally not returned for a given operation as per the `seccomp_unotify(2)` manpage
    Unknown(c_int),
    // there are also EINPROGRESS and EINVAL errors, but they can't happen in the current implementation
}

impl Display for SendResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Interrupted => {
                write!(f, "target thread was killed or system call was interrupted")
            }
            Self::Unknown(error_code) => {
                write!(f, "{}", crate::error::format_unknown_error(*error_code))
            }
        }
    }
}

impl Error for SendResponseError {}

pub fn send_response(
    descriptor: c_int,
    response: SeccompNotifResponse,
) -> Result<(), SendResponseError> {
    match unsafe {
        libc::ioctl(
            descriptor,
            UnotifyOperation::Respond as u64,
            // Kernel only copies the data, so a const pointer is ok
            &raw const response,
        )
    } {
        0 => Ok(()),
        -1 => match crate::error::errno() {
            ENOENT => Err(SendResponseError::Interrupted),
            other => Err(SendResponseError::Unknown(other as c_int)),
        },
        _ => unreachable!(),
    }
}

/// Continue the system call
///
/// Note that this function CAN NOT be used to implement a security policy, as it does not have protection against TOCTOU attacks.
/// See the `seccomp_unotify(2)` manpage for more details
#[must_use]
pub const fn continue_syscall(notification: SeccompNotif) -> SeccompNotifResponse {
    // A response to the kernel telling it to execute the target's system call. In this case, the flags field includes
    // SECCOMP_USER_NOTIF_FLAG_CONTINUE and the error and val fields must be zero.
    SeccompNotifResponse {
        id: notification.id,
        val: 0,
        error: 0,
        flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
    }
}

// A spoofed return value for the target's system call.
// In this case, the kernel does not execute the target's system call, instead causing the system call to return a spoofed value
// as specified by fields of the seccomp_notif_resp structure.

// The supervisor should set the fields of this structure as follows:
//
// • flags does not contain SECCOMP_USER_NOTIF_FLAG_CONTINUE.
//
// • error is set either to 0 for a spoofed "success" return or to a negative error number for a spoofed "failure" return.
//
// In the former case, the kernel causes the target's system call to return the value specified in the val field.
// In the latter case, the kernel causes the target's system call to return -1, and errno is assigned the negated error value.
//
// • val is set to a value that will be used as the return value for a spoofed "success" return for the target's system call.
// The value in this field is ignored if the error field contains a nonzero value.

/// Set the target's system call return value
#[must_use]
pub const fn return_syscall(notification: SeccompNotif, value: i64) -> SeccompNotifResponse {
    SeccompNotifResponse {
        id: notification.id,
        val: value,
        error: 0,
        flags: 0,
    }
}

/// Set the target's system call return code to `-error_code`
///
/// This function uses u16 for now: `error_code` must not be negative, using u32 may lead to overflows,
/// and returning an option is not convenient.
/// Also u16 should be enough for, like, every error code, and if it's not, you can use the [`return_syscall`]
#[must_use]
pub fn fail_syscall(notification: SeccompNotif, error_code: u16) -> SeccompNotifResponse {
    SeccompNotifResponse {
        id: notification.id,
        val: 0,
        error: -i32::from(error_code),
        flags: 0,
    }
}
