use core::ffi::c_int;
use std::{error::Error, fmt::Display};

use libc::ENOENT;

use crate::unotify::{SeccompData, SeccompNotif, UnotifyOperation};

#[derive(Debug)]
pub enum ReceiveNotificationError {
    /// The target thread was killed by a signal as the notification information was being generated,
    /// or the target's (blocked) system call was interrupted by a signal handler
    Interrupted,

    Unknown(c_int),
}

impl Display for ReceiveNotificationError {
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

impl Error for ReceiveNotificationError {}

/// Receive a SeccompNotif event
///
/// If no such event is currently pending, the operation blocks until an event occurs.
pub fn receive_notification(descriptor: c_int) -> Result<SeccompNotif, ReceiveNotificationError> {
    let mut notification = SeccompNotif {
        id: 0,
        pid: 0,
        flags: 0,
        data: SeccompData {
            nr: 0,
            arch: 0,
            instruction_pointer: 0,
            args: [0, 0, 0, 0, 0, 0],
        },
    };

    match unsafe {
        libc::ioctl(
            descriptor,
            UnotifyOperation::ReceiveNotification as u64,
            &mut notification as *mut _,
        )
    } {
        0 => Ok(notification),
        -1 => match crate::error::errno() {
            ENOENT => Err(ReceiveNotificationError::Interrupted),
            other => Err(ReceiveNotificationError::Unknown(other as c_int)),
        },
        _ => unreachable!(),
    }
}
