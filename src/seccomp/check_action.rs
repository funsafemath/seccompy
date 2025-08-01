use core::ffi::c_int;
use std::{error::Error, fmt::Display};

use libc::{EINVAL, EOPNOTSUPP};

use crate::seccomp::{Operation, filter::FilterAction, seccomp};

#[derive(Debug)]
pub enum CheckActionError {
    /// operation is unknown or is not supported by this kernel version or configuration.
    CheckNotSupported,

    /// Any error that's generally not returned for a given operation as per the seccomp(2) manpage
    Unknown(c_int),
}

impl Display for CheckActionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CheckNotSupported => write!(f, "check action operation not supported"),
            Self::Unknown(error_code) => {
                write!(f, "{}", crate::error::format_unknown_error(*error_code))
            }
        }
    }
}

impl Error for CheckActionError {}

/// Check if a given [FilterAction] is supported by the kernel
///
/// Returns true if it is supported, otherwise returns false.
///
/// This operation is helpful to confirm that the kernel knows of a more recently added filter return action
/// since the kernel treats all unknown actions as SECCOMP_RET_KILL_PROCESS.
///
/// Available since since Linux 4.14
///
/// # Examples
///
/// ```
/// use seccompy::{FilterAction, is_action_available};
///
/// let action = FilterAction::UserNotif;
/// let is_user_notif_available = is_action_available(action);
///
/// if let Ok(availability) = is_user_notif_available {
///     println!("{action:?} is {}", if availability { "available" } else { "not available" });
/// } else {
///     println!("Failed to check if {action:?} if available: {is_user_notif_available:?}");
/// }
/// ```
pub fn is_action_available(filter_action: FilterAction) -> Result<bool, CheckActionError> {
    match seccomp(Operation::CheckActionAvailable(filter_action)) {
        0 => Ok(true),
        -1 => match crate::error::errno() {
            EOPNOTSUPP => Ok(false),
            EINVAL => Err(CheckActionError::CheckNotSupported),
            other => Err(CheckActionError::Unknown(other)),
        },

        // For non-filter operations the return value is always 0 or -1
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_availability() {
        // these should be available everywhere if the kernel supports the seccomp
        let actions = &[
            FilterAction::KillThread,
            FilterAction::Trap { errno: 101 },
            FilterAction::Errno { errno: 202 },
        ];

        for action in actions {
            assert!(is_action_available(*action).unwrap())
        }
    }
}
