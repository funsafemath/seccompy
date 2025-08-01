use core::ffi::c_int;
use std::{error::Error, fmt::Display};

use libc::{EINVAL, seccomp_notif_sizes};

use crate::seccomp::{Operation, seccomp};

#[derive(Debug)]
pub enum GetNotificationSizesError {
    /// operation is unknown or is not supported by this kernel version or configuration.
    GetNotiSizesNotSupported,

    /// Any error that's generally not returned for a given operation as per the seccomp(2) manpage
    Unknown(c_int),
}

impl Display for GetNotificationSizesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GetNotiSizesNotSupported => {
                write!(f, "get notification sizes operation not supported")
            }
            Self::Unknown(error_code) => {
                write!(f, "{}", crate::error::format_unknown_error(*error_code))
            }
        }
    }
}

impl Error for GetNotificationSizesError {}

#[derive(Debug, Clone, Copy)]
pub struct NotificationSizes {
    pub notification_size: usize,
    pub response_size: usize,
    pub seccomp_data_size: usize,
}

/// Get an initialized [`NotificationSizes`] struct
///
/// [`NotificationSizes`] struct contains the sizes of the seccomp `SECCOMP_RET_USER_NOTIF` notification, notification response and data.
/// These sizes have little use, and it's easier to get these parameters from the libc crate, but this function is implemented for completeness.
///
/// # Examples
/// ```
/// use libc;
/// use seccompy::seccomp::get_notification_sizes;
///
/// let noti_sizes = get_notification_sizes().unwrap();
/// println!("{:?}", noti_sizes);
///
/// assert!(noti_sizes.notification_size == size_of::<libc::seccomp_notif>());
/// ```
/// Get the sizes of the seccomp user-space notification structures.  Since these structures may evolve and grow over time, this command can be used to determine
/// how much memory to allocate for sending and receiving notifications.
///
/// The value of flags must be 0, and args must be a pointer to a struct `seccomp_notif_sizes`, which has the following form:
///
/// ```c
/// struct seccomp_notif_sizes {
///     __u16 seccomp_notif;      /* Size of notification structure */
///     __u16 seccomp_notif_resp; /* Size of response structure */
///     __u16 seccomp_data;       /* Size of 'struct seccomp_data' */
/// };
/// ```
/// See `seccomp_unotify(2)` for further details.
pub fn get_notification_sizes() -> Result<NotificationSizes, GetNotificationSizesError> {
    let mut notif_sizes = seccomp_notif_sizes {
        seccomp_notif: 0,
        seccomp_notif_resp: 0,
        seccomp_data: 0,
    };

    match seccomp(Operation::GetNotificationSizes(&mut notif_sizes)) {
        0 => Ok(NotificationSizes {
            notification_size: notif_sizes.seccomp_notif as usize,
            response_size: notif_sizes.seccomp_notif_resp as usize,
            seccomp_data_size: notif_sizes.seccomp_data as usize,
        }),

        -1 => match crate::error::errno() {
            EINVAL => Err(GetNotificationSizesError::GetNotiSizesNotSupported),
            other => Err(GetNotificationSizesError::Unknown(other as c_int)),
        },

        // For non-filter operations the return value is always 0 or -1
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_libc_and_kernel_noti_sizes() {
        let noti_sizes = get_notification_sizes().unwrap();

        assert!(noti_sizes.notification_size == size_of::<libc::seccomp_notif>());
        assert!(noti_sizes.response_size == size_of::<libc::seccomp_notif_resp>());
        assert!(noti_sizes.seccomp_data_size == size_of::<libc::seccomp_data>());
    }
}
