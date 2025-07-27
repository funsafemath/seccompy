//! This module implements the seccomp() syscall Rust interface
//!
//! seccomp has 4 operations, and for each of them this module has a (non-pub) submodule:
//!
//! [check_action] with [is_action_available] and [CheckActionError] exported
//!
//! [get_noti_sizes] with [get_notification_sizes], [NotificationSizes] and [GetNotificationSizesError] exported
//!
//! [set_filter] with [set_filter::set_filter], [SetFilterResult] and [SetFilterError] exported
//!
//! [set_strict] with [set_strict::set_strict] and [SetStrictModeError] exported
//!
//! Also there is a [filter] module with [BpfInstruction], [FilterAction] and [FilterFlags] exported

use core::ffi::{c_uint, c_void};
use std::ptr;

use libc::{
    EINVAL, SECCOMP_GET_ACTION_AVAIL, SECCOMP_GET_NOTIF_SIZES, SECCOMP_SET_MODE_FILTER,
    SECCOMP_SET_MODE_STRICT, SYS_seccomp, c_ushort, seccomp_notif_sizes, syscall,
};

use crate::seccomp::filter::BpfProgram;

mod check_action;
mod filter;
mod get_noti_sizes;
mod set_filter;
mod set_strict;

pub use filter::{BpfInstruction, FilterAction, FilterFlags};

pub use check_action::{CheckActionError, is_action_available};
pub use get_noti_sizes::{GetNotificationSizesError, NotificationSizes, get_notification_sizes};
pub use set_filter::{SetFilterError, SetFilterResult, set_filter};
pub use set_strict::{SetStrictModeError, set_strict};

enum Operation<'a> {
    SetModeStrict,

    SetModeFilter(FilterFlags, &'a [BpfInstruction]),

    CheckActionAvailable(FilterAction),

    GetNotificationSizes(&'a mut seccomp_notif_sizes),
}

impl<'a> From<&Operation<'a>> for c_uint {
    fn from(value: &Operation) -> Self {
        match value {
            Operation::SetModeStrict => SECCOMP_SET_MODE_STRICT,
            Operation::SetModeFilter(_, _) => SECCOMP_SET_MODE_FILTER,
            Operation::CheckActionAvailable(_) => SECCOMP_GET_ACTION_AVAIL,
            Operation::GetNotificationSizes(_) => SECCOMP_GET_NOTIF_SIZES,
        }
    }
}

/// int syscall(SYS_seccomp, unsigned int operation, unsigned int flags, void *args);
unsafe fn seccomp_syscall(operation: c_uint, flags: c_uint, args: *mut c_void) -> i64 {
    unsafe { syscall(SYS_seccomp, operation, flags, args) }
}

fn seccomp(operation: Operation) -> isize {
    let op = c_uint::from(&operation);

    // All operations except the SECCOMP_SET_MODE_FILTER require the flags to be zero
    // FilterFlags::default() returns zero when converted to a c_int
    let flags = c_uint::from(match &operation {
        &Operation::SetModeFilter(flags, _) => flags,
        _ => FilterFlags::default(),
    });

    let args = match operation {
        // Strict mode requires a null pointer as args
        Operation::SetModeStrict => ptr::null::<c_void>() as *mut c_void,
        Operation::SetModeFilter(_, bpf_instructions) => {
            // EINVAL is returned if there are no instructions,
            // so we can return an error early
            if bpf_instructions.is_empty() {
                return EINVAL as isize;
            }

            let Ok(length) = c_ushort::try_from(bpf_instructions.len()) else {
                // EINVAL is returned when the number of instructions is more than BPF_MAXINSNS;
                // if there's an overflow, the number of instructions must be larger than BPF_MAXINSNS,
                // so we can return an error early
                return EINVAL as isize;
            };

            // Casting to a mutable pointer is ok, since the kernel doesn't write into the buffer
            &BpfProgram {
                length,
                bytecode: bpf_instructions.as_ptr(),
            } as *const BpfProgram as *mut c_void
        }
        Operation::CheckActionAvailable(filter_action) => {
            &filter_action as *const FilterAction as *mut c_void
        }
        Operation::GetNotificationSizes(notification_sizes) => {
            notification_sizes as *mut seccomp_notif_sizes as *mut c_void
        }
    };

    (unsafe { seccomp_syscall(op, flags, args) }) as isize
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [FilterFlags] default value is used for all operations except the filter one. If it is not zero for these operations, the
    /// system call will return an error
    #[test]
    fn verify_default_flags() {
        assert_eq!(c_uint::from(FilterFlags::default()), 0)
    }
}
