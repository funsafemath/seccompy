//! This module implements the seccomp syscall Rust interface
//!
//! seccomp has 4 operations, and for each of them this module has a submodule:
//!
//! [`check_action`] with [`is_action_available`] and [`CheckActionError`] exported
//!
//! [`get_noti_sizes`] with [`get_notification_sizes`], [`NotificationSizes`] and [`GetNotificationSizesError`] exported
//!
//! [`mod@set_filter`] with [`set_filter::set_filter`], [`set_filter::set_filter_with_listener`] and [`SetFilterError`] exported
//!
//! [`mod@set_strict`] with [`set_strict::set_strict`] and [`SetStrictModeError`] exported
//!
//! Also there is a [`filter`] module with [`FilterAction`], [`FilterFlags`] and [`FilterWithListenerFlags`] exported

use core::ffi::{c_uint, c_void};
use std::{ffi::c_long, ptr};

use libc::{
    EINVAL, SECCOMP_GET_ACTION_AVAIL, SECCOMP_GET_NOTIF_SIZES, SECCOMP_SET_MODE_FILTER,
    SECCOMP_SET_MODE_STRICT, SYS_seccomp, c_ushort, seccomp_notif_sizes, sock_fprog, syscall,
};

pub mod check_action;
pub mod filter;
pub mod get_noti_sizes;
pub mod set_filter;
pub mod set_strict;

pub use filter::{FilterAction, FilterFlags, FilterWithListenerFlags};

pub use check_action::{CheckActionError, is_action_available};
pub use get_noti_sizes::{GetNotificationSizesError, NotificationSizes, get_notification_sizes};
pub use set_filter::{SetFilterError, set_filter, set_filter_with_listener};
pub use set_strict::{SetStrictModeError, set_strict};

use crate::{bpf::BpfInstruction, seccomp::filter::FullFilterFlags};

enum Operation<'a> {
    SetModeStrict,

    SetModeFilter(FullFilterFlags, &'a [BpfInstruction]),

    CheckActionAvailable(FilterAction),

    GetNotificationSizes(&'a mut seccomp_notif_sizes),
}

impl Operation<'_> {
    fn flags(&self) -> c_uint {
        if let Self::SetModeFilter(flags, _) = self {
            c_uint::from(*flags)
        } else {
            0
        }
    }

    const fn opcode(&self) -> c_uint {
        match self {
            Operation::SetModeStrict => SECCOMP_SET_MODE_STRICT,
            Operation::SetModeFilter(_, _) => SECCOMP_SET_MODE_FILTER,
            Operation::CheckActionAvailable(_) => SECCOMP_GET_ACTION_AVAIL,
            Operation::GetNotificationSizes(_) => SECCOMP_GET_NOTIF_SIZES,
        }
    }
}

/// `int syscall(SYS_seccomp, unsigned int operation, unsigned int flags, void *args);`
unsafe fn seccomp_syscall(operation: c_uint, flags: c_uint, args: *mut c_void) -> c_long {
    unsafe { syscall(SYS_seccomp, operation, flags, args) }
}

type BpfProgram = sock_fprog;

// It's possible to write this function more concisely, but there's unsafe code,
// so the most obviously correct way is probably better than the shortest one
fn seccomp(operation: Operation) -> c_long {
    let opcode = operation.opcode();
    let flags = operation.flags();

    match operation {
        Operation::SetModeStrict => {
            // Strict mode requires a null pointer as args
            let args = ptr::null_mut::<c_void>();
            unsafe { seccomp_syscall(opcode, flags, args) }
        }
        Operation::SetModeFilter(_, bpf_instructions) => {
            // EINVAL is returned if there are no instructions,
            // so we can return an error early
            if bpf_instructions.is_empty() {
                return c_long::from(EINVAL);
            }

            let Ok(len) = c_ushort::try_from(bpf_instructions.len()) else {
                // EINVAL is returned when the number of instructions is more than BPF_MAXINSNS;
                // if there's an overflow, the number of instructions must be larger than BPF_MAXINSNS,
                // so we can return an error early
                // (if running as root, BPF_COMPLEXITY_LIMIT_INSNS is used instead, but the point still holds)
                return c_long::from(EINVAL);
            };

            // Casting to a mutable pointer is ok, since the kernel doesn't write into the buffer
            let mut bpf_program = BpfProgram {
                len,
                filter: bpf_instructions.as_ptr().cast_mut(),
            };
            unsafe { seccomp_syscall(opcode, flags, (&raw mut bpf_program).cast()) }
        }
        Operation::CheckActionAvailable(filter_action) => {
            // Actually the action won't be mutated, but this does not cause any problems
            let mut action = filter_action.action();
            unsafe { seccomp_syscall(opcode, flags, (&raw mut action).cast::<c_void>()) }
        }
        Operation::GetNotificationSizes(seccomp_notif_sizes) => unsafe {
            seccomp_syscall(
                opcode,
                flags,
                ptr::from_mut::<seccomp_notif_sizes>(seccomp_notif_sizes).cast::<c_void>(),
            )
        },
    }
}
