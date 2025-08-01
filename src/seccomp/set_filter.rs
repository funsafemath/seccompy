use core::ffi::c_int;
use std::{error::Error, fmt::Display};

use libc::{EACCES, EBUSY, EINVAL, ENOMEM, ESRCH, pid_t};

use crate::{
    bpf::BpfInstruction,
    seccomp::{
        Operation,
        filter::{FilterFlags, FilterWithListenerFlags},
        seccomp,
    },
};

#[derive(Debug)]
pub enum SetFilterError {
    /// The caller did not have the `CAP_SYS_ADMIN` capability in its user namespace,
    /// or had not set `no_new_privs` before using `SECCOMP_SET_MODE_FILTER`.
    PermissionError,

    /// While installing a new filter, the `SECCOMP_FILTER_FLAG_NEW_LISTENER` flag was specified,
    /// but a previous filter had already been installed with that flag.
    ListenerAlreadySet,

    /// operation is unknown or is not supported by this kernel version or configuration.
    ///
    /// operation included `BPF_ABS`, but the specified offset was not aligned to a 32-bit boundary or exceeded sizeof(struct `seccomp_data`).
    ///
    /// A secure computing mode has already been set, and operation differs from the existing setting.
    ///
    /// operation specified `SECCOMP_SET_MODE_FILTER`, but the filter program pointed to by args was not valid
    /// or the length of the filter program was zero or exceeded `BPF_MAXINSNS` (4096) instructions.
    InvalidArguments,

    /// Out of memory.
    ///
    /// The total length of all filter programs attached to the calling thread would exceed `MAX_INSNS_PER_PATH` (32768) instructions.
    /// Note that for the purposes of calculating this limit, each already existing filter program incurs an overhead penalty of 4 instructions.
    OutOfMemory,

    /// Another thread caused a failure during thread sync, but its ID could not be determined.
    SyncErrorNoThreadId,

    /// If any thread cannot synchronize to the same filter tree, the call will not attach the new seccomp filter,
    /// and will fail, returning the first thread ID found that cannot synchronize.  Synchronization will fail
    /// if another thread in the same process is in `SECCOMP_MODE_STRICT` or if it has attached new
    /// seccomp filters to itself, diverging from the calling thread's filter tree.
    SyncError(pid_t),

    /// Any error that's generally not returned for a given operation as per the seccomp(2) manpage
    Unknown(c_int),
}

impl Display for SetFilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::PermissionError => {
                "permission error, caller did not have CAP_SYS_ADMIN or did not set no_new_privs"
            }
            Self::ListenerAlreadySet => {
                "another filter has already set the SECCOMP_FILTER_FLAG_NEW_LISTENER flag"
            }
            Self::InvalidArguments => {
                "filters are not supported, or seccomp with different operation has already been set, or the bpf program is invalid"
            }
            Self::OutOfMemory => {
                "out of memory, or length all programs would exceed MAX_INSNS_PER_PATH instructions"
            }
            Self::SyncErrorNoThreadId => {
                "another thread caused a failure during thread sync, but its id could not be determined"
            }
            Self::SyncError(thread_id) => {
                &{ format!("thread {thread_id} caused a failure during thread sync") }
            }
            Self::Unknown(error_code) => &{ crate::error::format_unknown_error(*error_code) },
        };
        write!(f, "{text}")
    }
}

impl Error for SetFilterError {}

impl From<c_int> for SetFilterError {
    // errno to error
    fn from(value: c_int) -> Self {
        match value {
            EACCES => Self::PermissionError,
            EBUSY => Self::ListenerAlreadySet,
            EINVAL => Self::InvalidArguments,
            ENOMEM => Self::OutOfMemory,
            ESRCH => Self::SyncErrorNoThreadId,
            other => Self::Unknown(other),
        }
    }
}

/// Setup a system call filter
///
/// Filters allow to implement arbitrary logic for filtering the system calls. There are many different [`FilterFlags`]
/// and [`FilterAction`](crate::FilterAction)s that affect what the filter behavior. See their documentation for more info.
///
/// The system calls allowed are defined by a pointer to a Berkeley Packet Filter (BPF) passed via args.
/// This argument is a pointer to a struct `sock_fprog`;
/// it can be designed to filter arbitrary system calls and system call arguments.
/// If the filter is invalid, `seccomp()` fails, returning EINVAL in errno.
///
/// If fork(2) or clone(2) is allowed by the filter, any child processes will be constrained to the same system call filters as the parent.
/// If execve(2) is allowed, the existing filters will be preserved across a call to execve(2).
///
/// In order to use the `SECCOMP_SET_MODE_FILTER` operation, either the calling thread must have the `CAP_SYS_ADMIN` capability in its user namespace,
/// or the thread must already have the `no_new_privs` bit set. If that bit was not already set by an ancestor of this thread,
/// the thread must make the following call:
///
/// ```c
///     prctl(PR_SET_NO_NEW_PRIVS, 1);
/// ```
///
/// Otherwise, the `SECCOMP_SET_MODE_FILTER` operation fails and returns EACCES in errno.
/// This requirement ensures that an unprivileged process cannot apply a malicious filter and then invoke a set-user-ID
/// or other privileged program using execve(2), thus potentially compromising that program.
/// (Such a malicious filter might, for example, cause an attempt to use setuid(2) to set the caller's user IDs to nonzero values
/// to instead return 0 without actually making the system call. Thus, the program might be tricked into retaining superuser privileges
/// in circumstances where it is possible to influence it to do dangerous things because it did not actually drop privileges.)
///
/// If prctl(2) or `seccomp()` is allowed by the attached filter, further filters may be added.
/// This will increase evaluation time, but allows for further reduction of the attack surface during execution of a thread.
///
/// The `SECCOMP_SET_MODE_FILTER` operation is available only if the kernel is configured with `CONFIG_SECCOMP_FILTER` enabled.
///
/// When flags is 0, this operation is functionally identical to the call:
///
/// ```c
///     prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, args);
/// ```
pub fn set_filter(flags: FilterFlags, bpf_code: &[BpfInstruction]) -> Result<(), SetFilterError> {
    match seccomp(Operation::SetModeFilter(flags.into(), bpf_code)) {
        0 => Ok(()),
        -1 => Err(SetFilterError::from(crate::error::errno())),
        thread_id => Err(SetFilterError::SyncError(thread_id as pid_t)),
    }
}

/// Setup a system call filter with a new listener
///
/// Filters allow to implement arbitrary logic for filtering the system calls. There are many different [`FilterWithListenerFlags`]
/// and [`FilterAction`](crate::FilterAction)s that affect what the filter behavior. See their documentation for more info.
///
/// This function will return an event listener descriptor. Using it, a userspace process
/// can handle the system calls instead of the kernel or forward them to it.
/// These may be helpful: [`FilterWithListenerFlags::ignore_non_fatal_signals`](FilterWithListenerFlags),
/// [`FilterAction::UserNotif`](crate::FilterAction::UserNotif)
///
/// Beware of TOCTOU and other pitfalls if using it for anything sandboxing-related.
/// Read the `seccomp_unotify(2)` manpage for more information.
///
/// The system calls allowed are defined by a pointer to a Berkeley Packet Filter (BPF) passed via args.
/// This argument is a pointer to a struct `sock_fprog`;
/// it can be designed to filter arbitrary system calls and system call arguments.
/// If the filter is invalid, `seccomp()` fails, returning `EINVAL` in errno.
///
/// If fork(2) or clone(2) is allowed by the filter, any child processes will be constrained to the same system call filters as the parent.
/// If execve(2) is allowed, the existing filters will be preserved across a call to execve(2).
///
/// In order to use the `SECCOMP_SET_MODE_FILTER` operation, either the calling thread must have the `CAP_SYS_ADMIN` capability in its user namespace,
/// or the thread must already have the `no_new_privs` bit set. If that bit was not already set by an ancestor of this thread,
/// the thread must make the following call:
///
/// ```c
///     prctl(PR_SET_NO_NEW_PRIVS, 1);
/// ```
///
/// Otherwise, the `SECCOMP_SET_MODE_FILTER` operation fails and returns EACCES in errno.
/// This requirement ensures that an unprivileged process cannot apply a malicious filter and then invoke a set-user-ID
/// or other privileged program using execve(2), thus potentially compromising that program.
/// (Such a malicious filter might, for example, cause an attempt to use setuid(2) to set the caller's user IDs to nonzero values
/// to instead return 0 without actually making the system call. Thus, the program might be tricked into retaining superuser privileges
/// in circumstances where it is possible to influence it to do dangerous things because it did not actually drop privileges.)
///
/// If prctl(2) or `seccomp()` is allowed by the attached filter, further filters may be added.
/// This will increase evaluation time, but allows for further reduction of the attack surface during execution of a thread.
///
/// The `SECCOMP_SET_MODE_FILTER` operation is available only if the kernel is configured with `CONFIG_SECCOMP_FILTER` enabled.
pub fn set_filter_with_listener(
    flags: FilterWithListenerFlags,
    bpf_code: &[BpfInstruction],
) -> Result<c_int, SetFilterError> {
    match seccomp(Operation::SetModeFilter(flags.into(), bpf_code)) {
        -1 => Err(SetFilterError::from(crate::error::errno())),
        descriptor => Ok(descriptor as c_int),
    }
}
