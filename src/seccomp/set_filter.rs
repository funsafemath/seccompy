use core::ffi::c_int;
use std::{error::Error, fmt::Display};

use libc::{EACCES, EBUSY, EINVAL, ENOMEM, ESRCH, c_long, pid_t};

use crate::{
    FilterFlags,
    bpf::BpfInstruction,
    seccomp::{Operation, seccomp},
};

#[derive(Debug)]
pub enum SetFilterError {
    /// The caller did not have the CAP_SYS_ADMIN capability in its user namespace,
    /// or had not set no_new_privs before using SECCOMP_SET_MODE_FILTER.
    PermissionError,

    /// While installing a new filter, the SECCOMP_FILTER_FLAG_NEW_LISTENER flag was specified,
    /// but a previous filter had already been installed with that flag.
    ListenerAlreadySet,

    /// operation is unknown or is not supported by this kernel version or configuration.
    ///
    /// operation included BPF_ABS, but the specified offset was not aligned to a 32-bit boundary or exceeded sizeof(struct seccomp_data).
    ///
    /// A secure computing mode has already been set, and operation differs from the existing setting.
    ///
    /// operation specified SECCOMP_SET_MODE_FILTER, but the filter program pointed to by args was not valid
    /// or the length of the filter program was zero or exceeded BPF_MAXINSNS (4096) instructions.
    InvalidArguments,

    /// Out of memory.
    ///
    /// The total length of all filter programs attached to the calling thread would exceed MAX_INSNS_PER_PATH (32768) instructions.
    /// Note that for the purposes of calculating this limit, each already existing filter program incurs an overhead penalty of 4 instructions.
    OutOfMemory,

    /// Another thread caused a failure during thread sync, but its ID could not be determined.
    SyncErrorNoThreadId,

    /// If any thread cannot synchronize to the same filter tree, the call will not attach the new seccomp filter,
    /// and will fail, returning the first thread ID found that cannot synchronize.  Synchronization will fail
    /// if another thread in the same process is in SECCOMP_MODE_STRICT or if it has attached new
    /// seccomp filters to itself, diverging from the calling thread's filter tree.
    SyncError(pid_t),

    /// Any error that's generally not returned for a given operation as per the syscall(2) manpage
    Unknown(c_int),
}

// TODO: It'd probably be better if this was a Result<Ok(enum(Success, Descriptor(c_int))), Err(SetFilterError)>,
// this would simplify handling of the result, but that'd require forbidding using
// new_listener with sync_threads, but without no_thread_id_on_sync_error (who does this anyway?)
#[must_use]
#[derive(Debug)]
pub enum SetFilterResult {
    Ok,

    Descriptor(c_int),

    /// If sync_threads is enabled, seccomp will return the id of the first failed thread on failed sync;
    /// if new_listener is enabled, seccomp will return the descriptor on success;
    /// so without further interaction with the OS it's impossible to determine if the result is a descriptor or a thread id.
    /// To avoid this you can set the no_thread_id_on_sync_error flag.
    ErroredThreadIdOrDescriptor(c_long),

    Err(SetFilterError),
}

impl Display for SetFilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            SetFilterError::PermissionError => {
                "permission error, caller did not have CAP_SYS_ADMIN or did not set no_new_privs"
            }
            SetFilterError::ListenerAlreadySet => {
                "another filter has already set the SECCOMP_FILTER_FLAG_NEW_LISTENER flag"
            }
            SetFilterError::InvalidArguments => {
                "filters are not supported, or seccomp with different operation has already been set, or the bpf program is invalid"
            }
            SetFilterError::OutOfMemory => {
                "out of memory, or length all programs would exceed MAX_INSNS_PER_PATH instructions"
            }
            SetFilterError::SyncErrorNoThreadId => {
                "another thread caused a failure during thread sync, but its id could not be determined"
            }
            SetFilterError::SyncError(thread_id) => {
                &{ format!("thread {thread_id} caused a failure during thread sync") }
            }
            SetFilterError::Unknown(error_code) => {
                &{ crate::error::format_unknown_error(*error_code) }
            }
        };
        write!(f, "{text}")
    }
}

impl Error for SetFilterError {}

/// Setup a system call filter
///
/// System call filter allows to implement arbitrary logic for, well, filtering the system calls. There are many different [FilterFlags]
/// and [FilterAction](crate::FilterAction)s that affect what the filter behavior. See their documentation for more info.
///
/// One really useful feature is the user notifier. It allows another userspace process
/// to handle the system calls instead of the kernel or forward them to it.
/// These may be helpful: [FilterFlags::new_listener], [FilterFlags::ignore_non_fatal_signals],
/// [FilterAction::UserNotif](crate::FilterAction::UserNotif)
/// Beware of TOCTOU and other pitfalls if using it for anything sandboxing-related.
/// Read the seccomp_unotify(2) manpage for more information.
///
/// # Examples
///
/// TODO after the basic BPF is implemented
///
/// The system calls allowed are defined by a pointer to a Berkeley Packet Filter (BPF) passed via args.
/// This argument is a pointer to a struct sock_fprog;
/// it can be designed to filter arbitrary system calls and system call arguments.
/// If the filter is invalid, seccomp() fails, returning EINVAL in errno.
///
/// If fork(2) or clone(2) is allowed by the filter, any child processes will be constrained to the same system call filters as the parent.
/// If execve(2) is allowed, the existing filters will be preserved across a call to execve(2).
///
/// In order to use the SECCOMP_SET_MODE_FILTER operation, either the calling thread must have the CAP_SYS_ADMIN capability in its user namespace,
/// or the thread must already have the no_new_privs bit set. If that bit was not already set by an ancestor of this thread,
/// the thread must make the following call:
/// ```c
///     prctl(PR_SET_NO_NEW_PRIVS, 1);
/// ```
/// Otherwise, the SECCOMP_SET_MODE_FILTER operation fails and returns EACCES in errno.
/// This requirement ensures that an unprivileged process cannot apply a malicious filter and then invoke a set-user-ID
/// or other privileged program using execve(2), thus potentially compromising that program.
/// (Such a malicious filter might, for example, cause an attempt to use setuid(2) to set the caller's user IDs to nonzero values
/// to instead return 0 without actually making the system call. Thus, the program might be tricked into retaining superuser privileges
/// in circumstances where it is possible to influence it to do dangerous things because it did not actually drop privileges.)
///
/// If prctl(2) or seccomp() is allowed by the attached filter, further filters may be added.
/// This will increase evaluation time, but allows for further reduction of the attack surface during execution of a thread.
///
/// The SECCOMP_SET_MODE_FILTER operation is available only if the kernel is configured with CONFIG_SECCOMP_FILTER enabled.
///
/// When flags is 0, this operation is functionally identical to the call:
/// ```c
///     prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, args);
/// ```
///    
pub fn set_filter(flags: FilterFlags, bpf_code: &[BpfInstruction]) -> SetFilterResult {
    match seccomp(Operation::SetModeFilter(flags, bpf_code)) {
        0 => SetFilterResult::Ok,
        -1 => SetFilterResult::Err(match crate::error::errno() {
            EACCES => SetFilterError::PermissionError,
            EBUSY => SetFilterError::ListenerAlreadySet,
            EINVAL => SetFilterError::InvalidArguments,
            ENOMEM => SetFilterError::OutOfMemory,
            ESRCH => SetFilterError::SyncErrorNoThreadId,
            other => SetFilterError::Unknown(other),
        }),
        thread_id_or_descriptor => {
            let can_have_thread_id = flags.sync_threads && !flags.no_thread_id_on_sync_error;
            match (flags.new_listener, can_have_thread_id) {
                (true, true) => {
                    SetFilterResult::ErroredThreadIdOrDescriptor(thread_id_or_descriptor)
                }
                (true, false) => SetFilterResult::Descriptor(thread_id_or_descriptor as c_int),
                (false, true) => SetFilterResult::Err(SetFilterError::SyncError(
                    thread_id_or_descriptor as pid_t,
                )),

                // no thread id, no descriptor => error code is 0 or -1
                (false, false) => unreachable!(),
            }
        }
    }
}
