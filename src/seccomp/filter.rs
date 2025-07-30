use core::ffi::c_uint;

use libc::{
    SECCOMP_FILTER_FLAG_LOG, SECCOMP_FILTER_FLAG_NEW_LISTENER, SECCOMP_FILTER_FLAG_SPEC_ALLOW,
    SECCOMP_FILTER_FLAG_TSYNC, SECCOMP_FILTER_FLAG_TSYNC_ESRCH,
    SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV, SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO,
    SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_KILL_THREAD, SECCOMP_RET_LOG, SECCOMP_RET_TRACE,
    SECCOMP_RET_TRAP, SECCOMP_RET_USER_NOTIF,
};

/// Flags that modify the filter behavior
#[derive(Default, Clone, Copy)]
pub(crate) struct FullFilterFlags {
    /// All filter return actions except SECCOMP_RET_ALLOW should be logged.
    /// An administrator may override this filter flag by preventing specific actions
    /// from being logged via the /proc/sys/kernel/seccomp/actions_logged file.
    pub log: bool,

    /// After successfully installing the filter program, return a new user-space notification file descriptor.
    /// (The close-on-exec flag is set for the file descriptor.)
    /// When the filter returns SECCOMP_RET_USER_NOTIF a notification will be sent to this file descriptor.
    /// At most one seccomp filter using the SECCOMP_FILTER_FLAG_NEW_LISTENER flag can be installed for a thread.
    /// See seccomp_unotify(2) for further details.
    pub new_listener: bool,

    /// Disable Speculative Store Bypass mitigation.
    pub spec_allow: bool,

    /// When adding a new filter, synchronize all other threads of the calling process to the same seccomp filter tree.
    /// A "filter tree" is the ordered list of filters attached to a thread.
    /// (Attaching identical filters in separate seccomp() calls results in different filters from this perspective.)
    /// If any thread cannot synchronize to the same filter tree, the call will not attach the new seccomp filter,
    /// and will fail, returning the first thread ID found that cannot synchronize.
    /// Synchronization will fail if another thread in the same process is in SECCOMP_MODE_STRICT or if it has attached new
    /// seccomp filters to itself, diverging from the calling thread's filter tree.
    pub sync_threads: bool,

    /// This flag makes it such that when a user notification is received by the supervisor,
    /// the notifying process will ignore non-fatal signals until the response is sent.
    /// Signals that are sent prior to the notification being received by userspace are handled normally.
    pub ignore_non_fatal_signals: bool,

    /// Return ESRCH instead of a thread id on a thread sync error
    /// to avoid conflicts with a returned file descriptor if SECCOMP_FILTER_FLAG_NEW_LISTENER is set
    pub no_thread_id_on_sync_error: bool,
}

impl From<FullFilterFlags> for c_uint {
    fn from(value: FullFilterFlags) -> Self {
        let FullFilterFlags {
            log,
            new_listener,
            spec_allow,
            sync_threads,
            ignore_non_fatal_signals,
            no_thread_id_on_sync_error,
        } = value;

        let mut flags = 0;

        for (is_set, flag_value) in [
            (log, SECCOMP_FILTER_FLAG_LOG),
            (new_listener, SECCOMP_FILTER_FLAG_NEW_LISTENER),
            (spec_allow, SECCOMP_FILTER_FLAG_SPEC_ALLOW),
            (sync_threads, SECCOMP_FILTER_FLAG_TSYNC),
            (
                ignore_non_fatal_signals,
                SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
            ),
            (no_thread_id_on_sync_error, SECCOMP_FILTER_FLAG_TSYNC_ESRCH),
        ] {
            if is_set {
                flags |= flag_value as c_uint
            }
        }
        flags
    }
}

/// Flags that modify the filter behavior
#[derive(Default, Clone, Copy)]
pub struct FilterFlags {
    /// All filter return actions except SECCOMP_RET_ALLOW should be logged.
    /// An administrator may override this filter flag by preventing specific actions
    /// from being logged via the /proc/sys/kernel/seccomp/actions_logged file.
    pub log: bool,

    /// Disable Speculative Store Bypass mitigation.
    pub spec_allow: bool,

    /// When adding a new filter, synchronize all other threads of the calling process to the same seccomp filter tree.
    /// A "filter tree" is the ordered list of filters attached to a thread.
    /// (Attaching identical filters in separate seccomp() calls results in different filters from this perspective.)
    /// If any thread cannot synchronize to the same filter tree, the call will not attach the new seccomp filter,
    /// and will fail, returning the first thread ID found that cannot synchronize.
    /// Synchronization will fail if another thread in the same process is in SECCOMP_MODE_STRICT or if it has attached new
    /// seccomp filters to itself, diverging from the calling thread's filter tree.
    pub sync_threads: bool,

    /// This flag makes it such that when a user notification is received by the supervisor,
    /// the notifying process will ignore non-fatal signals until the response is sent.
    /// Signals that are sent prior to the notification being received by userspace are handled normally.
    pub ignore_non_fatal_signals: bool,

    /// Return ESRCH instead of a thread id on a thread sync error
    pub no_thread_id_on_sync_error: bool,
}

impl From<FilterFlags> for FullFilterFlags {
    fn from(
        FilterFlags {
            log,
            spec_allow,
            sync_threads,
            ignore_non_fatal_signals,
            no_thread_id_on_sync_error,
        }: FilterFlags,
    ) -> Self {
        Self {
            log,
            new_listener: false,
            spec_allow,
            sync_threads,
            ignore_non_fatal_signals,
            no_thread_id_on_sync_error,
        }
    }
}

/// Flags that modify the filter behavior
///
/// You can't set `no_thread_id_on_sync_error` to false, as it's incompatible with the listener creation request
#[derive(Default, Clone, Copy)]
pub struct FilterWithListenerFlags {
    /// All filter return actions except SECCOMP_RET_ALLOW should be logged.
    /// An administrator may override this filter flag by preventing specific actions
    /// from being logged via the /proc/sys/kernel/seccomp/actions_logged file.
    pub log: bool,

    /// Disable Speculative Store Bypass mitigation.
    pub spec_allow: bool,

    /// When adding a new filter, synchronize all other threads of the calling process to the same seccomp filter tree.
    /// A "filter tree" is the ordered list of filters attached to a thread.
    /// (Attaching identical filters in separate seccomp() calls results in different filters from this perspective.)
    /// If any thread cannot synchronize to the same filter tree, the call will not attach the new seccomp filter,
    /// and will fail.
    /// Synchronization will fail if another thread in the same process is in SECCOMP_MODE_STRICT or if it has attached new
    /// seccomp filters to itself, diverging from the calling thread's filter tree.
    pub sync_threads: bool,

    /// This flag makes it such that when a user notification is received by the supervisor,
    /// the notifying process will ignore non-fatal signals until the response is sent.
    /// Signals that are sent prior to the notification being received by userspace are handled normally.
    pub ignore_non_fatal_signals: bool,
}

impl From<FilterWithListenerFlags> for FullFilterFlags {
    fn from(
        FilterWithListenerFlags {
            log,
            spec_allow,
            sync_threads,
            ignore_non_fatal_signals,
        }: FilterWithListenerFlags,
    ) -> Self {
        Self {
            log,
            new_listener: true,
            spec_allow,
            sync_threads,
            ignore_non_fatal_signals,
            no_thread_id_on_sync_error: true,
        }
    }
}

/// A value that describes what to do with a system call
///
/// Possible filter actions in decreasing order of precedence
/// If an action value other than one of the below is specified, then the filter action is treated as
/// either SECCOMP_RET_KILL_PROCESS (since Linux 4.14) or SECCOMP_RET_KILL_THREAD (in Linux 4.13 and earlier).
// #[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum FilterAction {
    /// This value results in immediate termination of the process, with a core dump. The system call is not executed.  
    /// By contrast with SECCOMP_RET_KILL_THREAD below, all threads in the thread group are terminated.
    /// (For a discussion of thread groups, see the description of the CLONE_THREAD flag in clone(2).)
    ///
    /// The process terminates as though killed by a SIGSYS signal.
    /// Even if a signal handler has been registered for SIGSYS, the handler will be ignored in this case and the process always terminates.
    /// To a parent process that is waiting on this process (using waitpid(2) or similar), the returned wstatus will indicate that
    /// its child was terminated as though by a SIGSYS signal.
    ///
    /// Available since Linux 4.14
    KillProcess,

    /// This value results in immediate termination of the thread that made the system call. The system call is not executed.
    /// Other threads in the same thread group will continue to execute.
    ///
    /// The thread terminates as though killed by a SIGSYS signal. See SECCOMP_RET_KILL_PROCESS above.
    ///
    /// Before Linux 4.11, any process terminated in this way would not trigger a coredump
    /// (even though SIGSYS is documented in signal(7) as having a default action of termination with a core dump).
    /// Since Linux 4.11, a single-threaded process will dump core if terminated in this way.
    ///
    /// With the addition of SECCOMP_RET_KILL_PROCESS in Linux 4.14,
    /// SECCOMP_RET_KILL_THREAD was added as a synonym for SECCOMP_RET_KILL, in order to more clearly
    /// distinguish the two actions.
    ///
    /// Note: the use of SECCOMP_RET_KILL_THREAD to kill a single thread in a multithreaded process
    /// is likely to leave the process in a permanently inconsistent and possibly corrupt state.
    KillThread,

    /// This value results in the kernel sending a thread-directed SIGSYS signal to the triggering thread.
    /// (The system call is not executed.)  Various fields will
    /// be set in the siginfo_t structure (see sigaction(2)) associated with signal:
    ///
    /// •  si_signo will contain SIGSYS.
    ///
    /// •  si_call_addr will show the address of the system call instruction.
    ///
    /// •  si_syscall and si_arch will indicate which system call was attempted.
    ///
    /// •  si_code will contain SYS_SECCOMP.
    ///
    /// •  si_errno will contain the SECCOMP_RET_DATA portion of the filter return value.
    ///     
    /// The program counter will be as though the system call happened (i.e., the program counter will not point to the system call instruction).
    /// The return value register will contain an architecture-dependent value;
    /// if resuming execution, set it to something appropriate for the system call.  
    /// (The architecture dependency is because replacing it with ENOSYS could overwrite some useful information.)
    Trap { errno: u16 },

    /// This value results in the SECCOMP_RET_DATA portion of the filter's return value being passed to user space as the errno value
    /// without executing the system call.
    Errno { errno: u16 },

    /// Forward the system call to an attached user-space supervisor process to allow that process to decide what to do with the system call.
    /// If there is no attached supervisor (either because the filter was not installed with the SECCOMP_FILTER_FLAG_NEW_LISTENER flag
    /// or because the file descriptor was closed), the filter returns ENOSYS (similar to what happens when a filter returns
    /// SECCOMP_RET_TRACE and there is no tracer). See seccomp_unotify(2) for further details.
    ///
    /// Note that the supervisor process will not be notified if another filter returns an action value
    /// with a precedence greater than SECCOMP_RET_USER_NOTIF
    ///
    /// Available since Linux 5.0
    UserNotif,

    /// When returned, this value will cause the kernel to attempt to notify a ptrace(2)-based tracer prior to executing the system call.  
    /// If there is no tracer present, the system call is not executed and returns a failure status with errno set to ENOSYS.
    ///
    /// A tracer will be notified if it requests PTRACE_O_TRACESECCOMP using ptrace(PTRACE_SETOPTIONS).
    /// The tracer will be notified of a PTRACE_EVENT_SECCOMP and the SECCOMP_RET_DATA portion of the filter's return value
    /// will be available to the tracer via PTRACE_GETEVENTMSG.
    ///
    /// The tracer can skip the system call by changing the system call number to -1.
    /// Alternatively, the tracer can change the system call requested by changing the
    /// system call to a valid system call number.
    /// If the tracer asks to skip the system call, then the system call will appear to return the value that the tracer
    /// puts in the return value register.
    ///
    /// Before Linux 4.8, the seccomp check will not be run again after the tracer is notified.
    /// (This means that, on older kernels,
    /// seccomp-based sandboxes must not allow use of ptrace(2)—even of other sandboxed processes—without extreme care;
    /// ptracers can use this mechanism to escape from the seccomp sandbox.)
    ///
    /// Note that a tracer process will not be notified if another filter returns an action value
    /// with a precedence greater than SECCOMP_RET_TRACE.
    Trace,

    /// This value results in the system call being executed after the filter return action is logged.  
    /// An administrator may override the logging of this action via the /proc/sys/kernel/seccomp/actions_logged file.
    ///
    /// Available since Linux 4.14
    Log,

    /// This value results in the system call being executed.
    Allow,
}

impl FilterAction {
    pub fn action(&self) -> u32 {
        match self {
            FilterAction::KillProcess => SECCOMP_RET_KILL_PROCESS,
            FilterAction::KillThread => SECCOMP_RET_KILL_THREAD,
            FilterAction::Trap { .. } => SECCOMP_RET_TRAP,
            FilterAction::Errno { .. } => SECCOMP_RET_ERRNO,
            FilterAction::UserNotif => SECCOMP_RET_USER_NOTIF,
            FilterAction::Trace => SECCOMP_RET_TRACE,
            FilterAction::Log => SECCOMP_RET_LOG,
            FilterAction::Allow => SECCOMP_RET_ALLOW,
        }
    }
}

impl From<FilterAction> for u32 {
    fn from(value: FilterAction) -> Self {
        match value {
            FilterAction::Errno { errno } | FilterAction::Trap { errno } => {
                value.action() | errno as u32
            }
            _ => value.action(),
        }
    }
}
