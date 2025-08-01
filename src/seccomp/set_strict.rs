use core::ffi::c_int;
use std::{error::Error, fmt::Display};

use libc::EINVAL;

use crate::seccomp::{Operation, seccomp};

#[derive(Debug)]
pub enum SetStrictModeError {
    /// A secure computing mode has already been set, and operation differs from the existing setting.
    ///
    /// operation is unknown or is not supported by this kernel version or configuration.
    ConflictingModeOrUnsupported,

    /// Any error that's generally not returned for a given operation as per the seccomp(2) manpage
    Unknown(c_int),
}

impl Display for SetStrictModeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SetStrictModeError::ConflictingModeOrUnsupported => write!(
                f,
                "strict mode seccomp is not supported or incompatible seccomp operation mode is already set"
            ),
            SetStrictModeError::Unknown(error_code) => {
                write!(f, "{}", crate::error::format_unknown_error(*error_code))
            }
        }
    }
}

impl Error for SetStrictModeError {}

/// Set the thread seccomp mode to the strict mode
///
/// In the strict mode the thread can make only the read, write, _exit and sigreturn system calls, any other
/// system call will lead to the thread termination with the SIGKILL signal
///
/// # Examples
///
/// ```no_run
/// use std::fs::File;
/// use seccompy;
///
/// seccompy::set_strict();
///
/// println!("Bye, world!");  // This will work: stdout was already open, and write syscall is allowed
///
/// File::open("touch");      // SIGKILLed
///
/// ```
/// The only system calls that the calling thread is permitted to make are read(2), write(2), _exit(2)
/// (but not exit_group(2)), and sigreturn(2).  
/// Other system calls result in the termination of the calling thread,
/// or termination of the entire process with the SIGKILL signal when there is only one thread.
/// Strict secure computing mode is useful for number-crunching applications that may need to execute untrusted byte code,
/// perhaps obtained by reading from a pipe or socket.
///
/// Note that although the calling thread can no longer call sigprocmask(2), it can use sigreturn(2)
/// to block all signals apart from SIGKILL and SIGSTOP.  
/// This means that alarm(2) (for example) is not sufficient for restricting the process's execution time.
/// Instead, to reliably terminate the process, SIGKILL must be used.  
/// This can be done by using timer_create(2) with SIGEV_SIGNAL and sigev_signo set to SIGKILL,
/// or by using setrlimit(2) to set the hard limit for RLIMIT_CPU.
pub fn set_strict() -> Result<(), SetStrictModeError> {
    match seccomp(Operation::SetModeStrict) {
        0 => Ok(()),
        -1 => match crate::error::errno() {
            EINVAL => Err(SetStrictModeError::ConflictingModeOrUnsupported),
            other => Err(SetStrictModeError::Unknown(other)),
        },

        // For non-filter operations the return value is always 0 or -1
        _ => unreachable!(),
    }
}
