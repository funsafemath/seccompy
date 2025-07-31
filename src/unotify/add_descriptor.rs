use core::ffi::c_int;
use std::{error::Error, fmt::Display};

use libc::{
    EBADF, EBUSY, EMFILE, ENOENT, O_CLOEXEC, SECCOMP_ADDFD_FLAG_SEND, SECCOMP_ADDFD_FLAG_SETFD,
};

use crate::unotify::{SeccompNotif, SeccompNotifAddDescriptor, UnotifyOperation};

#[derive(Debug)]
pub enum AddDescriptorError {
    /// The provided source descriptor was invalid
    ///
    /// Allocating the file descriptor in the target would cause the target's RLIMIT_NOFILE limit to be exceeded (see getrlimit(2))
    InvalidSourceOrTargetDescriptor,

    /// If the flag SECCOMP_IOCTL_NOTIF_SEND is used,
    /// this means the operation can't proceed until other SECCOMP_IOCTL_NOTIF_ADDFD requests are processed
    AddDescriptorQueueNotEmpty,

    /// The file descriptor number specified in newfd exceeds the limit specified in /proc/sys/fs/nr_open
    InvalidTargetDescriptor,

    /// The blocked system call in the target has been interrupted by a signal handler or the target has terminated.
    Interrupted,

    Unknown(c_int),
}

impl Display for AddDescriptorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddDescriptorError::InvalidSourceOrTargetDescriptor => write!(
                f,
                "allocating a new descriptor would cause the target descriptor limit to be exceeded"
            ),
            AddDescriptorError::AddDescriptorQueueNotEmpty => write!(
                f,
                "cannot send an atomic add_descriptor_to_target & respond while the add descriptor queue is not empty"
            ),
            AddDescriptorError::InvalidTargetDescriptor => write!(
                f,
                "target descriptor number exceeds the limit specified in /proc/sys/fs/nr_open"
            ),
            AddDescriptorError::Interrupted => {
                write!(f, "target thread was killed or system call was interrupted")
            }
            Self::Unknown(error_code) => {
                write!(f, "{}", crate::error::format_unknown_error(*error_code))
            }
        }
    }
}

impl Error for AddDescriptorError {}

#[derive(Default, Debug, Clone, Copy)]
pub struct AddDescriptorOptions {
    /// When allocating the file descriptor in the target, use the file descriptor number specified in the newfd field.
    pub target_descriptor_number: Option<c_int>,

    /// Perform the equivalent of SECCOMP_IOCTL_NOTIF_ADDFD plus SECCOMP_IOCTL_NOTIF_SEND as an atomic operation.
    /// On successful invocation, the target process's errno will be 0
    /// and the return value will be the file descriptor number that was allocated in the target.  
    /// If allocating the file descriptor in the target fails, the target's system call continues to be blocked until a successful response is sent.
    pub add_and_respond: bool,

    /// Set the close-on-exec flag on the received file descriptor.
    pub set_descriptor_close_on_exec: bool,
}

impl AddDescriptorOptions {
    fn request_flags(&self) -> u32 {
        let mut flags = 0;
        if self.target_descriptor_number.is_some() {
            flags |= SECCOMP_ADDFD_FLAG_SETFD;
        }
        if self.add_and_respond {
            flags |= SECCOMP_ADDFD_FLAG_SEND
        }
        flags as u32
    }

    fn descriptor(&self) -> c_int {
        self.target_descriptor_number.unwrap_or_default()
    }

    fn descriptor_flags(&self) -> u32 {
        if self.set_descriptor_close_on_exec {
            O_CLOEXEC as u32
        } else {
            0
        }
    }
}

/// Add a copy of a supervisor descriptor to the target's descriptor table
///
/// After the operation, the supervisor can close its copy of the descriptor
// TODO: split into `add_descriptor_to_target` and `add_descriptor_to_target_and_respond` that consumes `self`?
// the problem is that on failure `add_descriptor_to_target_and_respond` must return `self` instead of dropping it
pub fn add_descriptor_to_target(
    descriptor: c_int,
    notification: &SeccompNotif,
    source_descriptor: c_int,
    options: AddDescriptorOptions,
) -> Result<c_int, AddDescriptorError> {
    let add_descriptor_request = SeccompNotifAddDescriptor {
        id: notification.id,
        flags: options.request_flags(),
        srcfd: source_descriptor as u32,
        newfd: options.descriptor() as u32,
        newfd_flags: options.descriptor_flags(),
    };

    match unsafe {
        libc::ioctl(
            descriptor,
            UnotifyOperation::AddDescriptorToTarget as u64,
            // Kernel only copies the data, so a const pointer is ok
            &add_descriptor_request as *const SeccompNotifAddDescriptor,
        )
    } {
        -1 => Err(match crate::error::errno() {
            EBADF => AddDescriptorError::InvalidSourceOrTargetDescriptor,
            EBUSY => AddDescriptorError::AddDescriptorQueueNotEmpty,
            EMFILE => AddDescriptorError::InvalidTargetDescriptor,
            ENOENT => AddDescriptorError::Interrupted,
            other => AddDescriptorError::Unknown(other as c_int),
        }),
        descriptor => Ok(descriptor),
    }
}
