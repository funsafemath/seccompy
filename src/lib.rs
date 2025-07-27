//! A crate that provides an interface to the seccomp syscall.
//!
//! Seccomp allows to filter system calls that a process makes, blocking or allowing them based on arbitrary rules.
//!
//! Seccomp user notifications allow a userspace process to handle the system calls instead of the kernel.
//!
//! Crate state:
//! - [x] Seccomp module
//! - [ ] BPF module
//! - [ ] Unotify module

mod error;

mod prctl;

pub mod seccomp;

pub use seccomp::{FilterAction, FilterFlags};

pub use seccomp::{CheckActionError, is_action_available};
pub use seccomp::{SetFilterError, SetFilterResult, set_filter};
pub use seccomp::{SetStrictModeError, set_strict};

// Probably should not be pub used: it's almost useless, and also it can be accessed through the seccomp module
// pub use seccomp::{GetNotificationSizesError, NotificationSizes, get_notification_sizes};

pub use prctl::{get_no_new_privileges, set_no_new_privileges};
