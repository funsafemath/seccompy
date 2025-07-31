#![doc = include_str!("./../README.md")]

mod error;

mod prctl;

pub mod seccomp;

pub use seccomp::FilterAction;

pub use seccomp::{CheckActionError, is_action_available};
pub use seccomp::{
    FilterFlags, FilterWithListenerFlags, SetFilterError, set_filter, set_filter_with_listener,
};
pub use seccomp::{SetStrictModeError, set_strict};

// Probably should not be pub used: it's almost useless, and also it can be accessed through the seccomp module
// pub use seccomp::{GetNotificationSizesError, NotificationSizes, get_notification_sizes};

pub use prctl::{get_no_new_privileges, set_no_new_privileges};

pub mod bpf;

pub mod seccomp_bpf;

pub use seccomp_bpf::filter::{Filter, FilterArgs};
