use libc::{_IOW, _IOWR, Ioctl, seccomp_data};

#[cfg(not(target_os = "android"))]
use libc::{seccomp_notif, seccomp_notif_addfd, seccomp_notif_resp};
#[cfg(target_os = "android")]
mod seccomp_unotify_structs {
    use libc::__s32;
    use libc::__s64;
    use libc::__u32;
    use libc::__u64;
    use libc::seccomp_data;

    #[repr(C)]
    #[derive(Debug, Eq, Hash, PartialEq, Clone, Copy)]
    pub struct seccomp_notif {
        pub id: __u64,
        pub pid: __u32,
        pub flags: __u32,
        pub data: seccomp_data,
    }

    #[repr(C)]
    #[derive(Debug, Eq, Hash, PartialEq, Clone, Copy)]
    pub struct seccomp_notif_resp {
        pub id: __u64,
        pub val: __s64,
        pub error: __s32,
        pub flags: __u32,
    }

    #[repr(C)]
    #[derive(Debug, Eq, Hash, PartialEq, Clone, Copy)]
    pub struct seccomp_notif_addfd {
        pub id: __u64,
        pub flags: __u32,
        pub srcfd: __u32,
        pub newfd: __u32,
        pub newfd_flags: __u32,
    }
}
#[cfg(target_os = "android")]
use seccomp_unotify_structs::*;

pub mod add_descriptor;
pub mod check_validity;
pub mod receive_noti;
pub mod send_response;

pub use add_descriptor::{AddDescriptorError, AddDescriptorOptions, add_descriptor_to_target};
pub use check_validity::{CheckValidityError, check_validity};
pub use receive_noti::{ReceiveNotificationError, receive_notification};
pub use send_response::{
    SendResponseError, continue_syscall, fail_syscall, return_syscall, send_response,
};

type SeccompNotif = seccomp_notif;

type SeccompNotifResponse = seccomp_notif_resp;

type SeccompData = seccomp_data;

type SeccompNotifAddDescriptor = seccomp_notif_addfd;

enum UnotifyOperation {
    ReceiveNotification,
    Respond,
    CheckValidity,
    AddDescriptorToTarget,
    // There's also a SECCOMP_IOCTL_NOTIF_SET_FLAGS operation which sets the event flags, but
    // it's not documented anywhere except one commit message,
    // and the only flag available just makes the kernel to complete the operation on the same CPU,
    // which makes the context switch a few times faster if the code is synchronous,
    // see commit 48a1084a8b742364 in the linux source tree
}

impl UnotifyOperation {
    // #define SECCOMP_IOC_MAGIC		'!'
    const DEVICE_ID: u32 = b'!' as u32;
}

impl From<UnotifyOperation> for Ioctl {
    fn from(value: UnotifyOperation) -> Self {
        match value {
            // #define SECCOMP_IOCTL_NOTIF_RECV	SECCOMP_IOWR(0, struct seccomp_notif)
            UnotifyOperation::ReceiveNotification => {
                _IOWR::<SeccompNotif>(UnotifyOperation::DEVICE_ID, 0)
            }

            // #define SECCOMP_IOCTL_NOTIF_SEND	SECCOMP_IOWR(1,	struct seccomp_notif_resp)
            UnotifyOperation::Respond => {
                _IOWR::<SeccompNotifResponse>(UnotifyOperation::DEVICE_ID, 1)
            }

            // #define SECCOMP_IOCTL_NOTIF_ID_VALID	SECCOMP_IOW(2, __u64)
            UnotifyOperation::CheckValidity => _IOW::<u64>(UnotifyOperation::DEVICE_ID, 2),

            // #define SECCOMP_IOCTL_NOTIF_ADDFD	SECCOMP_IOW(3, struct seccomp_notif_addfd)
            UnotifyOperation::AddDescriptorToTarget => {
                _IOW::<SeccompNotifAddDescriptor>(UnotifyOperation::DEVICE_ID, 3)
            }
        }
    }
}
