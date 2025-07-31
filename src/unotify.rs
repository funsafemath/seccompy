use libc::{_IOW, _IOWR, seccomp_data, seccomp_notif, seccomp_notif_addfd, seccomp_notif_resp};

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

#[repr(u64)]
enum UnotifyOperation {
    // #define SECCOMP_IOCTL_NOTIF_RECV	SECCOMP_IOWR(0, struct seccomp_notif)
    ReceiveNotification = _IOWR::<SeccompNotif>(Self::DEVICE_ID, 0),

    // #define SECCOMP_IOCTL_NOTIF_SEND	SECCOMP_IOWR(1,	struct seccomp_notif_resp)
    Respond = _IOWR::<SeccompNotifResponse>(Self::DEVICE_ID, 1),

    // #define SECCOMP_IOCTL_NOTIF_ID_VALID	SECCOMP_IOW(2, __u64)
    CheckValidity = _IOW::<u64>(Self::DEVICE_ID, 2),

    // #define SECCOMP_IOCTL_NOTIF_ADDFD	SECCOMP_IOW(3, struct seccomp_notif_addfd)
    AddDescriptorToTarget = _IOW::<SeccompNotifAddDescriptor>(Self::DEVICE_ID, 3),
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
