use libc::sock_filter;

#[cfg(not(target_os = "android"))]
use libc::{EM_AARCH64, EM_X86_64};
#[cfg(target_os = "android")]
mod architectures {
    pub const EM_X86_64: u16 = 62;
    pub const EM_AARCH64: u16 = 183;
}
#[cfg(target_os = "android")]
use architectures::*;

pub mod instruction;
pub mod primitive;
pub mod statement;

pub type BpfInstruction = sock_filter;

/// Architecture whose syscall convention was used for the syscall invocation
///
/// Because numbering of system calls varies between architectures and some architectures (e.g., x86-64)
/// allow user-space code to use the calling conventions of multiple architectures
/// (and the convention being used may vary over the life of a process that uses `execve(2)`
/// to execute binaries that employ the different conventions),
/// it is usually necessary to verify the value of the arch field.
///
/// It is strongly recommended to use an allow-list approach whenever possible because such an approach is more robust and simple.
/// A deny-list will have to be updated whenever a potentially dangerous system call is added
/// (or a dangerous flag or option if those are deny-listed), and it is often possible to alter the representation
/// of a value without altering its meaning, leading to a deny-list bypass. See also Caveats in the `seccomp(2)` manpage.
///
/// The arch field is not unique for all calling conventions.
/// The x86-64 ABI and the x32 ABI both use `AUDIT_ARCH_X86_64` as arch, and they run on the same processors.
/// Instead, the mask `__X32_SYSCALL_BIT` is used on the system call number to tell the two ABIs apart.
///
/// This means that a policy must either deny all syscalls with `__X32_SYSCALL_BIT` or it must recognize syscalls with and without
/// `__X32_SYSCALL_BIT` set. A list of system calls to be denied based on nr that does not
/// also contain nr values with `__X32_SYSCALL_BIT` set can be bypassed by a malicious program that sets `__X32_SYSCALL_BIT`.
///
/// Additionally, kernels prior to Linux 5.4 incorrectly permitted nr in the ranges 512-547
/// as well as the corresponding non-x32 syscalls `OR`ed with `__X32_SYSCALL_BIT`.
/// For example, nr == 521 and nr == (101 | `__X32_SYSCALL_BIT`) would result in invocations of `ptrace(2)`
/// with potentially confused x32-vs-x86_64 semantics in the kernel.
/// Policies intended to work on kernels before Linux 5.4 must ensure that they deny or otherwise correctly handle these system calls.
/// On Linux 5.4 and newer, such system calls will fail with the error `ENOSYS`, without doing anything.
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum Architecture {
    // #define AUDIT_ARCH_X86_64	(EM_X86_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
    X86_64 = EM_X86_64 as u32 | Self::ARCH_64_BIT | Self::ARCH_LE,

    // #define AUDIT_ARCH_AARCH64	(EM_AARCH64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
    Aarch64 = EM_AARCH64 as u32 | Self::ARCH_64_BIT | Self::ARCH_LE,
}

impl Architecture {
    // #define __AUDIT_ARCH_64BIT 0x80000000
    const ARCH_64_BIT: u32 = 0x8000_0000;

    // #define __AUDIT_ARCH_LE	   0x40000000
    const ARCH_LE: u32 = 0x4000_0000;

    /// Get the compile time architecture
    pub const fn compile_time_arch() -> Self {
        #[cfg(target_arch = "x86_64")]
        return Self::X86_64;
        #[cfg(target_arch = "aarch64")]
        return Self::Aarch64;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            compile_error!(
                "compile_time_arch() not implemented for the target architecture, you may want to extend the Architecture enum"
            );
            unimplemented!()
        }
    }
}
