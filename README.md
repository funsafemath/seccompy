Yet another crate that provides an interface to the
[seccomp syscall](https://manpages.debian.org/testing/manpages-dev/seccomp.2.en.html)

Seccomp allows to filter system calls that a process makes, blocking or allowing
them based on arbitrary rules

[Seccomp user notifications](https://manpages.debian.org/testing/manpages-dev/seccomp_unotify.2.en.html)
allow a userspace process to handle the system calls instead of the kernel

For userspace notifications you'll need to pass a descriptor from a target to
the supervisor. This crate does not provide such functionality; you can do this
using unix sockets or pidfd_getfd

Also, you may want to check if the descriptor can return new events, i.e. there
are alive processes that use a given seccomp filter; you should not rely on the
receive_notification return value. Instead, use a select/poll/epoll/etc... to
check if/get a notification when a descriptor has reached the EOF, there are
many crates that have functions for this

Note that seccomp cannot intercept the vDSO system calls (clock_gettime, getcpu,
gettimeofday, time on x86_64, see the
[vdso(7)](https://manpages.debian.org/testing/manpages/vdso.7.en.html) for more
info), as they run in the userspace. If you really want to intercept them, you
may either disable the vDSO for the entire system, or overwrite the
AT_SYSINFO_EHDR value in the auxilary vector before any library loads (though
the kernel memory will remain mapped, and even if you unmap it, the process can
remap it using the prctl's ARCH_MAP_VDSO_X32/32/64)

# Examples

Strict seccomp:

```rust no_run
use std::{error::Error, fs::File};

fn main() -> Result<(), Box<dyn Error>> {
    // The strict mode forbids every syscall, except for `read`, `write`, `_exit` and `sigreturn`
    // any violation will result in immediate thread termination by SIGKILL signal
    seccompy::set_strict()?;

    // Note that even without this line the process would be killed instead of exiting cleanly,
    // as rust would call `sigaltstack`, `munmap` and `exit_group`, which are not allowed
    println!("{:?}", File::open("/etc/passwd")); // <---- SIGKILLed

    println!("This code is unreachable!");

    Ok(())
}
```

Filters:

```rust
use std::{error::Error, fs, io::ErrorKind};

use libc::{SYS_exit_group, SYS_munmap, SYS_openat, SYS_sigaltstack, SYS_write};
use seccompy::{Filter, FilterAction, FilterArgs, FilterFlags};

fn main() -> Result<(), Box<dyn Error>> {
    let mut filter = Filter::new(FilterArgs::default());

    // Allow Rust to exit gracefully
    filter.add_syscall_group(
        &[SYS_sigaltstack as u32, SYS_munmap as u32, SYS_exit_group as u32],
        FilterAction::Allow,
    );

    // Allow writing to already open descriptors
    filter.add_syscall_group(&[SYS_write as u32], FilterAction::Allow);

    // Return a custom error code for a syscall, even if does not make sense
    // errno 26 is ExecutableFileBusy
    filter.add_syscall_group(
        &[SYS_openat as u32],
        FilterAction::Errno { errno: 26 },
    );

    // To set a filter, a thread must have the no_new_privs attribute or the CAP_SYS_ADMIN capability
    seccompy::set_no_new_privileges()?;

    seccompy::set_filter(FilterFlags::default(), &filter.compile()?)?;

    // Everything is ok, SYS_write is allowed
    println!("Hi!");

    // Fails with errno 26
    assert_eq!(
        fs::File::open("file.txt").unwrap_err().kind(),
        ErrorKind::ExecutableFileBusy
    );

    Ok(())
}
```

Unotify:

```rust
#![feature(unix_socket_ancillary_data)]

use std::{
    convert::Infallible,
    error::Error,
    fs::File,
    io::{self, IoSlice, Seek, Write},
    os::unix::net::{AncillaryData, SocketAncillary, UnixStream},
    process::Command,
    thread,
};

use libc::{SYS_getrandom, close};
use seccompy::{
    FilterAction, FilterWithListenerFlags, receive_notification, return_syscall,
    seccomp_bpf::filter::{Filter, FilterArgs},
    send_response,
};

fn target(tx: UnixStream) -> Result<(), Box<dyn Error>> {
    let mut filter = Filter::new(FilterArgs {
        default_action: FilterAction::Allow,
        ..Default::default()
    });

    filter.add_syscall_group(&[SYS_getrandom as u32], FilterAction::UserNotif);

    seccompy::set_no_new_privileges().unwrap();

    let descriptor = seccompy::set_filter_with_listener(
        FilterWithListenerFlags {
            ..Default::default()
        },
        &filter.compile()?,
    )?;

    let mut ancillary_buffer = [0; 32];
    let mut ancillary = SocketAncillary::new(&mut ancillary_buffer[..]);
    ancillary.add_fds(&[descriptor]);

    // We must send some real data to be able to send ancillary data
    tx.send_vectored_with_ancillary(&[IoSlice::new(&[0; 1])], &mut ancillary)?;

    // close target's copy of the descriptor (optionally)
    // also it has the close_on_exec flag
    unsafe { close(descriptor) };

    let random_number = || {
        str::from_utf8(
            &Command::new("python3")
                .arg("-c")
                .arg("import random; print(random.randint(1,100))")
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .parse::<i32>()
        .unwrap()
    };

    let first_random_number = random_number();

    let second_random_number = random_number();

    println!(
        "First process returned {first_random_number}, second process returned {second_random_number}"
    );

    assert_eq!(first_random_number, second_random_number);

    Ok(())
}

fn supervisor(rx: UnixStream) -> Result<Infallible, Box<dyn Error>> {
    let mut ancillary_buffer = [0; 32];
    let mut ancillary = SocketAncillary::new(&mut ancillary_buffer[..]);

    rx.recv_vectored_with_ancillary(&mut [], &mut ancillary)?;

    let AncillaryData::ScmRights(mut scm_rights) = ancillary.messages().next().unwrap().unwrap()
    else {
        unreachable!()
    };

    let descriptor = scm_rights.next().unwrap();

    loop {
        let noti = receive_notification(descriptor)?;

        // Note that writing into the target's memory is never safe:
        // syscalls can be interrupted, so you can corrupt the target's memory;
        // the process may be dead, and you'll (really unlikely) write into another process' memory;
        // you can use the `ignore_non_fatal_signals` flag to exclude the first case
        let mut memory = File::options()
            .write(true)
            .open(format!("/proc/{}/mem", noti.pid))?;

        memory.seek(io::SeekFrom::Start(noti.data.args[0]))?;

        memory.write_all(&b"\0".repeat(noti.data.args[1] as usize))?;

        send_response(descriptor, return_syscall(noti, noti.data.args[1] as i64))?;
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let (tx, rx) = UnixStream::pair()?;

    let handle = thread::spawn(|| {
        target(tx).unwrap();
    });

    // supervisor will eventually return with an error
    let _ = supervisor(rx).unwrap_err();

    handle.join().unwrap();

    Ok(())
}
```

TODO:

- [ ] Tests
- [ ] Document all public functions
