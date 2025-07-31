Yet another crate that provides an interface to the
[seccomp syscall](https://manpages.debian.org/testing/manpages-dev/seccomp.2.en.html)

Seccomp allows to filter system calls that a process makes, blocking or allowing
them based on arbitrary rules

[Seccomp user notifications](https://manpages.debian.org/testing/manpages-dev/seccomp_unotify.2.en.html)
allow a userspace process to handle the system calls instead of the kernel

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
        &[SYS_sigaltstack, SYS_munmap, SYS_exit_group].map(|x| x as u32),
        FilterAction::Allow,
    );

    // Allow writing to already open descriptors
    filter.add_syscall_group(&[SYS_write].map(|x| x as u32), FilterAction::Allow);

    // Return a custom error code for a syscall, even if does not make sense
    // errno 26 is ExecutableFileBusy
    filter.add_syscall_group(
        &[SYS_openat].map(|x| x as u32),
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

Crate state:

- [x] Seccomp module
- [x] BPF module
- [ ] Unotify module

TODO:

- [ ] Examples in the README
  - [x] Basic seccomp
  - [x] Filters
  - [ ] Unotify
- [ ] Tests
- [ ] Document all public functions
