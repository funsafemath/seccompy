Yet another crate that provides an interface to the
[seccomp syscall](https://manpages.debian.org/testing/manpages-dev/seccomp.2.en.html)

Seccomp allows to filter system calls that a process makes, blocking or allowing
them based on arbitrary rules

[Seccomp user notifications](https://manpages.debian.org/testing/manpages-dev/seccomp_unotify.2.en.html)
allow a userspace process to handle the system calls instead of the kernel

# Examples

Strict seccomp:

```no_run
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

Crate state:

- [x] Seccomp module
- [x] BPF module
- [ ] Unotify module

TODO:

- [ ] Examples in the README
  - [x] Basic seccomp
  - [ ] Filters
  - [ ] Unotify
- [ ] Tests
- [ ] Document all public functions
