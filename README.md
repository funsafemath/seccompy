Yet another crate that provides an interface to the
[seccomp syscall](https://manpages.debian.org/testing/manpages-dev/seccomp.2.en.html)

Seccomp allows to filter system calls that a process makes, blocking or allowing
them based on arbitrary rules

[Seccomp user notifications](https://manpages.debian.org/testing/manpages-dev/seccomp_unotify.2.en.html)
allow a userspace process to handle the system calls instead of the kernel

Crate state:

- [x] Seccomp module
- [ ] BPF module
- [ ] Unotify module
