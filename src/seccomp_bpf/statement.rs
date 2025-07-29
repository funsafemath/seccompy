use std::mem;

use libc::seccomp_data;

use crate::{
    FilterAction,
    bpf::{self, instruction::Instruction, primitive::Size},
};

#[repr(u32)]
pub enum Offset {
    SyscallNumber = mem::offset_of!(seccomp_data, nr) as u32,
    Architecture = mem::offset_of!(seccomp_data, arch) as u32,
}

/// Loads the `seccomp_data[offset..offset+4]` into the accumulator register
pub fn load_offset(offset: Offset) -> Instruction {
    bpf::statement::load_input(Size::Word, offset as u32)
}

/// Loads the syscall number into the accumulator register
pub fn load_syscall() -> Instruction {
    load_offset(Offset::SyscallNumber)
}

/// Loads the architecture into the accumulator register
pub fn load_architecture() -> Instruction {
    load_offset(Offset::Architecture)
}

pub fn return_action(action: FilterAction) -> Instruction {
    bpf::statement::return_immediate(u32::from(action))
}
