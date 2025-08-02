#[cfg(not(target_os = "android"))]
use libc::{
    BPF_A, BPF_ABS, BPF_ALU, BPF_IMM, BPF_JA, BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JMP, BPF_JSET, BPF_K,
    BPF_LD, BPF_LDX, BPF_RET, BPF_ST, BPF_STX, BPF_W, BPF_X,
};
#[cfg(target_os = "android")]
mod bpf_flags {
    use libc::__u32;

    // linux/bpf_common.h
    pub const BPF_LD: __u32 = 0x00;
    pub const BPF_LDX: __u32 = 0x01;
    pub const BPF_ST: __u32 = 0x02;
    pub const BPF_STX: __u32 = 0x03;
    pub const BPF_ALU: __u32 = 0x04;
    pub const BPF_JMP: __u32 = 0x05;
    pub const BPF_RET: __u32 = 0x06;
    pub const BPF_MISC: __u32 = 0x07;
    pub const BPF_W: __u32 = 0x00;
    pub const BPF_H: __u32 = 0x08;
    pub const BPF_B: __u32 = 0x10;
    pub const BPF_IMM: __u32 = 0x00;
    pub const BPF_ABS: __u32 = 0x20;
    pub const BPF_IND: __u32 = 0x40;
    pub const BPF_MEM: __u32 = 0x60;
    pub const BPF_LEN: __u32 = 0x80;
    pub const BPF_MSH: __u32 = 0xa0;
    pub const BPF_ADD: __u32 = 0x00;
    pub const BPF_SUB: __u32 = 0x10;
    pub const BPF_MUL: __u32 = 0x20;
    pub const BPF_DIV: __u32 = 0x30;
    pub const BPF_OR: __u32 = 0x40;
    pub const BPF_AND: __u32 = 0x50;
    pub const BPF_LSH: __u32 = 0x60;
    pub const BPF_RSH: __u32 = 0x70;
    pub const BPF_NEG: __u32 = 0x80;
    pub const BPF_MOD: __u32 = 0x90;
    pub const BPF_XOR: __u32 = 0xa0;
    pub const BPF_JA: __u32 = 0x00;
    pub const BPF_JEQ: __u32 = 0x10;
    pub const BPF_JGT: __u32 = 0x20;
    pub const BPF_JGE: __u32 = 0x30;
    pub const BPF_JSET: __u32 = 0x40;
    pub const BPF_K: __u32 = 0x00;
    pub const BPF_X: __u32 = 0x08;

    // linux/filter.h
    pub const BPF_A: __u32 = 0x10;
    pub const BPF_TAX: __u32 = 0x00;
    pub const BPF_TXA: __u32 = 0x80;
}
#[cfg(target_os = "android")]
use bpf_flags::*;

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum InstructionType {
    LoadAccumulator = BPF_LD as u16,
    LoadIndex = BPF_LDX as u16,

    // Note that these don't need an addressing mode, as they load data from the scratch memory
    StoreAccumulator = BPF_ST as u16,
    StoreIndex = BPF_STX as u16,

    Arithmetic = BPF_ALU as u16,

    Jump = BPF_JMP as u16,

    Return = BPF_RET as u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum AddressingMode {
    Immediate = BPF_IMM as u16,
    ProgramInput = BPF_ABS as u16,
}

/// The `BPF_H` and `BPF_B` size modifiers are not supported by the seccomp: all operations must load and store (4-byte) words (`BPF_W`).
#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum Size {
    Word = BPF_W as u16,
    // HalfWord = BPF_H as u16,
    // Byte = BPF_B as u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum Condition {
    /// Always jumps to the destination. Uses the 32-bit instruction data as the offset
    Always = BPF_JA as u16,
    /// `==`
    Equal = BPF_JEQ as u16,
    /// Unsigned `>`
    Greater = BPF_JGT as u16,
    /// Unsigned `>=`
    GreaterOrEqual = BPF_JGE as u16,
    /// Jump if `dst & src`
    BitSet = BPF_JSET as u16,
}

// Used by the arithmetic and jump instructions
#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum Operand {
    Immediate = BPF_K as u16,
    IndexRegister = BPF_X as u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum ReturnValue {
    Accumulator = BPF_A as u16,
    Immediate = BPF_K as u16,
}
