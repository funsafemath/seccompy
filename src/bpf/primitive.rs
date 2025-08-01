use libc::{
    BPF_A, BPF_ABS, BPF_ALU, BPF_IMM, BPF_JA, BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JMP, BPF_JSET, BPF_K,
    BPF_LD, BPF_LDX, BPF_RET, BPF_ST, BPF_STX, BPF_W, BPF_X,
};

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
