use super::{
    BpfInstruction,
    primitive::{AddressingMode, Condition, InstructionType, Operand, ReturnValue, Size},
};

#[derive(Debug, Clone)]
pub enum Instruction {
    // Addressing mode sets are different for the LoadAccumulator and LoadIndex, so having a single Load instruction would be incorrect
    LoadAccumulator {
        addressing_mode: AddressingMode,
        size: Size,
        data: u32,
    },
    Jump {
        condition: Condition,
        operand: Operand,
        data: u32,

        // Note that the offsets apply after incrementing the instruction pointer, or, equivalently,
        // these jump to (address of the jump instruction + value + 1)
        jump_offset_if_true: u8,
        jump_offset_if_false: u8,
    },
    Return {
        return_value: ReturnValue,
        data: u32,
    },
}

impl Instruction {
    const fn instruction_type(&self) -> InstructionType {
        match self {
            Self::LoadAccumulator { .. } => InstructionType::LoadAccumulator,
            Self::Jump { .. } => InstructionType::Jump,
            Self::Return { .. } => InstructionType::Return,
        }
    }

    const fn opcode(&self) -> u16 {
        self.instruction_type() as u16
            | match self {
                Self::LoadAccumulator {
                    addressing_mode,
                    size,
                    ..
                } => *addressing_mode as u16 | *size as u16,
                Self::Jump {
                    condition, operand, ..
                } => *condition as u16 | *operand as u16,
                Self::Return { return_value, .. } => *return_value as u16,
            }
    }

    const fn jump_offsets(&self) -> (u8, u8) {
        match self {
            Self::Jump {
                jump_offset_if_true: offset_true,
                jump_offset_if_false: offset_false,
                ..
            } => (*offset_true, *offset_false),
            _ => (0, 0),
        }
    }

    const fn data(&self) -> u32 {
        *match self {
            Self::LoadAccumulator { data, .. }
            | Self::Jump { data, .. }
            | Self::Return { data, .. } => data,
        }
    }
}

impl From<Instruction> for BpfInstruction {
    fn from(value: Instruction) -> Self {
        let (jump_offset_if_true, jump_offset_if_false) = value.jump_offsets();
        Self {
            code: value.opcode(),
            jt: jump_offset_if_true,
            jf: jump_offset_if_false,
            k: value.data(),
        }
    }
}
