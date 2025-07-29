use std::{error::Error, fmt::Display};

use crate::bpf::primitive::{Condition, Operand};

use super::{
    instruction::Instruction,
    primitive::{AddressingMode, ReturnValue, Size},
};

#[derive(Debug)]
pub enum StatementError {
    TooLargeBody(usize),
    TooLargeCondition(usize),
    EmptyCondition,
}

impl Display for StatementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StatementError::TooLargeBody(size) => {
                write!(
                    f,
                    "body contained {size} instructions, which is more than the maximum of {}",
                    u8::MAX
                )
            }
            StatementError::TooLargeCondition(size) => {
                write!(
                    f,
                    "condition contained {size} instructions, which is more than the maximum of {}",
                    (u8::MAX as u16) + 1
                )
            }
            StatementError::EmptyCondition => write!(f, "condition cannot be empty"),
        }
    }
}

impl Error for StatementError {}

/// Return the immediate value (instruction data)
pub fn return_immediate(data: u32) -> Instruction {
    Instruction::Return {
        return_value: ReturnValue::Immediate,
        data,
    }
}

/// Load the data from the arguments provided to the BPF program into accumulator register
pub fn load_input(size: Size, offset: u32) -> Instruction {
    Instruction::LoadAccumulator {
        addressing_mode: AddressingMode::ProgramInput,
        size,
        data: offset,
    }
}

pub struct IfCondition {
    pub condition: Condition,
    pub operand: Operand,
    pub data: u32,
}

impl IfCondition {
    pub fn eq(data: u32) -> Self {
        Self {
            condition: Condition::Equal,
            operand: Operand::Immediate,
            data,
        }
    }
}

pub fn if_statement(
    IfCondition {
        condition,
        operand,
        data,
    }: IfCondition,
    body: Vec<Instruction>,
) -> Option<Vec<Instruction>> {
    let mut ixs = vec![Instruction::Jump {
        condition,
        operand,
        data,
        // true => execute the body
        jump_offset_if_true: 0,
        // false => skip the body
        jump_offset_if_false: u8::try_from(body.len()).ok()?,
    }];
    ixs.extend(body);
    Some(ixs)
}

pub fn if_not_statement(
    IfCondition {
        condition,
        operand,
        data,
    }: IfCondition,
    body: Vec<Instruction>,
) -> Option<Vec<Instruction>> {
    let mut ixs = vec![Instruction::Jump {
        condition,
        operand,
        data,
        // true => skip the body
        jump_offset_if_true: u8::try_from(body.len()).ok()?,
        // false => execute the body
        jump_offset_if_false: 0,
    }];
    ixs.extend(body);
    Some(ixs)
}

pub fn if_or_statement(
    terms_any: Vec<IfCondition>,
    body: Vec<Instruction>,
) -> Result<Vec<Instruction>, StatementError> {
    // Each condition is a single instruction; if there are n conditions and the body contains m instructions,
    // we need to jump (n - 1) instructions if the first condition is true,
    // (n - 2) if the second condition is true, ..., (n - n) = 0 if the last one is true.
    // If a condition is false, we need to jump 0 instructions,
    // except if it's the last one -- in that case we need to jump m instructions to skip the body
    //
    // If the `terms_any` vec is empty, return an error, though logically the body should've been skipped, as the or(empty set) is
    // vacuously false, but there's basically no reason have empty `or` statements, they count towards the ix limit, and an
    // error may catch some bugs early
    if terms_any.is_empty() {
        return Err(StatementError::EmptyCondition);
    }

    let Ok(body_len) = u8::try_from(body.len()) else {
        return Err(StatementError::TooLargeBody(body.len()));
    };

    let Ok(terms_max_index) = u8::try_from(terms_any.len() - 1) else {
        return Err(StatementError::TooLargeCondition(terms_any.len()));
    };

    let mut ixs = vec![];
    for (
        i,
        IfCondition {
            condition,
            operand,
            data,
        },
    ) in terms_any.into_iter().enumerate()
    {
        let conditions_remaining = terms_max_index - u8::try_from(i).unwrap();
        let jump_offset_if_false = if conditions_remaining == 0 {
            body_len
        } else {
            0
        };
        ixs.push(Instruction::Jump {
            condition,
            operand,
            data,
            // Unwrap is obviously ok here: terms_max_index is an u8, and 0 <= i <= terms_max_index
            jump_offset_if_true: conditions_remaining,
            jump_offset_if_false,
        });
    }
    ixs.extend(body);
    Ok(ixs)
}
