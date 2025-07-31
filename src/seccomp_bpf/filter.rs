use std::{collections::HashMap, error::Error, fmt::Display};

use libc::BPF_MAXINSNS;

use crate::{
    FilterAction,
    bpf::{
        self, Architecture, BpfInstruction,
        instruction::Instruction,
        statement::{IfCondition, if_or_statement},
    },
    seccomp_bpf::statement::{self, return_action},
};

#[derive(Debug)]
pub enum VerificationError {
    TooManyInstructions { has: usize, max: usize },
    DuplicateSyscall { syscall: u32 },
}

impl Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyInstructions { has, max } => write!(
                f,
                "filter contains {has} instructions, which is more than the maximum of {max}",
            ),
            Self::DuplicateSyscall { syscall } => {
                write!(f, "filter contains a duplicate syscall: {syscall}",)
            }
        }
    }
}

impl Error for VerificationError {}

pub struct FilterArgs {
    pub default_action: FilterAction,
    pub arch: Architecture,
    pub arch_mismatch_action: FilterAction,
    pub max_instruction_count: usize,
}

/// Default action: killing the thread,
/// Default arch: compile-time arch,
/// Default arch mismatch action: killing the thread,
/// Default max instruction count: the BPF_MAXINSNS, which is the limit for non-CAP_SYS_ADMIN processes (threads, actually)
impl Default for FilterArgs {
    fn default() -> Self {
        Self {
            default_action: FilterAction::KillThread,
            arch: Architecture::compile_time_arch(),
            arch_mismatch_action: FilterAction::KillThread,
            max_instruction_count: BPF_MAXINSNS as usize,
        }
    }
}

/// A structure that helps to build a syscall filter BPF bytecode for the [seccomp::set_filter](crate::seccomp::set_filter::set_filter) function
/// Be sure to read the [Architecture] docs: a x86_64 program may call the x86 syscalls,
/// so you need to either explicitly disable them by checking if the X32_SYSCALL_BIT bit is set, or implement them,
/// or, better off, not make a denylist
pub struct Filter {
    default_action: FilterAction,
    arch: Architecture,
    arch_mismatch_action: FilterAction,
    instructions: Vec<Instruction>,
    max_instruction_count: usize,
    syscall_count: HashMap<u32, usize>,
}

impl Filter {
    pub fn new(
        FilterArgs {
            default_action,
            arch,
            arch_mismatch_action,
            max_instruction_count,
        }: FilterArgs,
    ) -> Self {
        let mut filter = Self {
            default_action,
            arch,
            arch_mismatch_action,
            instructions: vec![],
            max_instruction_count,
            syscall_count: HashMap::new(),
        };
        filter.begin();
        filter
    }

    fn push(&mut self, ix: Instruction) {
        self.instructions.push(ix);
    }

    fn extend(&mut self, ixs: Vec<Instruction>) {
        self.instructions.extend(ixs);
    }

    fn verify_architecture(&mut self) {
        // A register: arch value
        self.push(statement::load_architecture());
        // (A = runtime arch value) != (Immediate = filter arch value) => return the arch mismatch action
        // unwrap is ok, since the function returns None only if the length of the body is > 255, and the length is 1
        self.extend(
            bpf::statement::if_not_statement(
                IfCondition::eq(self.arch as u32),
                vec![statement::return_action(self.arch_mismatch_action)],
            )
            .unwrap(),
        );
    }

    // TODO: Duplicate syscalls are disallowed, so it's possible merge the groups in the compilation stage
    // but this may break the filters if non-commutative filtering methods are added
    // (e.g. filter.add_group(A, action); filter.check_syscall_is_between_1_and_100(); filter.add_group(B, action); won't be the same as
    // filter.add_group(A | B, action); filter.check_syscall_is_between_1_and_100();)
    pub fn add_syscall_group(&mut self, syscalls: &[u32], action: FilterAction) {
        if syscalls.is_empty() {
            return;
        }
        self.push(statement::load_syscall());

        for chunk in syscalls.chunks(u8::MAX as usize + 1) {
            let mut terms_any = vec![];
            for syscall in chunk {
                *self.syscall_count.entry(*syscall).or_default() += 1;
                terms_any.push(IfCondition::eq(*syscall));
            }
            // unwrap is ok here:
            // terms_any is not empty
            // the syscalls are split in chunks of 256, the max allowed condition size
            // the body contains a single instruction
            self.extend(
                if_or_statement(terms_any, vec![statement::return_action(action)]).unwrap(),
            );
        }
    }

    fn begin(&mut self) {
        self.verify_architecture();
    }

    fn finish(&mut self) {
        self.push(return_action(self.default_action));
    }

    fn verify(&self) -> Result<(), VerificationError> {
        if self.instructions.len() > self.max_instruction_count {
            return Err(VerificationError::TooManyInstructions {
                has: self.instructions.len(),
                max: self.max_instruction_count,
            });
        }

        for (syscall, count) in &self.syscall_count {
            if *count > 1 {
                return Err(VerificationError::DuplicateSyscall { syscall: *syscall });
            }
        }

        Ok(())
    }

    pub fn compile(mut self) -> Result<Vec<BpfInstruction>, VerificationError> {
        self.finish();

        self.verify()?;

        Ok(self.instructions.into_iter().map(|x| x.into()).collect())
    }
}

impl Default for Filter {
    fn default() -> Self {
        Self::new(Default::default())
    }
}
