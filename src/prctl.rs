//! A module that provides functions to get/set no_new_privs attribute that is required to set up the filters without CAP_SYS_ADMIN

use core::ffi::c_long;
use std::{error::Error, fmt::Display};

use libc::{PR_GET_NO_NEW_PRIVS, PR_SET_NO_NEW_PRIVS, c_int, prctl};

use crate::error::format_unknown_error;

#[derive(Debug)]
pub struct ProcessControlError {
    pub error_code: c_int,
}

impl Display for ProcessControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "prctl error ({})", format_unknown_error(self.error_code))
    }
}

impl Error for ProcessControlError {}

/// Set the no_new_privs attribute of the calling thread
pub fn set_no_new_privileges() -> Result<(), ProcessControlError> {
    match unsafe {
        prctl(
            PR_SET_NO_NEW_PRIVS,
            // why shouldn't i wrap the integers into c_longs
            c_long::from(1),
            c_long::from(0),
            c_long::from(0),
            c_long::from(0),
        )
    } {
        0 => Ok(()),
        -1 => Err(ProcessControlError {
            error_code: crate::error::errno(),
        }),
        _ => unreachable!(),
    }
}

/// Get the no_new_privs attribute of the calling thread
pub fn get_no_new_privileges() -> Result<bool, ProcessControlError> {
    match unsafe {
        prctl(
            PR_GET_NO_NEW_PRIVS,
            c_long::from(0),
            c_long::from(0),
            c_long::from(0),
            c_long::from(0),
        )
    } {
        1 => Ok(true),
        0 => Ok(false),
        -1 => Err(ProcessControlError {
            error_code: crate::error::errno(),
        }),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_has_new_privileges() {
        assert!(!get_no_new_privileges().unwrap());
    }

    #[test]
    fn test_set_has_new_privileges() {
        assert!(!get_no_new_privileges().unwrap());
        set_no_new_privileges().unwrap();
        assert!(get_no_new_privileges().unwrap());
    }
}
