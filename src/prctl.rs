//! A module that provides functions to get/set no_new_privs attribute that is required to set up the filters without CAP_SYS_ADMIN

use core::ffi::c_long;

use libc::{PR_GET_NO_NEW_PRIVS, PR_SET_NO_NEW_PRIVS, c_int, prctl};

/// PR_SET_NO_NEW_PRIVS - set the calling thread's no_new_privs attribute
/// int prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L);
pub fn set_no_new_privileges() -> Result<(), c_int> {
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
        -1 => Err(crate::error::errno()),
        _ => unreachable!(),
    }
}

/// PR_GET_NO_NEW_PRIVS - get the calling thread's no_new_privs attribute
/// int prctl(PR_GET_NO_NEW_PRIVS, 0L, 0L, 0L, 0L);
pub fn get_no_new_privileges() -> Result<bool, c_int> {
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
        -1 => Err(crate::error::errno()),
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
