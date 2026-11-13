//! Account database lookups for a numeric user ID.

use std::ffi::{CStr, OsString};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

/// Largest `getpwuid_r` scratch buffer tried before giving up on an entry.
const PASSWD_BUFFER_MAX: usize = 64 * 1024;

/// The account name for a UID, or `None` when it does not resolve.
pub(crate) fn user_name(uid: u32) -> Option<String> {
    passwd_entry(uid, |entry| {
        // SAFETY: `passwd_entry` passes an entry whose string fields are null
        // or valid NUL-terminated strings for the duration of this call.
        let name = unsafe { field(entry.pw_name) }?;
        Some(name.to_string_lossy().into_owned())
    })?
}

/// The home directory recorded for a UID, or `None` when it does not resolve.
pub(crate) fn home_dir(uid: u32) -> Option<PathBuf> {
    passwd_entry(uid, |entry| {
        // SAFETY: as in `user_name`.
        let home = unsafe { field(entry.pw_dir) }?;
        Some(PathBuf::from(OsString::from_vec(home.to_bytes().to_vec())))
    })?
}

/// Borrow one passwd string field, treating a null pointer as absent.
///
/// # Safety
///
/// A non-null `pointer` must point to a NUL-terminated string that stays valid
/// and unmodified for `'a`.
unsafe fn field<'a>(pointer: *const libc::c_char) -> Option<&'a CStr> {
    if pointer.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees a valid NUL-terminated string for `'a`.
    Some(unsafe { CStr::from_ptr(pointer) })
}

/// Look up one passwd entry and copy what the caller needs out of it.
///
/// The entry's strings live in a local buffer, so `read` must return owned
/// data. `None` means the UID has no entry or the lookup failed.
fn passwd_entry<T>(uid: u32, read: impl FnOnce(&libc::passwd) -> T) -> Option<T> {
    let mut buffer = vec![0_u8; 1024];
    loop {
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::zeroed();
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `entry` and `buffer` are writable for the sizes passed, and
        // `result` is a valid out-pointer. getpwuid_r stores string data only
        // inside `buffer` and retains none of the pointers.
        let code = unsafe {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &raw mut result,
            )
        };
        if code == libc::ERANGE && buffer.len() < PASSWD_BUFFER_MAX {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if code != 0 || result.is_null() {
            return None;
        }
        // SAFETY: on success with a non-null result, `result` points at
        // `entry`, which getpwuid_r initialized, and its string fields point
        // into `buffer`. Both outlive this call to `read`.
        return Some(read(unsafe { &*result }));
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{home_dir, user_name};

    #[test]
    fn root_resolves_to_a_name_and_an_absolute_home() {
        assert_eq!(user_name(0).as_deref(), Some("root"));
        assert!(home_dir(0).is_some_and(|home| Path::new(&home).is_absolute()));
    }
}
