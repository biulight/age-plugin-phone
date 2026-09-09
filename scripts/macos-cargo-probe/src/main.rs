use std::{
    ffi::{CString, c_char},
    process::ExitCode,
};

unsafe extern "C" {
    fn age_phone_m0_cryptokit_probe(argc: i32, argv: *const *const c_char) -> i32;
}

fn main() -> ExitCode {
    let Ok(args) = std::env::args()
        .map(CString::new)
        .collect::<Result<Vec<_>, _>>()
    else {
        return ExitCode::FAILURE;
    };
    if args.len() != 3 {
        eprintln!(
            "usage: age-phone-m0-cryptokit-probe create|verify|observe|hold <isolated-directory>"
        );
        return ExitCode::FAILURE;
    }
    let pointers: Vec<_> = args.iter().map(|arg| arg.as_ptr()).collect();
    // SAFETY: exactly three valid NUL-terminated UTF-8 strings and the pointer array
    // outlive this synchronous call. Swift borrows them and returns an integer status;
    // no keys or owned allocations cross the ABI. This fixture is single-threaded.
    match unsafe { age_phone_m0_cryptokit_probe(3, pointers.as_ptr()) } {
        0 => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}
