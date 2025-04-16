//! `cargo atomvchecker $FLAGS $ARGS` calls `cargo build` with RUSTC_WRAPPER set to `atomvchecker`.
//! The flags are passed to `atomvchecker` through env var `ATOMVCHECKER_FLAGS`.
//! The remainining args are unchanged.
//! To re-run `cargo atomvchecker` with different flags on the same crate, please `cargo clean` first.
use std::env;
use std::ffi::OsString;
use std::process::Command;

const CARGO_ATOMVCHECKER_HELP: &str = r#"Statically detect bugs on MIR
Usage:
    cargo atomvchecker [options] [<cargo options>...] [--] [<program/test suite options>...]
Common options:
    -h, --help               Print this message
    -V, --version            Print version info and exit
    -k, --detector-kind      Choose detector, deadlock
    -b, --blacklist-mode     Use crate-name-list as blacklist, whitelist if not specified
    -l, --crate-name-list    Will not white-or-black list the crates if not specified.
    
Other [options] are the same as `cargo build`. Everything after the second "--" verbatim
to the program.
Examples:
    # only detect [mycrate1, mycrate2]
    cargo atomvchecker -k deadlock -l mycrate1,mycrate2
    # skip detecting [mycrate1, mycrate2]
    cargo atomvchecker -k deadlock -b -l mycrate1,mycrate2
"#;

fn show_help() {
    println!("{}", CARGO_ATOMVCHECKER_HELP);
}

fn show_version() {
    println!("atomvchecker 0.2.0");
}

fn cargo() -> Command {
    Command::new(env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo")))
}

// Determines whether a `--flag` is present.
fn has_arg_flag(name: &str) -> bool {
    let mut args = std::env::args().take_while(|val| val != "--");
    args.any(|val| val == name)
}

fn in_cargo_atomvchecker() {
    // Now we run `cargo build $FLAGS $ARGS`, giving the user the
    // change to add additional arguments. `FLAGS` is set to identify
    // this target. The user gets to control what gets actually passed to atomvchecker.
    let mut cmd = cargo();
    cmd.arg("build");
    cmd.env("RUSTC_WRAPPER", "atomvchecker");
    cmd.env("RUST_BACKTRACE", "full");
    cmd.env("ATOMVCHECKER_LOG", "info");
    let args = std::env::args().skip(2);
    let mut flags = Vec::new();
    for arg in args {
        if arg == "--" {
            break;
        }
        flags.push(arg);
    }
    let flags = flags.join(" ");
    cmd.env("ATOMVCHECKER_FLAGS", flags);
    let exit_status = cmd
        .spawn()
        .expect("could not run cargo")
        .wait()
        .expect("failed to wait for cargo?");
    if !exit_status.success() {
        std::process::exit(exit_status.code().unwrap_or(-1))
    };
}

fn main() {
    if has_arg_flag("--help") || has_arg_flag("-h") {
        show_help();
        return;
    }
    if has_arg_flag("--version") || has_arg_flag("-V") {
        show_version();
        return;
    }
    if let Some("atomvchecker") = std::env::args().nth(1).as_deref() {
        in_cargo_atomvchecker();
    }
}
