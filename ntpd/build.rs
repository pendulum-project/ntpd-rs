use std::process::{Command, ExitStatus};

fn main() {
    // check if the repository is dirty (if there is any)
    let is_dirty = if let Ok(status) = Command::new("git")
        .args(["diff-index", "--quiet", "HEAD", "--"])
        .status()
    {
        !status.success()
    } else {
        false
    };

    // determine the git commit (if there is any)
    let git_rev = run_command_out("git", &["rev-parse", "HEAD"])
        .ok()
        .map(|rev| {
            if is_dirty {
                format!("{}-dirty", rev)
            } else {
                rev
            }
        });

    // determine the date of the git commit (if there is any)
    let git_date = if let Some(hash) = &git_rev {
        if is_dirty {
            run_command_out("date", &["-u", "+%Y-%m-%d"]).ok()
        } else {
            run_command_out(
                "git",
                &[
                    "show",
                    "-s",
                    "--date=format:%Y-%m-%d",
                    "--format=%cd",
                    hash,
                    "--",
                ],
            )
            .ok()
        }
    } else {
        None
    };

    println!(
        "cargo:rustc-env=NTP_GIT_REV={}",
        git_rev.unwrap_or("-".to_owned())
    );
    println!(
        "cargo:rustc-env=NTP_GIT_DATE={}",
        git_date.unwrap_or("-".to_owned())
    );
    println!("cargo:rustc-rerun-if-changed=.git/HEAD");
}

fn run_command(cmd: &str, args: &[&str]) -> std::io::Result<(String, ExitStatus)> {
    let res = Command::new(cmd).args(args).output()?;
    match String::from_utf8(res.stdout) {
        Ok(data) => Ok((data.trim().to_owned(), res.status)),
        Err(e) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
    }
}

fn run_command_out(cmd: &str, args: &[&str]) -> std::io::Result<String> {
    run_command(cmd, args).map(|(out, _)| out)
}
