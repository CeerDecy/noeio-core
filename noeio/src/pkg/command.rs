use tokio::process::Command;

pub async fn run_command(cmd: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cmd_out: std::process::Output;
    let stdout: String;
    let stderr: String;
    {
        #[cfg(unix)]
        let mut builder = {
            let mut c = Command::new("sh");
            c.arg("-c").arg(cmd);
            c
        };
        #[cfg(windows)]
        let mut builder = {
            let mut c = Command::new("cmd");
            c.arg("/C").arg(cmd);
            c
        };

        cmd_out = builder.output().await?;
        stdout = String::from_utf8_lossy(cmd_out.stdout.as_slice()).to_string();
        stderr = String::from_utf8_lossy(cmd_out.stderr.as_slice()).to_string();
    };

    let ec = cmd_out.status.code();
    let succ = cmd_out.status.success();
    tracing::debug!(?cmd, ?ec, ?succ, ?stdout, ?stderr, "run shell cmd");

    if !cmd_out.status.success() {
        return Err(format!("{} {}", stdout, &stderr).into());
    }
    Ok(())
}
