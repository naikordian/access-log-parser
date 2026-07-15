use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use tempfile::tempdir;

const FIRST: &str =
    r#"192.0.2.1 - - [07/Oct/2025:07:35:03 +0700] "GET /one HTTP/1.1" 200 12 "-" "Agent, One""#;
const SECOND: &str = r#"192.0.2.2 - bob [07/Oct/2025:08:00:00 +0700] "POST /two HTTP/1.1" 201 - "https://example.test/" "Agent Two""#;
const HEADER: &str = "remote_host,ident,remote_user,timestamp,request,method,request_target,request_path,extension,query_string,protocol,status,bytes_sent,referer,user_agent\n";

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_access-log-parser"))
}

#[test]
fn reads_stdin_and_writes_csv_stdout() {
    let mut child = binary()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{FIRST}").unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with(HEADER));
    assert!(stdout.contains("2025-10-07T00:35:03Z"));
    assert!(stdout.contains("\"Agent, One\""));
    assert!(stdout.contains(",/one,/one,,,HTTP/1.1,"));
}

#[test]
fn directory_mode_aggregates_log_files_in_filename_order() {
    let directory = tempdir().unwrap();
    fs::write(directory.path().join("b.log"), format!("{SECOND}\n")).unwrap();
    fs::write(directory.path().join("a.log"), format!("{FIRST}\n")).unwrap();
    fs::write(directory.path().join("ignored.txt"), "not a log\n").unwrap();
    fs::write(
        directory.path().join("a.log:Zone.Identifier"),
        "not a log\n",
    )
    .unwrap();

    let output = binary().arg("-d").arg(directory.path()).output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.matches('\n').count(), 3);
    assert!(stdout.find("192.0.2.1").unwrap() < stdout.find("192.0.2.2").unwrap());
}

#[test]
fn strict_mode_stops_at_first_invalid_line() {
    let directory = tempdir().unwrap();
    let input = directory.path().join("access.log");
    fs::write(&input, format!("{FIRST}\ninvalid\n{SECOND}\n")).unwrap();

    let output = binary().arg(&input).output().unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stdout.contains("192.0.2.1"));
    assert!(!stdout.contains("192.0.2.2"));
    assert!(stderr.contains("access.log:2: byte"));
}

#[test]
fn skip_invalid_continues_but_returns_nonzero() {
    let directory = tempdir().unwrap();
    let input = directory.path().join("access.log");
    fs::write(&input, format!("{FIRST}\ninvalid\n{SECOND}\n")).unwrap();

    let output = binary().arg("--skip-invalid").arg(&input).output().unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("192.0.2.1"));
    assert!(stdout.contains("192.0.2.2"));
}

#[test]
fn writes_to_output_file() {
    let directory = tempdir().unwrap();
    let input = directory.path().join("access.log");
    let output_path = directory.path().join("access.csv");
    fs::write(&input, format!("{FIRST}\n")).unwrap();

    let output = binary()
        .arg(&input)
        .arg("-o")
        .arg(&output_path)
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    let csv = fs::read_to_string(output_path).unwrap();
    assert!(csv.starts_with(HEADER));
    assert!(csv.contains("192.0.2.1"));
}

#[test]
fn rejects_using_input_as_output() {
    let directory = tempdir().unwrap();
    let input = directory.path().join("access.log");
    fs::write(&input, format!("{FIRST}\n")).unwrap();

    let output = binary().arg(&input).arg("-o").arg(&input).output().unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("same file")
    );
}

#[test]
fn exits_silently_when_stdout_reader_closes_early() {
    let directory = tempdir().unwrap();
    let input = directory.path().join("large.log");
    fs::write(&input, format!("{FIRST}\n").repeat(5_000)).unwrap();
    let mut child = binary()
        .arg(&input)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut first_line = String::new();

    stdout.read_line(&mut first_line).unwrap();
    assert_eq!(first_line, HEADER);
    drop(stdout);

    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
}
