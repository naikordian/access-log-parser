use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use access_log_parser::{CSV_HEADER, parse_line};
use clap::Parser;
use csv::{Terminator, Writer, WriterBuilder};

#[derive(Debug, Parser)]
#[command(version, about = "Convert Combined Log Format access logs to CSV")]
struct Cli {
    /// Input log file; reads stdin when omitted
    #[arg(value_name = "INPUT", conflicts_with = "directory")]
    input: Option<PathBuf>,

    /// Parse regular *.log files directly inside this directory
    #[arg(short = 'd', long, value_name = "DIR", conflicts_with = "input")]
    directory: Option<PathBuf>,

    /// Write CSV to this file instead of stdout
    #[arg(short, long, value_name = "OUTPUT")]
    output: Option<PathBuf>,

    /// Continue after malformed lines (the final exit status is still nonzero)
    #[arg(long)]
    skip_invalid: bool,
}

#[derive(Debug)]
struct AppError(String);

impl std::fmt::Display for AppError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for AppError {}

impl From<csv::Error> for AppError {
    fn from(error: csv::Error) -> Self {
        Self(error.to_string())
    }
}

impl From<io::Error> for AppError {
    fn from(error: io::Error) -> Self {
        Self(error.to_string())
    }
}

#[derive(Default)]
struct ProcessStatus {
    invalid: bool,
    stop: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(false) => ExitCode::SUCCESS,
        Ok(true) => ExitCode::from(1),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<bool, AppError> {
    if let (Some(input), Some(output)) = (&cli.input, &cli.output)
        && paths_refer_to_same_file(input, output)?
    {
        return Err(AppError(
            "input and output paths refer to the same file".to_owned(),
        ));
    }

    let files = match &cli.directory {
        Some(directory) => discover_log_files(directory, cli.output.as_deref())?,
        None => cli.input.iter().cloned().collect(),
    };

    let destination: Box<dyn Write> = match &cli.output {
        Some(path) => Box::new(BufWriter::new(File::create(path).map_err(|error| {
            AppError(format!("cannot create {}: {error}", path.display()))
        })?)),
        None => Box::new(BufWriter::new(io::stdout().lock())),
    };
    let mut writer = WriterBuilder::new()
        .terminator(Terminator::Any(b'\n'))
        .from_writer(destination);
    writer
        .write_record(CSV_HEADER)
        .map_err(|error| AppError(format!("cannot write CSV header: {error}")))?;

    let mut invalid = false;
    if cli.directory.is_some() || cli.input.is_some() {
        for path in files {
            let file = File::open(&path)
                .map_err(|error| AppError(format!("cannot open {}: {error}", path.display())))?;
            let status = process_reader(
                BufReader::new(file),
                &path.display().to_string(),
                cli.skip_invalid,
                &mut writer,
            )?;
            invalid |= status.invalid;
            if status.stop {
                break;
            }
        }
    } else {
        let stdin = io::stdin();
        let status = process_reader(stdin.lock(), "<stdin>", cli.skip_invalid, &mut writer)?;
        invalid = status.invalid;
    }

    writer
        .flush()
        .map_err(|error| AppError(format!("cannot flush CSV output: {error}")))?;
    Ok(invalid)
}

fn process_reader<R: BufRead>(
    mut reader: R,
    source: &str,
    skip_invalid: bool,
    writer: &mut Writer<Box<dyn Write>>,
) -> Result<ProcessStatus, AppError> {
    let mut line = Vec::new();
    let mut line_number = 0_u64;
    let mut status = ProcessStatus::default();

    loop {
        line.clear();
        let bytes_read = reader
            .read_until(b'\n', &mut line)
            .map_err(|error| AppError(format!("cannot read {source}: {error}")))?;
        if bytes_read == 0 {
            break;
        }
        line_number += 1;
        trim_line_ending(&mut line);

        match parse_line(&line) {
            Ok(record) => writer.write_record(record.csv_fields()).map_err(|error| {
                AppError(format!(
                    "cannot write CSV record for {source}:{line_number}: {error}"
                ))
            })?,
            Err(error) => {
                eprintln!("{source}:{line_number}: {error}");
                status.invalid = true;
                if !skip_invalid {
                    status.stop = true;
                    break;
                }
            }
        }
    }

    Ok(status)
}

fn trim_line_ending(line: &mut Vec<u8>) {
    if line.last() == Some(&b'\n') {
        line.pop();
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
}

fn discover_log_files(directory: &Path, output: Option<&Path>) -> Result<Vec<PathBuf>, AppError> {
    let entries = fs::read_dir(directory).map_err(|error| {
        AppError(format!(
            "cannot read directory {}: {error}",
            directory.display()
        ))
    })?;
    let mut files = Vec::new();

    for entry in entries {
        let entry = entry.map_err(|error| {
            AppError(format!(
                "cannot read an entry in {}: {error}",
                directory.display()
            ))
        })?;
        let file_type = entry.file_type().map_err(|error| {
            AppError(format!(
                "cannot inspect {}: {error}",
                entry.path().display()
            ))
        })?;
        let path = entry.path();
        let is_log = path.extension().is_some_and(|extension| extension == "log");
        if !file_type.is_file() || !is_log {
            continue;
        }
        if let Some(output) = output
            && paths_refer_to_same_file(&path, output)?
        {
            continue;
        }
        files.push(path);
    }

    files.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    Ok(files)
}

fn paths_refer_to_same_file(left: &Path, right: &Path) -> Result<bool, AppError> {
    if left == right {
        return Ok(true);
    }
    if !left.exists() || !right.exists() {
        return Ok(false);
    }

    let left = left
        .canonicalize()
        .map_err(|error| AppError(format!("cannot resolve {}: {error}", left.display())))?;
    let right = right
        .canonicalize()
        .map_err(|error| AppError(format!("cannot resolve {}: {error}", right.display())))?;
    Ok(left == right)
}

#[cfg(test)]
mod tests {
    use super::trim_line_ending;

    #[test]
    fn trims_unix_and_windows_line_endings() {
        for (mut input, expected) in [
            (b"line\n".to_vec(), b"line".as_slice()),
            (b"line\r\n".to_vec(), b"line".as_slice()),
            (b"line".to_vec(), b"line".as_slice()),
        ] {
            trim_line_ending(&mut input);
            assert_eq!(input, expected);
        }
    }
}
