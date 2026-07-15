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
enum AppError {
    BrokenPipe,
    Other(String),
}

impl AppError {
    fn other(message: impl Into<String>) -> Self {
        Self::Other(message.into())
    }

    fn from_csv_write(error: csv::Error, context: impl Into<String>) -> Self {
        if matches!(
            error.kind(),
            csv::ErrorKind::Io(error) if error.kind() == io::ErrorKind::BrokenPipe
        ) {
            Self::BrokenPipe
        } else {
            Self::other(format!("{}: {error}", context.into()))
        }
    }

    fn from_io_write(error: io::Error, context: impl Into<String>) -> Self {
        if error.kind() == io::ErrorKind::BrokenPipe {
            Self::BrokenPipe
        } else {
            Self::other(format!("{}: {error}", context.into()))
        }
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BrokenPipe => formatter.write_str("broken pipe"),
            Self::Other(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for AppError {}

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
        Err(AppError::BrokenPipe) => ExitCode::SUCCESS,
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
        return Err(AppError::other(
            "input and output paths refer to the same file".to_owned(),
        ));
    }

    let files = match &cli.directory {
        Some(directory) => discover_log_files(directory, cli.output.as_deref())?,
        None => cli.input.iter().cloned().collect(),
    };

    let destination: Box<dyn Write> = match &cli.output {
        Some(path) => Box::new(BufWriter::new(File::create(path).map_err(|error| {
            AppError::other(format!("cannot create {}: {error}", path.display()))
        })?)),
        None => Box::new(BufWriter::new(io::stdout().lock())),
    };
    let mut writer = WriterBuilder::new()
        .terminator(Terminator::Any(b'\n'))
        .from_writer(destination);
    writer
        .write_record(CSV_HEADER)
        .map_err(|error| AppError::from_csv_write(error, "cannot write CSV header"))?;

    let mut invalid = false;
    if cli.directory.is_some() || cli.input.is_some() {
        for path in files {
            let file = File::open(&path).map_err(|error| {
                AppError::other(format!("cannot open {}: {error}", path.display()))
            })?;
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
        .map_err(|error| AppError::from_io_write(error, "cannot flush CSV output"))?;
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
            .map_err(|error| AppError::other(format!("cannot read {source}: {error}")))?;
        if bytes_read == 0 {
            break;
        }
        line_number += 1;
        trim_line_ending(&mut line);

        match parse_line(&line) {
            Ok(record) => writer.write_record(record.csv_fields()).map_err(|error| {
                AppError::from_csv_write(
                    error,
                    format!("cannot write CSV record for {source}:{line_number}"),
                )
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
        AppError::other(format!(
            "cannot read directory {}: {error}",
            directory.display()
        ))
    })?;
    let mut files = Vec::new();

    for entry in entries {
        let entry = entry.map_err(|error| {
            AppError::other(format!(
                "cannot read an entry in {}: {error}",
                directory.display()
            ))
        })?;
        let file_type = entry.file_type().map_err(|error| {
            AppError::other(format!(
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
        .map_err(|error| AppError::other(format!("cannot resolve {}: {error}", left.display())))?;
    let right = right
        .canonicalize()
        .map_err(|error| AppError::other(format!("cannot resolve {}: {error}", right.display())))?;
    Ok(left == right)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;

    use tempfile::tempdir;

    use super::{AppError, paths_refer_to_same_file, trim_line_ending};

    #[test]
    fn classifies_only_broken_pipe_write_errors_as_normal_termination() {
        let broken_pipe = io::Error::from(io::ErrorKind::BrokenPipe);
        assert!(matches!(
            AppError::from_io_write(broken_pipe, "writing output"),
            AppError::BrokenPipe
        ));

        let disk_full = io::Error::from(io::ErrorKind::StorageFull);
        let error = AppError::from_io_write(disk_full, "writing output");
        assert!(matches!(error, AppError::Other(_)));
        assert!(error.to_string().starts_with("writing output:"));
    }

    #[test]
    fn recognizes_broken_pipe_wrapped_by_csv_writer() {
        let error = csv::Error::from(io::Error::from(io::ErrorKind::BrokenPipe));

        assert!(matches!(
            AppError::from_csv_write(error, "writing CSV"),
            AppError::BrokenPipe
        ));
    }

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

    #[test]
    fn missing_left_path_is_not_the_same_as_an_existing_file() {
        let directory = tempdir().unwrap();
        let missing = directory.path().join("missing.log");
        let existing = directory.path().join("existing.log");
        fs::write(&existing, "log").unwrap();

        assert!(!paths_refer_to_same_file(&missing, &existing).unwrap());
    }

    #[test]
    fn distinct_existing_files_are_not_the_same() {
        let directory = tempdir().unwrap();
        let left = directory.path().join("left.log");
        let right = directory.path().join("right.log");
        fs::write(&left, "left").unwrap();
        fs::write(&right, "right").unwrap();

        assert!(!paths_refer_to_same_file(&left, &right).unwrap());
    }

    #[test]
    fn canonical_aliases_refer_to_the_same_file() {
        let directory = tempdir().unwrap();
        let subdirectory = directory.path().join("subdirectory");
        fs::create_dir(&subdirectory).unwrap();
        let direct = directory.path().join("access.log");
        let alias = subdirectory.join("..").join("access.log");
        fs::write(&direct, "log").unwrap();

        assert!(paths_refer_to_same_file(&alias, &direct).unwrap());
    }
}
