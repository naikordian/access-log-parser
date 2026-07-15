# access-log-parser

`access-log-parser` converts Apache/Nginx Combined Log Format records to CSV.
It uses a byte-oriented state-machine lexer rather than regular expressions,
normalizes timestamps to UTC RFC 3339, and streams records without loading an
entire log into memory.

## Usage

```text
access-log-parser [OPTIONS] [INPUT]
```

Read a file and write CSV to stdout:

```sh
access-log-parser data/web-access.log > access.csv
```

Read stdin and write a file:

```sh
cat access.log | access-log-parser -o access.csv
```

Aggregate regular, case-sensitive `*.log` files immediately inside a directory
in filename order:

```sh
access-log-parser -d data -o access.csv
```

Parsing stops at the first malformed record by default. `--skip-invalid`
continues after reporting each rejected source path and line number to stderr;
the process still exits with status 1 if any record was rejected.

The CSV columns are:

```text
remote_host,ident,remote_user,timestamp,request,method,request_target,request_path,extension,query_string,protocol,status,bytes_sent,referer,user_agent
```

Combined Log Format `-` placeholders become empty CSV fields. Quoted values
support `\"`, `\\`, and `\xHH` escapes. Decoded fields must be valid UTF-8.
The original request target is retained while `request_path`, `extension`, and
the unexpanded raw `query_string` are emitted as analysis-friendly columns.
