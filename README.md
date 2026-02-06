# DuckDB Zeek Log Query Tool

A high-performance command-line tool for querying Zeek network security log files using DuckDB - a "poor man's SIEM" that lets you run SQL queries against your network logs. This tool automatically discovers schemas across multiple TSV log files and creates a unified view, allowing you to efficiently analyze and search through your Zeek logs.

**Note:** For a native DuckDB extension that provides a `read_zeek()` function, see [Yacin's zeek-duckdb extension](https://github.com/ynadji/zeek-duckdb). This script is a Python-based alternative that works without a standalone DuckDB installation and without requiring extension compilation.

## Features

- **Automatic Schema Discovery**: Scans file headers to detect log type (`#path`), field names (`#fields`), and types (`#types`)
- **Multi-Schema Support**: Handles files with different schemas by creating separate views for each log type
- **Multiple Log Types**: Automatically creates views for each Zeek log type found (e.g., `conn`, `http`, `dns`)
- **Struct Fields**: Dotted field names (e.g., `id.orig_h`) are grouped into DuckDB STRUCTs so you can use natural dot notation in SQL without quoting
- **Native IP/Network Queries**: IP addresses are stored as `INET` type, enabling native CIDR/subnet matching with `<<=` operator
- **JOIN Support**: Load multiple log types and JOIN them on common fields like `uid`
- **Container Type Parsing**: `vector[T]` and `set[T]` fields are parsed into DuckDB LIST types with proper element typing
- **Type Row Output**: Output includes a second header row showing the original Zeek types for each column
- **Gzip Compression**: Automatically handles gzipped Zeek log files
- **Absolute Path Support**: Regex patterns can include absolute paths (e.g., `/data/logs/conn.*\.gz$`)
- **Streaming Results**: Outputs results in real-time as they're processed
- **Memory Management**: Configurable memory limit via `DUCKDB_MEMORY_LIMIT` environment variable; DuckDB spills to disk when exceeded
- **Tab-Separated Output**: Produces TSV output suitable for piping to other tools

## Requirements

- Python 3.6+ (uses standard library `ipaddress` module)
- `duckdb` Python package

## Installation

Install the required dependency:

```bash
pip install duckdb
```

## Usage

```bash
python3 zeek-log-query.py <file_regex> [<file_regex> ...] <sql_query>
```

### Arguments

- `file_regex`: One or more regular expression patterns matching the Zeek log files to query (searches recursively from current directory, or from the directory prefix if pattern starts with `/`)
- `sql_query`: A SQL query to execute against the log type views (e.g., query `conn`, `http`, `dns`, etc.) - must be the last argument

### Examples

**Count total events:**
```bash
python3 zeek-log-query.py 'conn.*\.log\.gz$' 'SELECT COUNT(*) FROM conn'
```

**Find top source IPs:**
```bash
python3 zeek-log-query.py 'conn.*\.gz$' "SELECT id.orig_h, COUNT(*) as cnt FROM conn GROUP BY id.orig_h ORDER BY cnt DESC LIMIT 10"
```

**Filter by IP address:**
```bash
python3 zeek-log-query.py 'dns.*\.gz$' "SELECT * FROM dns WHERE id.orig_h = '192.168.1.100' OR id.resp_h = '192.168.1.100'"
```

**Filter by network/CIDR:**
```bash
# Find all connections from 192.168.1.0/24 network using native INET matching
python3 zeek-log-query.py 'dns.*\.gz$' "SELECT * FROM dns WHERE id.orig_h <<= INET '192.168.1.0/24' OR id.resp_h <<= INET '192.168.1.0/24'"

# Find all connections to private networks
python3 zeek-log-query.py 'conn.*\.gz$' "SELECT * FROM conn WHERE id.resp_h <<= INET '192.168.0.0/16' OR id.resp_h <<= INET '10.0.0.0/8'"
```

**Filter by timestamp:**
```bash
python3 zeek-log-query.py '.*\.log\.gz$' 'SELECT * FROM conn WHERE ts > 1234567890.0'
```

**Multiple file patterns:**
```bash
python3 zeek-log-query.py 'conn.*\.gz$' 'http.*\.gz$' 'SELECT * FROM conn'
```

**Joining log types:**
Pass file patterns for each log type you want to join, then use SQL `JOIN` on a common field (e.g. `uid`). The script creates one view per log type; duplicate column names in the output are made unique (e.g. `uid`, `uid_2`).
```bash
# Join dns and conn on uid
python3 zeek-log-query.py 'conn.*\.gz$' 'dns.*\.gz$' "SELECT * FROM dns JOIN conn ON dns.uid = conn.uid LIMIT 100"

# Count joined rows
python3 zeek-log-query.py 'conn.*\.gz$' 'dns.*\.gz$' "SELECT COUNT(*) FROM dns JOIN conn ON dns.uid = conn.uid"
```

**Query multiple log types:**
```bash
python3 zeek-log-query.py '.*\.log\.gz$' 'SELECT * FROM conn UNION ALL SELECT * FROM http'
```

**Save results to a file:**
```bash
python3 zeek-log-query.py 'conn.*\.gz$' 'SELECT * FROM conn WHERE duration > 10' > results.tsv
```

**Query array/vector fields:**
```bash
# Find records where a vector field contains a specific value
# Example: Find connections where app vector contains 'mozilla'
# Note: This assumes the conn log has an "app" field of type vector[string]
python3 zeek-log-query.py 'conn.*\.gz$' "SELECT count(*) FROM conn WHERE orig_bytes > 0 AND resp_bytes > 0 AND 'mozilla' = ANY(app)"

# Count elements in a vector/set field
python3 zeek-log-query.py '.*\.log\.gz$' "SELECT id.orig_h, list_length(app) as app_count FROM conn WHERE list_length(app) > 0"
```

## How It Works

1. **File Discovery**: Uses regex matching to find all matching log files. Supports absolute paths (e.g., `/data/logs/conn.*\.gz$`) and relative patterns (searches recursively from current directory)
2. **Metadata Extraction**: Reads the first 15 lines of each gzipped file to extract `#path`, `#fields`, and `#types` metadata
3. **Log Type Grouping**: Groups files by Zeek log type (from `#path`) and then by schema (field names and order)
4. **Type Mapping**: Maps Zeek types to DuckDB types (e.g., `addr` → `INET`, `port` → `BIGINT`, `vector[T]` → `LIST[T]`)
5. **View Creation**: Creates a raw DuckDB view per log type with `UNION ALL BY NAME`, then wraps it in a struct view that groups dotted field names (e.g., `id.orig_h`) into DuckDB STRUCTs for natural dot-notation access
6. **Query Execution**: Executes your SQL query and streams results in chunks of 1000 rows, with a type header row showing original Zeek types

## Output Format

- **Standard Output (stdout)**: Tab-separated query results
- **Standard Error (stderr)**: Status messages, timing information, and error messages

The output has three sections:
1. **Row 1**: Column names (duplicate names from JOINs get `_2`, `_3`, etc.)
2. **Row 2**: Original Zeek type names (e.g., `time`, `addr`, `port`, `count`, `string`)
3. **Row 3+**: Data rows

The output format matches Zeek log conventions:
- Null values (both `-` and `(empty)` in input) are displayed as `-`
- Boolean `True` is displayed as `T`
- Boolean `False` is displayed as `F`
- IP addresses (INET type) are automatically converted to readable strings (e.g., `192.168.1.100`)
- STRUCT fields (e.g., `id`) display as `{orig_h: 192.168.1.100, resp_h: 10.0.0.1, orig_p: 60230, resp_p: 53}`
- LIST fields display as `[value1,value2,value3]`

Example output:
```
ts	uid	id	proto	service
time	string	record[addr,addr,port,port]	string	string
1768435188.9	Cx7SWV	{orig_h: 192.168.1.100, resp_h: 10.0.0.1, orig_p: 60230, resp_p: 53}	udp	dns
```

This design allows you to pipe results to other tools while keeping status information separate:

```bash
python3 zeek-log-query.py '.*\.log\.gz$' 'SELECT * FROM conn' | grep "192.168.1.1"
```

## Type Mapping

The tool automatically maps Zeek types to DuckDB types:

### Time Types
- `time` → `DOUBLE` (Unix timestamp with fractional seconds)
- `interval` → `DOUBLE` (Duration in seconds)

### Numeric Types
- `count` → `BIGINT` (Unsigned 64-bit integer)
- `int` → `BIGINT` (Signed integer)
- `double` → `DOUBLE` (Floating point number)

### Network Types
- `addr` → `INET` (IP address - enables network/CIDR queries)
- `subnet` → `INET` (Network/subnet in CIDR notation - enables network queries)
- `port` → `BIGINT` (Port number; protocol information is not preserved)

### Boolean
- `bool` → `BOOLEAN` (Boolean value)

### String and Container Types
- `string` → `VARCHAR` (Text data)
- `pattern` → `VARCHAR` (Regular expression, stored as text)
- `enum` → `VARCHAR` (Enumeration, stored as text)
- `vector[type]` → `LIST[type]` (Parsed from `[value1,value2]` format into DuckDB LIST)
- `set[type]` → `LIST[type]` (Parsed from `{value1,value2}` format into DuckDB LIST)
- `table`, `record` → `VARCHAR` (Complex types serialized as text in TSV logs)

### Not Applicable to Logs
- Executable types (`function`, `event`, `hook`) - Not present in log files
- `file` - Only used for writing, not in logs
- `opaque` - Internal type, not in logs
- `any` - Generic type, resolves to specific type in logs

Note: `vector` and `set` types are automatically parsed from Zeek's serialized format (`[value1,value2]` or `{value1,value2}`) into DuckDB LIST types, allowing you to query array elements using SQL array functions. Complex container types like `table` and `record` remain as `VARCHAR` since they have more complex serialization.

### IP Address and Network Queries

IP addresses (Zeek type `addr`) and subnets (Zeek type `subnet`) are stored as `INET` type in DuckDB, which enables native network/subnet queries:

- **Exact match**: Standard equality works with IP addresses
  ```sql
  WHERE id.orig_h = '192.168.1.1'
  ```

- **Network containment**: Use `<<=` operator to check if an IP is contained in a network
  ```sql
  WHERE id.orig_h <<= INET '192.168.1.0/24'
  ```
  This checks if the IP address is within the specified CIDR block.

- **Network contains**: Use `>>=` operator to check if a network contains an IP
  ```sql
  WHERE INET '192.168.1.0/24' >>= id.resp_h
  ```

The `<<=` operator means "is contained by or equal to" - it returns true if the left-side IP is within the right-side network/subnet.

## Performance

The tool reports timing information for:
- File discovery (regex matching)
- Schema scanning
- View initialization
- Query execution
- Total runtime

Example output (stderr):
```
[*] Analyzed 150 files. Identified 3 log types in 0.4567s
[*] View 'conn' created (2 schemas detected)
[*] View 'http' created (1 schemas detected)
[*] View 'dns' created (1 schemas detected)
[*] All views initialized in 0.2345s

--- Streaming Results ---

--- Summary ---
Total Rows:  1,234,567	Query Time: 2.3456s
```

## Memory and large datasets

DuckDB runs **in memory** by default. Data is streamed from the Zeek log files, but query execution (JOINs, GROUP BY, sorts, etc.) uses RAM for intermediate results. Very large log sets or heavy JOINs can cause **out-of-memory (OOM)** errors.

**If you run out of memory:**

1. **Set a memory limit** so DuckDB spills intermediate results to disk instead of using unbounded RAM:
   ```bash
   DUCKDB_MEMORY_LIMIT=4GB python3 zeek-log-query.py 'conn.*\.gz$' "SELECT COUNT(*) FROM conn"
   ```
   Use a value that fits your machine (e.g. `2GB`, `8GB`). When the limit is reached, DuckDB writes temporary data to disk and continues, which is slower but avoids OOM.

2. **Reduce scope**: Use stricter file regex patterns or date-based directories so fewer files are loaded.

3. **Simplify the query**: Avoid broad JOINs over huge tables; filter first (e.g. `WHERE ts > ...`) or aggregate before joining.

If `DUCKDB_MEMORY_LIMIT` is set, the script prints a message at startup confirming the limit. DuckDB’s default (when not set) is about 75% of system RAM.

## SQL Query Tips

### Column Names with Dots (Struct Fields)

Zeek field names with dots (e.g., `id.orig_h`, `id.resp_h`) are automatically grouped into DuckDB STRUCTs. This means you can use natural dot notation in SQL without quoting:

```sql
-- Works naturally: id is a STRUCT with fields orig_h, resp_h, orig_p, resp_p
SELECT id.orig_h, id.resp_h FROM conn

-- SELECT * returns struct columns as a single grouped column
SELECT * FROM conn
-- id column shows as: {orig_h: 192.168.1.100, resp_h: 10.0.0.1, orig_p: 60230, resp_p: 53}

-- To get flat output, select individual struct fields
SELECT ts, uid, id.orig_h, id.resp_h, id.orig_p, id.resp_p, proto FROM conn
```

### String Values

String values must be quoted with single quotes. IP addresses can be used directly or with INET casting:

```sql
-- IP address exact match (works with INET type)
SELECT * FROM dns WHERE id.orig_h = '192.168.1.100'

-- Network/CIDR queries (requires INET casting and <<= operator)
SELECT * FROM conn WHERE id.orig_h <<= INET '10.0.0.0/8'

-- Incorrect: Will cause syntax errors
SELECT * FROM dns WHERE id.orig_h = 192.168.1.100
```

### Escaping Quotes in Shell

When writing SQL queries from the command line, use double quotes for the SQL string:

```bash
# With struct fields, no need to escape column names
python3 zeek-log-query.py 'dns.*\.gz$' "SELECT * FROM dns WHERE id.orig_h = '192.168.1.100'"

# Alternative: Use single quotes for SQL, but you need complex escaping for internal single quotes
# '\'' escapes a single quote within single quotes
python3 zeek-log-query.py 'dns.*\.gz$' 'SELECT * FROM dns WHERE id.orig_h = '\''192.168.1.100'\'''
```

## Notes

- **Regex vs Glob**: The tool uses regular expressions (not glob patterns). Common differences:
  - Use `.*` instead of `*` for "any characters"
  - Use `\.` instead of `.` to match a literal dot
  - Use `$` to match end of string (e.g., `.*\.gz$` matches files ending in `.gz`)
  - Regex patterns match against the full normalized file path
- **Absolute paths**: If a regex pattern starts with `/`, the tool extracts the longest existing directory prefix from the pattern and searches recursively from there, instead of the current directory
- The tool skips the first 8 lines of each file (Zeek header lines)
- Views are named after the Zeek log type from the `#path` metadata (e.g., `conn`, `http`, `dns`)
- Multiple views are created when your regex patterns match different log types
- Missing fields in files with different schemas are filled with `NULL` (displayed as `-` in output)
- Both `-` (unset) and `(empty)` (empty value) in Zeek input are treated as `NULL` and displayed as `-` in output
- Boolean values in output are displayed as `T` (True) and `F` (False)
- Dotted field names (e.g., `id.orig_h`) are grouped into DuckDB STRUCTs, allowing natural dot notation in SQL queries
- A `schema_source` column is included in each view showing which file a row came from
- Files that cannot be read are skipped with a warning message

## License

MIT License - see LICENSE file for details.
