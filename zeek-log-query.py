import duckdb
import gzip
import re
import os
import sys
import time
import ipaddress

# 1. Start Global Timer
start_total = time.perf_counter()

if len(sys.argv) < 3:
    script_name = sys.argv[0]
    print(f"Usage: python3 {script_name} <file_regex> [<file_regex> ...] <sql_query>")
    print(f"Example: python3 {script_name} '.*\\.log\\.gz$' 'SELECT * FROM conn LIMIT 10'")
    print(f"Example: python3 {script_name} 'conn.*\\.gz$' 'http.*\\.gz$' 'SELECT * FROM conn'")
    print(f"Example (join): python3 {script_name} 'conn.*\\.gz$' 'dns.*\\.gz$' \"SELECT * FROM dns JOIN conn ON dns.uid = conn.uid LIMIT 100\"")
    sys.exit(1)

# Last argument is the SQL query, all others are file regex patterns
file_regexes = [re.compile(arg) for arg in sys.argv[1:-1]]
user_query = sys.argv[-1]

# 2. Schema and Path Discovery
def get_log_metadata(file_path):
    """Extracts Zeek #path, #fields, and #types."""
    try:
        with gzip.open(file_path, 'rt') as f:
            log_path, fields, types = None, [], []
            for _ in range(15): # Scan first 15 lines
                line = f.readline()
                if not line: break
                if line.startswith('#path'):
                    log_path = line.strip().split('\t')[1]
                elif line.startswith('#fields'):
                    fields = line.strip().split('\t')[1:]
                elif line.startswith('#types'):
                    types = line.strip().split('\t')[1:]
                    if log_path and fields and types:
                        return log_path, fields, types
    except Exception as e:
        print(f"[!] Warning: Could not read {file_path}: {e}", file=sys.stderr)
    return None, None, None

t0 = time.perf_counter()
# Find all files matching any of the regex patterns (recursively)
all_files = set()

# Determine search root: if pattern starts with /, search from root, otherwise from current dir
search_roots = set()
for pattern_str in sys.argv[1:-1]:
    if pattern_str.startswith('/'):
        # Absolute path pattern - extract the root directory to search from
        # Find the longest existing directory prefix
        parts = pattern_str.split('/')
        for i in range(len(parts), 0, -1):
            test_path = '/'.join(parts[:i]) if i > 1 else '/'
            if os.path.isdir(test_path):
                search_roots.add(test_path)
                break
        else:
            search_roots.add('/')  # Fallback to root
    else:
        search_roots.add('.')  # Relative pattern, search from current dir

# If no absolute paths found, default to current directory
if not search_roots:
    search_roots.add('.')

# Search from all identified roots
for search_root in search_roots:
    for root, dirs, files in os.walk(search_root):
        for file in files:
            file_path = os.path.join(root, file)
            # Normalize path for consistent matching
            normalized_path = os.path.normpath(file_path)
            # Check if file matches any of the regex patterns
            if any(pattern.search(normalized_path) for pattern in file_regexes):
                all_files.add(normalized_path)

all_files = sorted(all_files)
# Dict structure: { "conn": { "field_string": { "fields": [], "types": [], "files": [] } } }
log_collections = {}

for fname in all_files:
    l_path, f_list, t_list = get_log_metadata(fname)
    if not all([l_path, f_list, t_list]): continue
    
    if l_path not in log_collections:
        log_collections[l_path] = {}
    
    schema_key = "|".join(f_list)
    if schema_key not in log_collections[l_path]:
        log_collections[l_path][schema_key] = {'fields': f_list, 'types': t_list, 'files': []}
    
    log_collections[l_path][schema_key]['files'].append(fname)

# Build global field_name -> zeek_type mapping (preserves original Zeek types)
zeek_type_lookup = {}  # "field_name" -> "zeek_type" (e.g., "id.orig_h" -> "addr", "id.orig_p" -> "port")
for log_type_schemas in log_collections.values():
    for info in log_type_schemas.values():
        for f, t in zip(info['fields'], info['types']):
            zeek_type_lookup[f] = t

t_metadata = time.perf_counter() - t0
print(f"[*] Analyzed {len(all_files):,} files. Identified {len(log_collections)} log types in {t_metadata:.4f}s", file=sys.stderr)

# 3. Build Views for each Log Type
t0 = time.perf_counter()
con = duckdb.connect()
# Optional: set memory limit so DuckDB spills to disk instead of OOM (e.g. DUCKDB_MEMORY_LIMIT=4GB)
memory_limit = os.environ.get('DUCKDB_MEMORY_LIMIT')
if memory_limit:
    try:
        con.execute(f"SET memory_limit = '{memory_limit}'")
        print(f"[*] Memory limit set to {memory_limit} (intermediate results will spill to disk when exceeded)", file=sys.stderr)
    except Exception as e:
        print(f"[!] Warning: Could not set memory_limit: {e}", file=sys.stderr)
# Load INET extension for network queries
try:
    con.execute("INSTALL inet;")
except:
    pass  # Extension might already be installed
try:
    con.execute("LOAD inet;")
except:
    pass  # Extension might already be loaded
type_map = {
    # Time types
    'time': 'DOUBLE',      # Unix timestamp with fractional seconds
    'interval': 'DOUBLE',  # Duration in seconds
    
    # Numeric types
    'count': 'BIGINT',     # Unsigned 64-bit integer
    'int': 'BIGINT',       # Signed integer
    'double': 'DOUBLE',    # Floating point
    
    # Network types
    'addr': 'INET',        # IP address (IPv4/IPv6)
    'subnet': 'INET',      # Network/subnet (CIDR notation)
    'port': 'BIGINT',      # Port number (protocol info lost, but number preserved)
    
    # Boolean
    'bool': 'BOOLEAN',     # Boolean
    
    # String and other types default to VARCHAR
    # 'string', 'pattern', 'enum', 'table', 'set', 'vector', 'record' → VARCHAR
}

for log_type, schemas in log_collections.items():
    select_statements = []
    for info in schemas.values():
        # Build column definitions - use proper types from type_map
        # Note: read_csv doesn't support INET directly, so we read addr fields as VARCHAR and cast
        col_defs = []
        select_cols = []
        for f, t in zip(info['fields'], info['types']):
            db_type = type_map.get(t, 'VARCHAR')
            
            # Check if this is a container type (vector or set)
            is_vector = t.startswith('vector[')
            is_set = t.startswith('set[')
            
            if db_type == 'INET':
                # Read as VARCHAR since read_csv doesn't support INET, then cast to INET
                col_defs.append(f"'{f}': 'VARCHAR'")
                select_cols.append(f"TRY_CAST(CASE WHEN \"{f}\" = '-' OR \"{f}\" = '(empty)' OR \"{f}\" IS NULL OR \"{f}\" = '' THEN NULL ELSE \"{f}\" END AS INET) AS \"{f}\"")
            elif is_vector or is_set:
                # Parse container types (vector/set) into DuckDB LIST type
                # Zeek format: vector[string] -> [value1,value2] or set[addr] -> {value1,value2}
                # Extract element type
                if is_vector:
                    elem_type = t[7:-1]  # Remove 'vector[' and ']'
                    bracket_start, bracket_end = '[', ']'
                else:  # is_set
                    elem_type = t[4:-1]  # Remove 'set[' and ']'
                    bracket_start, bracket_end = '{', '}'
                
                # Map element type to DuckDB type
                elem_db_type = type_map.get(elem_type, 'VARCHAR')
                
                # Read as VARCHAR, then parse and convert to LIST
                col_defs.append(f"'{f}': 'VARCHAR'")
                
                # Parse the serialized format: remove brackets and split by comma
                # DuckDB's string_split returns a list, which we can use directly
                # For INET arrays, we'll need to cast each element separately
                if elem_db_type == 'INET':
                    # For arrays of IPs: split, then cast each element to INET
                    select_cols.append(f"""
                        CASE 
                            WHEN "{f}" = '-' OR "{f}" = '(empty)' OR "{f}" IS NULL OR "{f}" = '' THEN NULL
                            WHEN "{f}" = '{bracket_start}{bracket_end}' THEN NULL
                            ELSE list_transform(
                                string_split(
                                    REPLACE(REPLACE(TRIM("{f}"), '{bracket_start}', ''), '{bracket_end}', ''),
                                    ','
                                ),
                                x -> TRY_CAST(TRIM(x) AS INET)
                            )
                        END AS "{f}"
                    """)
                else:
                    # For other types, split and optionally cast
                    if elem_db_type != 'VARCHAR':
                        select_cols.append(f"""
                            CASE 
                                WHEN "{f}" = '-' OR "{f}" IS NULL OR "{f}" = '' THEN NULL
                                WHEN "{f}" = '{bracket_start}{bracket_end}' THEN NULL
                                ELSE list_transform(
                                    string_split(
                                        REPLACE(REPLACE(TRIM("{f}"), '{bracket_start}', ''), '{bracket_end}', ''),
                                        ','
                                    ),
                                    x -> TRY_CAST(TRIM(x) AS {elem_db_type})
                                )
                            END AS "{f}"
                        """)
                    else:
                        # For VARCHAR, just split (no casting needed)
                        select_cols.append(f"""
                            CASE 
                                WHEN "{f}" = '-' OR "{f}" IS NULL OR "{f}" = '' THEN NULL
                                WHEN "{f}" = '{bracket_start}{bracket_end}' THEN NULL
                                ELSE string_split(
                                    REPLACE(REPLACE(TRIM("{f}"), '{bracket_start}', ''), '{bracket_end}', ''),
                                    ','
                                )
                            END AS "{f}"
                        """)
            else:
                # Use the mapped type directly for other fields
                col_defs.append(f"'{f}': '{db_type}'")
                select_cols.append(f"\"{f}\"")
        
        col_def = ", ".join(col_defs)
        
        select_statements.append(f"""
            SELECT {', '.join(select_cols)}, '{info['files'][0]}' as schema_source 
            FROM read_csv({str(info['files'])}, delim='\\t', skip=8, header=false, columns={{{col_def}}}, nullstr='-', ignore_errors=True)
        """)
    
    # Create a raw view with flat dotted column names
    raw_view_name = f"__{log_type}_raw"
    view_sql = f"CREATE VIEW \"{raw_view_name}\" AS {' UNION ALL BY NAME '.join(select_statements)}"
    con.execute(view_sql)
    
    # Collect all field names (in order) across all schemas for this log type
    field_order = []
    seen_fields = set()
    for info in schemas.values():
        for f in info['fields']:
            if f not in seen_fields:
                seen_fields.add(f)
                field_order.append(f)
    
    # Check if any fields have dots (e.g., id.orig_h)
    has_dotted = any('.' in f for f in field_order)
    
    if has_dotted:
        # Group dotted fields into STRUCTs so users can write id.orig_h instead of "id.orig_h"
        from collections import OrderedDict
        struct_groups = OrderedDict()  # prefix -> [full_field_name, ...]
        
        for f in field_order:
            if '.' in f:
                prefix = f.split('.', 1)[0]
                if prefix not in struct_groups:
                    struct_groups[prefix] = []
                struct_groups[prefix].append(f)
        
        # Build wrapper SELECT: replace dotted fields with STRUCT_PACK
        wrapper_parts = []
        seen_prefixes = set()
        for f in field_order:
            if '.' in f:
                prefix = f.split('.', 1)[0]
                if prefix not in seen_prefixes:
                    seen_prefixes.add(prefix)
                    pack_parts = []
                    for full_name in struct_groups[prefix]:
                        sub = full_name.split('.', 1)[1]
                        pack_parts.append(f'"{sub}" := "{full_name}"')
                    wrapper_parts.append(f'STRUCT_PACK({", ".join(pack_parts)}) AS "{prefix}"')
            else:
                wrapper_parts.append(f'"{f}"')
        
        # Include schema_source column
        wrapper_parts.append('"schema_source"')
        
        wrapper_sql = f'CREATE VIEW "{log_type}" AS SELECT {", ".join(wrapper_parts)} FROM "{raw_view_name}"'
        con.execute(wrapper_sql)
    else:
        # No dotted fields, just alias the raw view
        con.execute(f'CREATE VIEW "{log_type}" AS SELECT * FROM "{raw_view_name}"')
    
    print(f"[*] View '{log_type}' created ({len(schemas)} schemas detected)", file=sys.stderr)

t_view = time.perf_counter() - t0
print(f"[*] All views initialized in {t_view:.4f}s\n", file=sys.stderr)

# 4. Execution & Streaming
print(f"--- Streaming Results ---\n", file=sys.stderr, flush=True)
t0 = time.perf_counter()
row_count = 0

try:
    res = con.execute(user_query)
    # Make column names unique for JOIN output (duplicate names get _2, _3, ...)
    col_names = [d[0] for d in res.description]
    seen = {}
    unique_names = []
    for name in col_names:
        count = seen.get(name, 0) + 1
        seen[name] = count
        unique_names.append(f"{name}_{count}" if count > 1 else name)
    print("\t".join(unique_names), flush=True)
    
    # Row 2: Original Zeek type names (looked up from schema metadata)
    col_types = []
    for i, name in enumerate(col_names):
        if name in zeek_type_lookup:
            # Direct field match (e.g., "ts" -> "time", "uid" -> "string")
            col_types.append(zeek_type_lookup[name])
        else:
            # Check if this is a struct column (e.g., "id" groups "id.orig_h", "id.resp_h", ...)
            # Build a record type from the sub-fields
            sub_types = []
            for field_name, zeek_type in zeek_type_lookup.items():
                if field_name.startswith(name + '.'):
                    sub_types.append(zeek_type)
            if sub_types:
                col_types.append('record[' + ','.join(sub_types) + ']')
            else:
                # SQL expression or alias — use DuckDB type as fallback
                try:
                    col_types.append(str(res.description[i][1]).lower())
                except:
                    col_types.append('unknown')
    print("\t".join(col_types), flush=True)
    
    def format_value(val):
        """Recursively format a DuckDB value to match Zeek log conventions."""
        if val is None:
            return '-'
        elif val is False:
            return 'F'
        elif val is True:
            return 'T'
        elif isinstance(val, dict) and 'address' in val and 'ip_type' in val:
            # DuckDB INET type -> IP address string
            try:
                if val['ip_type'] == 1:  # IPv4
                    return str(ipaddress.IPv4Address(val['address']))
                elif val['ip_type'] == 2:  # IPv6
                    return str(ipaddress.IPv6Address(val['address']))
            except:
                pass
            return str(val)
        elif isinstance(val, dict):
            # STRUCT type -> {field1: value1, field2: value2}
            formatted = ', '.join(f'{k}: {format_value(v)}' for k, v in val.items())
            return '{' + formatted + '}'
        elif isinstance(val, list):
            # LIST type -> [value1,value2,value3]
            return '[' + ','.join(format_value(item) for item in val) + ']'
        else:
            return str(val)
    
    while True:
        chunk = res.fetchmany(1000)
        if not chunk: break
        for row in chunk:
            print("\t".join(format_value(val) for val in row), flush=True)
            row_count += 1
            
    print(f"\n--- Summary ---", file=sys.stderr)
    print(f"Total Rows:  {row_count:,}\tQuery Time: {time.perf_counter()-t0:.4f}s", file=sys.stderr)
except Exception as e:
    print(f"\nSQL Error: {e}", file=sys.stderr)