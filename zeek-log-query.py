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
for root, dirs, files in os.walk('.'):
    for file in files:
        file_path = os.path.join(root, file)
        # Check if file matches any of the regex patterns
        if any(pattern.search(file_path) for pattern in file_regexes):
            all_files.add(file_path)

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

t_metadata = time.perf_counter() - t0
print(f"[*] Analyzed {len(all_files):,} files. Identified {len(log_collections)} log types in {t_metadata:.4f}s", file=sys.stderr)

# 3. Build Views for each Log Type
t0 = time.perf_counter()
con = duckdb.connect()
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
            if db_type == 'INET':
                # Read as VARCHAR since read_csv doesn't support INET, then cast to INET
                col_defs.append(f"'{f}': 'VARCHAR'")
                select_cols.append(f"TRY_CAST(CASE WHEN \"{f}\" = '-' OR \"{f}\" IS NULL OR \"{f}\" = '' THEN NULL ELSE \"{f}\" END AS INET) AS \"{f}\"")
            else:
                # Use the mapped type directly for other fields
                col_defs.append(f"'{f}': '{db_type}'")
                select_cols.append(f"\"{f}\"")
        
        col_def = ", ".join(col_defs)
        
        select_statements.append(f"""
            SELECT {', '.join(select_cols)}, '{info['files'][0]}' as schema_source 
            FROM read_csv({str(info['files'])}, delim='\\t', skip=8, header=false, columns={{{col_def}}}, nullstr='-', ignore_errors=True)
        """)
    
    # Create a view named after the Zeek #path (e.g., CREATE VIEW conn AS...)
    view_sql = f"CREATE VIEW \"{log_type}\" AS {' UNION ALL BY NAME '.join(select_statements)}"
    con.execute(view_sql)
    print(f"[*] View '{log_type}' created ({len(schemas)} schemas detected)", file=sys.stderr)

t_view = time.perf_counter() - t0
print(f"[*] All views initialized in {t_view:.4f}s\n", file=sys.stderr)

# 4. Execution & Streaming
print(f"--- Streaming Results ---\n", file=sys.stderr, flush=True)
t0 = time.perf_counter()
row_count = 0

try:
    res = con.execute(user_query)
    print("\t".join([d[0] for d in res.description]), flush=True)
    
    while True:
        chunk = res.fetchmany(1000)
        if not chunk: break
        for row in chunk:
            # Convert values to match Zeek log format: None -> '-', False -> 'F', True -> 'T'
            # Also convert INET types (dictionaries) to IP address strings
            formatted_row = []
            for val in row:
                if val is None:
                    formatted_row.append('-')
                elif val is False:
                    formatted_row.append('F')
                elif val is True:
                    formatted_row.append('T')
                elif isinstance(val, dict) and 'address' in val and 'ip_type' in val:
                    # Convert DuckDB INET dictionary to IP address string
                    try:
                        if val['ip_type'] == 1:  # IPv4
                            ip = ipaddress.IPv4Address(val['address'])
                            formatted_row.append(str(ip))
                        elif val['ip_type'] == 2:  # IPv6
                            ip = ipaddress.IPv6Address(val['address'])
                            formatted_row.append(str(ip))
                        else:
                            formatted_row.append(str(val))
                    except:
                        formatted_row.append(str(val))
                else:
                    formatted_row.append(str(val))
            print("\t".join(formatted_row), flush=True)
            row_count += 1
            
    print(f"\n--- Summary ---", file=sys.stderr)
    print(f"Total Rows:  {row_count:,}\tQuery Time: {time.perf_counter()-t0:.4f}s", file=sys.stderr)
except Exception as e:
    print(f"\nSQL Error: {e}", file=sys.stderr)