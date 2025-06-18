# Fractus

A command-line interface for [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) using the [fractus-shamir](../fractus-shamir) library.

## 🚀 Quick Start

### Installation

#### From Source
```bash
git clone https://github.com/logan272/fractus.git
cd fractus
cargo install --path crates/fractus-cli
```

### Basic Usage

```bash
# Split a secret into 5 shares (need 3 to recover)
echo "my secret password" | fractus split -k 3 -n 5

# Split a file
fractus split -k 3 -n 5 -i secret.txt -o ./shares/

# Recover from shares
fractus recover shares/share-*.json

# Get information about shares
fractus info shares/
```

## Commands

### `split`

Split a secret into multiple shares using Shamir's Secret Sharing.

```bash
fractus split -k <THRESHOLD> -n <SHARES> [OPTIONS]
```

#### Examples

```bash
# Interactive secret entry (hidden input)
fractus split -k 3 -n 5 --interactive

# From file with custom output directory
fractus split -k 2 -n 4 -i document.pdf -o /secure/shares/

# From environment variable
export SECRET_KEY="my-api-key-12345"
fractus split -k 3 -n 7 --env-var SECRET_KEY

# Output to stdout in hex format
echo "secret" | fractus split -k 2 -n 3 --stdout -f hex

# Deterministic shares with custom seed
fractus split -k 3 -n 5 -i file.txt --seed "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# Include metadata in output
fractus split -k 3 -n 5 -i secret.txt --include-metadata
```

#### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-k, --threshold <THRESHOLD>` | Minimum shares needed for recovery | Required |
| `-n, --shares <SHARES>` | Number of shares to generate | Required |
| `-i, --input <FILE>` | Input file (use '-' for stdin) | `"-"` |
| `-o, --output-dir <DIR>` | Output directory for share files | Current directory |
| `-f, --format <FORMAT>` | Output format: json, hex, base64, binary | `"json"` |
| `--base-name <NAME>` | Base name for output files | `"share"` |
| `--stdout` | Print shares to stdout instead of files | `false` |
| `--env-var <VAR>` | Read secret from environment variable | - |
| `--interactive` | Prompt for secret interactively (hidden) | `false` |
| `--seed <HEX>` | Custom seed for deterministic generation | - |
| `--include-metadata` | Include metadata in output | `false` |

### `recover`

Reconstruct the original secret from shares.

```bash
fractus recover <SHARES...> [OPTIONS]
```

#### Examples

```bash
# Recover from specific files
fractus recover share-001.json share-003.json share-005.json

# Recover from directory (auto-detect share files)
fractus recover /path/to/shares/

# Recover from stdin
cat shares.txt | fractus recover --stdin

# Save to specific file
fractus recover shares/*.json -o recovered-secret.txt

# Verify recovery by re-splitting
fractus recover shares/*.json --verify

# Specify expected threshold for validation
fractus recover shares/*.json -k 3
```

#### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --format <FORMAT>` | Input format (auto-detect if not specified) | Auto-detect |
| `-o, --output <FILE>` | Output file (use '-' for stdout) | `"-"` |
| `-k, --threshold <THRESHOLD>` | Expected threshold for validation | Auto-infer |
| `--stdin` | Read shares from stdin (one per line) | `false` |
| `--verify` | Verify recovery by re-splitting | `false` |

### `info`

Display detailed information about shares and their compatibility.

```bash
fractus info <SHARES...> [OPTIONS]
```

#### Examples

```bash
# Analyze shares in a directory
fractus info /path/to/shares/

# Analyze specific files
fractus info share-*.json

# Detailed information
fractus info shares/ --detailed

# Output as JSON
fractus info shares/ --output-format json

# Output as YAML
fractus info shares/ --output-format yaml
```

#### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --format <FORMAT>` | Input format (auto-detect if not specified) | Auto-detect |
| `-d, --detailed` | Show detailed information | `false` |
| `--output-format <FORMAT>` | Output format: table, json, yaml | `"table"` |

## File Formats

Fractus-CLI supports multiple input/output formats for maximum flexibility:

### JSON Format (Default)
Human-readable with optional metadata:

```json
{
  "id": 1,
  "x": 1,
  "y": [42, 137, 203, 91],
  "threshold": 3,
  "total_shares": 5,
  "created_at": "2024-06-17T10:30:00Z"
}
```

### Hex Format
Compact hexadecimal encoding:

```
01002a89cb5b
```

### Base64 Format
Standard base64 encoding:

```
AQAqics[
```

### Binary Format
Raw binary data (most compact):

```bash
# Binary files are not human-readable
file share-001.bin
# share-001.bin: data
```

## Configuration

Fractus-CLI supports configuration files for default settings.

### Configuration Locations

1. `~/.config/fractus/config.toml` (Linux/macOS)
2. `%APPDATA%\fractus\config.toml` (Windows)
3. `./fractus.toml` (current directory)
4. `./.fractus.toml` (current directory, hidden)

### Configuration Format

```toml
[defaults]
threshold = 3
shares = 5
format = "json"
```

### Custom Configuration

```bash
# Use specific config file
fractus split -k 2 -n 3 --config /path/to/config.toml

# Override config with command-line options
fractus split -k 5 -n 8  # Overrides config defaults
```

## Advanced Usage

### Batch Processing

```bash
# Split multiple files
for file in *.txt; do
    fractus split -k 3 -n 5 -i "$file" -o "shares-$file/"
done

# Recover multiple secrets
for dir in shares-*/; do
    fractus recover "$dir"*.json -o "recovered-$(basename "$dir").txt"
done
```

### Pipeline Usage

```bash
# Generate secret and split in one command
openssl rand -base64 32 | fractus split -k 3 -n 5 --stdout -f hex

# Split and immediately test recovery
echo "test secret" | fractus split -k 2 -n 3 --stdout | head -2 | fractus recover --stdin
```

### Scripting

```bash
#!/bin/bash
# backup-keys.sh - Split SSH keys for backup

KEY_FILE="$HOME/.ssh/id_rsa"
BACKUP_DIR="/secure/backups/ssh-keys"

if [ ! -f "$KEY_FILE" ]; then
    echo "SSH key not found: $KEY_FILE"
    exit 1
fi

# Split the key into 7 shares (need 4 to recover)
fractus split -k 4 -n 7 -i "$KEY_FILE" -o "$BACKUP_DIR" --include-metadata

echo "SSH key split into 7 shares in $BACKUP_DIR"
echo "Store these shares in different secure locations"
echo "Need any 4 shares to recover the key"
```

### Security Best Practices

```bash
# Use environment variable for sensitive data
export SECRET_DATA="$(cat sensitive-file.txt)"
fractus split -k 3 -n 5 --env-var SECRET_DATA
unset SECRET_DATA

# Interactive input for maximum security
fractus split -k 3 -n 5 --interactive

# Verify integrity during recovery
fractus recover shares/*.json --verify -o recovered.txt

# Check share compatibility before recovery
fractus info shares/ --detailed
```
