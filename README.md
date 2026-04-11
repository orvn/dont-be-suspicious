# Don't Be Suspicious

<img src="./assets/images/dont-be-suspicious-2.png" width="300">

A PHP malware scanner. Finds suspicious files by looking for common malicious patterns. This tool is meant as a starting point to signal where files that may have some degree of obfuscated code can be found, and is good for surveying large directories for potential compromises.

## Compatibility
- For portability purposes, all the logic is included in a single file, `scan.php`
- To be used with PHP 5.5 or above

## Usage

```bash
php -f scan.php [target_directory] [log_file] [--exclude=dir1,dir2,...] [--max=size]
```

- Relative paths are okay
- If not supplied, the default target directory is the current directory
- Max to be provided in bytes
- If not supplied, the default max size before a file is skipped is 1MB (`1048576`)
- If not supplied, a log file is created in the current directory: `suspicious_[date].log`
- If more logs are created from the same day, they are appended to the existing file

## Options

- `--exclude` 
  - A comma-separated list of directories to exclude from the scan

- `--max`
  - Sets the maximum file size (in bytes)

## Examples

`php -f scan.php`

`php -f scan.php ~/public_html --exclude ~/public_html/backups --max=5242880`

## Error handling

- Permission checks
  - Checks for read permissions on directories and files before scanning
- File Read Errors
  - If a file can't be read it is logged as an error and skipped

## Heuristic scoring

- Each pattern carries a score
- A file's total score is the sum of every matched pattern
- The risk level is a representation of that total

| Score | Level | Description |
|-------|-------|-------------|
| 0–7 | Clean | No meaningful signals |
| 8–19 | Low | Common patterns stacking (worth noting but rarely actionable) |
| 20–34 | Medium | Real concern — `eval`, `shell_exec`, `passthru` alone land here |
| 35–59 | High | Strong indicators — `preg_replace /e`, `backdoor`, WP hook abuse |
| 60+ | Critical | Multiple strong indicators combined |

Only Medium and above are counted as "flagged" in the scan summary.

### Score tiers

Scores are calibrated so that common-but-legitimate patterns contribute little noise, while rare or dangerous patterns rapidly push a file into higher risk bands.

| Score range | What it means | Examples |
|-------------|---------------|---------|
| 1–3 | Noise, extremely common in legitimate code | `die`, `header()`, `session_start`, `$_SERVER`, `mysqli_query`, `fopen`, `curl_exec` |
| 4–7 | Eyebrow-raise, slightly suspicious in isolation | `str_rot13`, `gzinflate`, `base_convert`, `$$` variable variables |
| 12–15 | Concerning, uncommon in clean code | `assert`, `system`, `exec`, `popen`, `proc_open`, `echo '<script'`, `stream_socket_server` |
| 20–25 | Strong indicators, rarely legitimate | `eval`, `shell_exec`, `passthru`, `create_function`, backtick execution, remote `file_get_contents` |
| 35–40 | Near-certain malware | `preg_replace /e`, `backdoor`, WP hook payloads (`add_action.*base64_decode`), polyglot file headers |

### False positive handling

Patterns that were generating too many false positives are commented out rather than removed (`include`, `include_once`, `require`, `require_once`). Low-score patterns only contribute to a flag when they accumulate alongside higher-score matches. E.g., a file with only `$_POST` and `header()` scores a 3 and stays _Clean_.

## Enhancements

_Ideas for improvement_
- Progress indicator

#### Lineage

This project began as a result of observations I mention in [a 2016 Stack Overflow thread](https://stackoverflow.com/questions/9731800/wordpress-site-is-appears-clear-of-malware-but-clicking-on-google-search-result/78802204).
