# Don't be suspicious

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

## Enhancements

_Ideas for improvement_
- Move all patterns into a map with metadata on each one
- Progress indicator
- Score threat level per pattern and use scores to assess potential thread
- Implement heuristic analysis approach
