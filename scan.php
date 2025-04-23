<?php
/**
 * Don't be suspicious
 * Recursively scans a directory for potentially malicious files (esp. PHP)
 */

// Config
$defaultDir = getcwd();
$defaultLog = getcwd() . DIRECTORY_SEPARATOR . 'suspicious_' . date('Ymd') . '.log';
$maxFileSize = 1 * 1024 * 1024; // Default to 1MB

// Get $1 and $2 args
$targetDir = isset($argv[1]) ? $argv[1] : $defaultDir;
$targetLog = isset($argv[2]) ? $argv[2] : $defaultLog;

// Exclude dirs
$excludedDirs = array();

// CLI flags
for ($i = 3; $i < count($argv); $i++) {
    if (strpos($argv[$i], '--exclude=') === 0) {
        $excludePaths = substr($argv[$i], 10);
        $excludedDirs = array_merge($excludedDirs, explode(',', $excludePaths));
    } elseif (strpos($argv[$i], '--max=') === 0) {
        $maxFileSize = (int) substr($argv[$i], 6);
    }
}

// Running list of regex patterns for suspicious PHP
$suspiciousPatterns = array(
    '/base64_decode\s*\(/i', // Most common obfuscation
    '/eval\s*\(/i', // Arbitrary code eval
    '/shell_exec\s*\(/i', // Shell execution
    '/system\s*\(/i', // System command execution
    '/exec\s*\(/i', // Command execution
    '/passthru\s*\(/i', // Command execution with output
    '/popen\s*\(/i', // Opens process for read-write
    '/proc_open\s*\(/i', // Opens a process
    '/`.*`/i', // Backticks suggest suspicious shell exec usage
    '/preg_replace\s*\(.*\/e.*\)/i', // preg_replace with /e modifier
    '/str_rot13\s*\(/i', // Another common obfuscation pattern
    '/gzuncompress\s*\(/i', // Decompresses data
    '/gzinflate\s*\(/i', // Decompresses data
    '/strrev\s*\(/i', // String reversal
    '/date\s*\(/i', // Uses date functions (may indicate time-based behavior)
    '/time\s*\(/i', // Uses current time (used to trigger actions)
    '/rand\s*\(/i', // Uses random number generation
    '/mt_rand\s*\(/i', // Mersenne Twister RNG
    '/microtime\s*\(/i', // Uses precise timing (can be used in stealth logic)
    '/echo\s+["\']<script/i', // Outputs inline script tag
    '/print\s+["\']<script/i', // Prints inline script tag
    '/printf\s*\(\s*["\']<script/i', // Formatted print of script tag
    '/document\.write\s*\(/i', // JavaScript injection pattern
    '/<iframe[^>]+style\s*=\s*["\']?display\s*:\s*none/i', // Hidden iframe using inline CSS
    '/<iframe[^>]+width\s*=\s*["\']?0/i', // Zero-width iframe
    '/<iframe[^>]+height\s*=\s*["\']?0/i', // Zero-height iframe
    '/<div[^>]+style\s*=\s*["\']?display\s*:\s*none/i', // Hidden div used for fake content or obfuscation
    '/ob_start\s*\(/i', // Starts output buffering
    '/ob_get_clean\s*\(/i', // Gets current buffer and deletes it
    '/ob_end_clean\s*\(/i', // Ends and cleans output buffer
    '/ob_get_contents\s*\(/i', // Gets current buffer contents
    '/add_action\s*\(.*base64_decode/i', // Obfuscated code in WP hook
    '/add_filter\s*\(.*eval/i', // Code execution in WP filter
    '/wp_eval_request\s*\(/i', // Known malicious plugin pattern
    '/\$GLOBALS\s*\[\s*["\']wp_filter["\']\s*\]/i', // Manipulates WP global hooks
    '/functions\.php/i', // Indicates direct theme function manipulation
    '/wp-config\.php/i', // Indicates tampering with configuration
    '/fopen\s*\(/i', // Opens file
    '/fwrite\s*\(/i', // Writes to file
    '/fread\s*\(/i', // Reads from file
    '/file_put_contents\s*\(/i', //  Writes to file
    '/file_get_contents\s*\(/i', // Reads from file
    '/unlink\s*\(/i', // Deletes file
    '/rename\s*\(/i', // Renames file
    '/assert\s*\(/i', // Executes some PHP
    // '/include\s*\(/i',
    // '/include_once\s*\(/i',
    // '/require\s*\(/i',
    // '/require_once\s*\(/i',
    '/\$_REQUEST/i', // User input
    '/\$_POST/i', // User input
    '/\$_GET/i', // User input
    '/\$_FILES/i', // User input
    '/\$_SERVER/i', // Server variables
    '/\$_COOKIE/i', // User cookies
    '/\$_SESSION/i', // User session data
    '/\$_ENV/i', // Environment variables
    '/\$_SERVER\s*\[\s*[\'"]HTTP_REFERER[\'"]\s*\]/i', // HTTP Referrer
    '/\$_SERVER\s*\[\s*[\'"]HTTP_USER_AGENT[\'"]\s*\]/i', // User Agent
    '/preg_match\s*\(.*(HTTP_USER_AGENT|HTTP_REFERER)/i', // Matches user agent or referrer
    '/strpos\s*\(\s*\$_SERVER\s*\[\s*[\'"](HTTP_USER_AGENT|HTTP_REFERER)[\'"]\s*\]/i', // Checks user agent or referrer
    '/php:\/\/input/i', // Raw POST data
    '/php:\/\/filter/i', // PHP filter wrapper
    '/curl_exec\s*\(/i', // Starts curl session
    '/curl_multi_exec\s*\(/i', // Executes multiple cURL sessions
    '/fsockopen\s*\(/i', // Opens a socket connection
    '/pfsockopen\s*\(/i', // Opens a persistent socket connection
    '/stream_socket_client\s*\(/i', // Creates a socket client
    '/stream_socket_server\s*\(/i', // Creates a socket server
    '/session_start\s*\(/i', // Starts a session
    '/session_regenerate_id\s*\(/i', // Regenerates session ID
    '/header\s*\(/i', // Sends a raw HTTP header
    '/setcookie\s*\(/i', // Sets a cookie
    '/setrawcookie\s*\(/i', // Sets a raw cookie
    '/create_function\s*\(/i', // Creates an anonymous function
    '/call_user_func\s*\(/i', // Calls a callback function
    '/call_user_func_array\s*\(/i', // Calls a callback function with an array of parameters
    '/unserialize\s*\(/i', // Unserializes data
    '/\$\$/i', // Variable variables
    '/phpinfo\s*\(/i', // Outputs PHP configuration
    '/die\s*\(/i', // Terminates script execution
    '/exit\s*\(/i', // Terminates script execution
    '/register_shutdown_function\s*\(/i', // Registers a shutdown function
    '/ini_set\s*\(/i', // Sets a configuration option
    '/ini_get\s*\(/i', // Gets a configuration option
    '/mysql_query\s*\(/i', // MySQL query
    '/mysqli_query\s*\(/i', // MySQLi query
    '/pg_query\s*\(/i', // PostgreSQL query
    '/sqlite_query\s*\(/i', // SQLite query
    '/file_get_contents\s*\(\s*("|\')https?:\/\//i', // Remote file inclusion
    '/mcrypt_encrypt\s*\(/i', // Encrypts data
    '/mcrypt_decrypt\s*\(/i', // Decrypts data
    '/openssl_encrypt\s*\(/i', // Encrypts data with OpenSSL
    '/openssl_decrypt\s*\(/i', // Decrypts data with OpenSSL
    '/base_convert\s*\(/i', // Converts a number from one base to another
    '/pack\s*\(/i', // Packs data into binary string
    '/unpack\s*\(/i', // Unpacks data from binary string
    '/ReflectionFunction\s*\(/i', // Reflects on a function
    '/ReflectionMethod\s*\(/i', // Reflects on a method
    '/ReflectionClass\s*\(/i', // Reflects on a class
    '/backdoor/i', // Indicates potential backdoor
    '/shell/i', // Indicates shell commands
    '/cmd/i', // Indicates command execution
    '/pcntl_exec\s*\(/i' // Executes a program
);

// Counters for report
$totalFilesScanned = 0;
$suspiciousFilesFound = 0;
$filesSkipped = 0;

// Check if is excluded
function isExcluded($dir) {
    global $excludedDirs;
    foreach ($excludedDirs as $excludedDir) {
        if (strpos($dir, $excludedDir) === 0) {
            return true;
        }
    }
    return false;
}

// Perms for dirs
function checkPerms($dir) {
    if (!is_readable($dir)) {
        throw new Exception("Error: unable to read directory: $dir");
    }
    $files = scandir($dir);
    foreach ($files as $file) {
        if ($file == '.' || $file == '..') {
            continue;
        }
        $filePath = $dir . DIRECTORY_SEPARATOR . $file;
        if (is_dir($filePath)) {
            checkPerms($filePath);
        }
    }
}

// Scan file
function scanFile($filePath) {
    global $suspiciousPatterns, $targetLog;
    $fileContent = @file_get_contents($filePath);

    if ($fileContent === false) {
        echo "\033[31mError: Unable to read file: $filePath\033[0m\n";
        logMessage("Error: Unable to read file: $filePath");
        return false;
    }
    
    foreach ($suspiciousPatterns as $pattern) {
        if (preg_match($pattern, $fileContent, $matches)) {
            $redPattern = "\033[31m{$pattern}\033[0m"; // Red color for pattern
            echo "Suspicious file found: $filePath (Pattern: {$redPattern})\n";
            logMessage("Suspicious file found: $filePath (Pattern: {$pattern})");
            return false;
        }
    }
    
    return true;
}

// Write logs
function logMessage($message) {
    global $targetLog;
    $logEntry = date('Y-m-d H:i:s') . ' - ' . $message . PHP_EOL;
    file_put_contents($targetLog, $logEntry, FILE_APPEND);
}

function scanDirectory($dir) {
    global $suspiciousPatterns, $targetLog, $totalFilesScanned, $suspiciousFilesFound, $filesSkipped, $maxFileSize;
    $clean = true;
    $queue = array($dir);

    while (!empty($queue)) {
        $currentDir = array_shift($queue);
        $files = scandir($currentDir);

        foreach ($files as $file) {
            if ($file == '.' || $file == '..') {
                continue;
            }

            $filePath = $currentDir . DIRECTORY_SEPARATOR . $file;

            if (isExcluded($filePath)) {
                continue;
            }

            if (is_dir($filePath)) {
                $queue[] = $filePath; // Add subdirectory to the queue
            } else {
                // Scan leaf nodes, i.e., files
                if (pathinfo($filePath, PATHINFO_EXTENSION) === 'php') {
                    if ($maxFileSize > 0 && filesize($filePath) > $maxFileSize) {
                        $filesSkipped++;
                        echo "\033[33mFile skipped due to size: $filePath\033[0m\n";
                        logMessage("File skipped due to size: $filePath");
                        continue;
                    }
                    $totalFilesScanned++;
                    if (!scanFile($filePath)) {
                        $clean = false;
                        $suspiciousFilesFound++;
                    }
                }
            }
        }
    }

    if ($clean) {
        logMessage("Directory clean: $dir");
    } else {
        logMessage("Suspicious files found in directory: $dir");
    }

    return $clean;
}

try {
    checkPerms($targetDir);
    scanDirectory($targetDir);
    $greenMessage = "\033[32mSuspicious file scan complete! See $targetLog for results.\033[0m";
    echo $greenMessage;

    // Print report on completion
    echo "\n\n[Summary of Scan]\n\n";
    echo "Total files scanned: $totalFilesScanned\n";
    echo "Suspicious files found: $suspiciousFilesFound\n";
    echo "Files skipped due to size: $filesSkipped\n";

} catch (Exception $e) {
    echo "\033[31m" . $e->getMessage() . "\033[0m\n";
}
?>
