<?php
/**
 * Don't be suspicious
 * Recursively scans a directory for potentially malicious files (esp. PHP)
 */

// Config
$defaultDir = getcwd();
$defaultLog = getcwd() . DIRECTORY_SEPARATOR . 'suspicious_' . date('Ymd') . '.log';

// Get $1 and $2 args
$targetDir = isset($argv[1]) ? $argv[1] : $defaultDir;
$targetLog = isset($argv[2]) ? $argv[2] : $defaultLog;

// Exclude dirs
$excludedDirs = array();

for ($i = 3; $i < count($argv); $i++) {
    if (strpos($argv[$i], '--exclude=') === 0) {
        $excludePaths = substr($argv[$i], 10);
        $excludedDirs = array_merge($excludedDirs, explode(',', $excludePaths));
    }
}

// Running list of regex patterns for suspicious PHP
$suspiciousPatterns = array(
    '/base64_decode\s*\(/i',
    '/eval\s*\(/i',
    '/shell_exec\s*\(/i',
    '/system\s*\(/i',
    '/exec\s*\(/i',
    '/passthru\s*\(/i',
    '/popen\s*\(/i',
    '/proc_open\s*\(/i',
    '/`.*`/i', // backticks indicate suspicious shell exec usage
    '/preg_replace\s*\(.*\/e.*\)/i', // preg_replace with /e modifier is suspicious
    '/str_rot13\s*\(/i',
    '/gzuncompress\s*\(/i',
    '/gzinflate\s*\(/i',
    '/strrev\s*\(/i',
    '/fopen\s*\(/i',
    '/fwrite\s*\(/i',
    '/fread\s*\(/i',
    '/file_put_contents\s*\(/i',
    '/file_get_contents\s*\(/i',
    '/unlink\s*\(/i',
    '/rename\s*\(/i',
    '/assert\s*\(/i',
    '/include\s*\(/i',
    '/include_once\s*\(/i',
    '/require\s*\(/i',
    '/require_once\s*\(/i',
    '/\$_REQUEST/i',
    '/\$_POST/i',
    '/\$_GET/i',
    '/\$_FILES/i',
    '/\$_SERVER/i',
    '/\$_COOKIE/i',
    '/\$_SESSION/i',
    '/\$_ENV/i',
    '/php:\/\/input/i',
    '/php:\/\/filter/i',
    '/curl_exec\s*\(/i',
    '/curl_multi_exec\s*\(/i',
    '/fsockopen\s*\(/i',
    '/pfsockopen\s*\(/i',
    '/stream_socket_client\s*\(/i',
    '/stream_socket_server\s*\(/i',
    '/session_start\s*\(/i',
    '/session_regenerate_id\s*\(/i',
    '/header\s*\(/i',
    '/setcookie\s*\(/i',
    '/setrawcookie\s*\(/i',
    '/create_function\s*\(/i',
    '/call_user_func\s*\(/i',
    '/call_user_func_array\s*\(/i',
    '/unserialize\s*\(/i',
    '/\$\$/i', // Variable variables
    '/phpinfo\s*\(/i',
    '/die\s*\(/i',
    '/exit\s*\(/i',
    '/register_shutdown_function\s*\(/i',
    '/ini_set\s*\(/i',
    '/ini_get\s*\(/i',
    '/mysql_query\s*\(/i',
    '/mysqli_query\s*\(/i',
    '/pg_query\s*\(/i',
    '/sqlite_query\s*\(/i',
    '/file_get_contents\s*\(\s*("|\')https?:\/\//i', // Remote file inclusion
    '/mcrypt_encrypt\s*\(/i',
    '/mcrypt_decrypt\s*\(/i',
    '/openssl_encrypt\s*\(/i',
    '/openssl_decrypt\s*\(/i',
    '/base_convert\s*\(/i',
    '/pack\s*\(/i',
    '/unpack\s*\(/i',
    '/ReflectionFunction\s*\(/i',
    '/ReflectionMethod\s*\(/i',
    '/ReflectionClass\s*\(/i',
    '/backdoor/i',
    '/shell/i',
    '/cmd/i',
    '/pcntl_exec\s*\(/i'
);

// Counters for report
$totalFilesScanned = 0;
$suspiciousFilesFound = 0;

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

// Recursively scan dir
function scanDirectory($dir) {
    global $suspiciousPatterns, $targetLog, $totalFilesScanned, $suspiciousFilesFound;
    $clean = true;
    $files = scandir($dir);
    
    foreach ($files as $file) {
        if ($file == '.' || $file == '..') {
            continue;
        }

        $filePath = $dir . DIRECTORY_SEPARATOR . $file;
        
        if (isExcluded($filePath)) {
            continue;
        }

        if (is_dir($filePath)) {
            // Recursively scan subdirs
            if (!scanDirectory($filePath)) {
                $clean = false;
            }
        } else {
            // Scan leaf nodes, i.e., files
            if (pathinfo($filePath, PATHINFO_EXTENSION) === 'php') {
                $totalFilesScanned++;
                if (!scanFile($filePath)) {
                    $clean = false;
                    $suspiciousFilesFound++;
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

try {
    checkPerms($targetDir);
    scanDirectory($targetDir);
    $greenMessage = "\033[32mSuspicious file scan complete! See $targetLog for results.\033[0m";
    echo $greenMessage;

    // Print report on completion
    echo "\n\nSummary Report:\n";
    echo "Total files scanned: $totalFilesScanned\n";
    echo "Suspicious files found: $suspiciousFilesFound\n";

} catch (Exception $e) {
    echo "\033[31m" . $e->getMessage() . "\033[0m\n";
}
?>
