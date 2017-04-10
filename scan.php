<?php
/**
 * Don't be suspicious
 * Recursively scans a directory for potentially malicious files (esp. PHP)
 */

// Config
$directoryToScan = '~/public_html/foo';
$logFile = '~/suspicious_log.txt';
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
);

// Recursively scan dir
function scanDirectory($dir) {
    global $suspiciousPatterns, $logFile;
    $clean = true;
    $files = scandir($dir);
    
    foreach ($files as $file) {
        if ($file == '.' || $file == '..') {
            continue;
        }

        $filePath = $dir . DIRECTORY_SEPARATOR . $file;
        
        if (is_dir($filePath)) {
            // Recursively scan subdirs
            if (!scanDirectory($filePath)) {
                $clean = false;
            }
        } else {
            // Scan leaf nodes, i.e., files
            if (pathinfo($filePath, PATHINFO_EXTENSION) === 'php') {
                if (!scanFile($filePath)) {
                    $clean = false;
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
    global $suspiciousPatterns, $logFile;
    $fileContent = file_get_contents($filePath);
    
    foreach ($suspiciousPatterns as $pattern) {
        if (preg_match($pattern, $fileContent, $matches)) {
            logMessage("Suspicious file found: $filePath (Pattern: {$pattern})");
            return false;
        }
    }
    
    return true;
}

// Write logs
function logMessage($message) {
    global $logFile;
    $logEntry = date('Y-m-d H:i:s') . ' - ' . $message . PHP_EOL;
    file_put_contents($logFile, $logEntry, FILE_APPEND);
}

scanDirectory($directoryToScan);

echo "Suspicious file scan complete! See $logFile for results.";
?>
