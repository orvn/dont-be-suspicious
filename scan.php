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
    '/`.*`/i', // backticks indicicate suspicious shell exec usage
    '/preg_replace\s*\(.*\/e.*\)/i', // preg_replace with /e modifier is suspicious
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
        if (preg_match($pattern, $fileContent)) {
            logMessage("Suspicious file found: $filePath");
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
