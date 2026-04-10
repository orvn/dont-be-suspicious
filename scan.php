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

// Heuristic score thresholds
// A file's total score is the sum of every matched pattern's score.
// Scores are calibrated so that common-but-legitimate patterns contribute
// little noise, while rare/dangerous patterns rapidly push a file into
// higher risk bands.
define('SCORE_LOW',      8);
define('SCORE_MEDIUM',   20);
define('SCORE_HIGH',     35);
define('SCORE_CRITICAL', 60);

// Running list of patterns with heuristic scores.
//
// score: how much this pattern contributes to the file's suspicion score.
//   1-3  : noise — extremely common in legitimate code
//   4-7  : eyebrow-raise — less common, slightly suspicious in isolation
//   12-15: concerning — uncommon in clean code, alarming when combined
//   20-25: strong indicator — rarely legitimate in web-facing PHP
//   35-40: near-certain malware — almost never seen in legitimate code
//
$suspiciousPatterns = array(

    // Obfuscation and encoding
    array('pattern' => '/base64_decode\s*\(/i',                                               'score' => 2,  'desc' => 'base64_decode() — common obfuscation layer'),
    array('pattern' => '/str_rot13\s*\(/i',                                                   'score' => 4,  'desc' => 'str_rot13() — ROT13 obfuscation'),
    array('pattern' => '/gzuncompress\s*\(/i',                                                'score' => 4,  'desc' => 'gzuncompress() — decompression (chained obfuscation)'),
    array('pattern' => '/gzinflate\s*\(/i',                                                   'score' => 4,  'desc' => 'gzinflate() — decompression (chained obfuscation)'),
    array('pattern' => '/strrev\s*\(/i',                                                      'score' => 2,  'desc' => 'strrev() — string reversal'),
    array('pattern' => '/preg_replace\s*\(.*\/e.*\)/i',                                      'score' => 35, 'desc' => 'preg_replace() with /e modifier — eval-equivalent code execution'),
    array('pattern' => '/pack\s*\(/i',                                                        'score' => 2,  'desc' => 'pack() — binary data packing'),
    array('pattern' => '/unpack\s*\(/i',                                                      'score' => 2,  'desc' => 'unpack() — binary data unpacking'),
    array('pattern' => '/base_convert\s*\(/i',                                                'score' => 7,  'desc' => 'base_convert() — used in obfuscation chains'),
    array('pattern' => '/mcrypt_encrypt\s*\(/i',                                              'score' => 2,  'desc' => 'mcrypt_encrypt() — legacy encryption'),
    array('pattern' => '/mcrypt_decrypt\s*\(/i',                                              'score' => 2,  'desc' => 'mcrypt_decrypt() — legacy decryption'),
    array('pattern' => '/openssl_encrypt\s*\(/i',                                             'score' => 1,  'desc' => 'openssl_encrypt() — OpenSSL encryption'),
    array('pattern' => '/openssl_decrypt\s*\(/i',                                             'score' => 1,  'desc' => 'openssl_decrypt() — OpenSSL decryption'),

    // Code execution
    array('pattern' => '/eval\s*\(/i',                                                        'score' => 20, 'desc' => 'eval() — arbitrary code execution'),
    array('pattern' => '/shell_exec\s*\(/i',                                                  'score' => 25, 'desc' => 'shell_exec() — shell command execution'),
    array('pattern' => '/system\s*\(/i',                                                      'score' => 15, 'desc' => 'system() — system command execution'),
    array('pattern' => '/exec\s*\(/i',                                                        'score' => 15, 'desc' => 'exec() — command execution'),
    array('pattern' => '/passthru\s*\(/i',                                                    'score' => 25, 'desc' => 'passthru() — raw command execution'),
    array('pattern' => '/popen\s*\(/i',                                                       'score' => 15, 'desc' => 'popen() — opens process pipe'),
    array('pattern' => '/proc_open\s*\(/i',                                                   'score' => 15, 'desc' => 'proc_open() — opens a process'),
    array('pattern' => '/assert\s*\(/i',                                                      'score' => 12, 'desc' => 'assert() — can execute PHP strings'),
    array('pattern' => '/call_user_func\s*\(/i',                                              'score' => 5,  'desc' => 'call_user_func() — dynamic function dispatch'),
    array('pattern' => '/call_user_func_array\s*\(/i',                                        'score' => 5,  'desc' => 'call_user_func_array() — dynamic function dispatch'),
    array('pattern' => '/create_function\s*\(/i',                                             'score' => 20, 'desc' => 'create_function() — eval-equivalent, deprecated'),
    array('pattern' => '/pcntl_exec\s*\(/i',                                                  'score' => 25, 'desc' => 'pcntl_exec() — replaces current process image'),

    // File operations
    array('pattern' => '/fopen\s*\(/i',                                                       'score' => 1,  'desc' => 'fopen() — opens a file'),
    array('pattern' => '/fwrite\s*\(/i',                                                      'score' => 2,  'desc' => 'fwrite() — writes to file'),
    array('pattern' => '/fread\s*\(/i',                                                       'score' => 1,  'desc' => 'fread() — reads from file'),
    array('pattern' => '/file_put_contents\s*\(/i',                                           'score' => 2,  'desc' => 'file_put_contents() — writes to file'),
    array('pattern' => '/file_get_contents\s*\(/i',                                           'score' => 1,  'desc' => 'file_get_contents() — reads a file'),
    array('pattern' => '/unlink\s*\(/i',                                                      'score' => 3,  'desc' => 'unlink() — deletes a file'),
    array('pattern' => '/rename\s*\(/i',                                                      'score' => 2,  'desc' => 'rename() — renames a file'),
    array('pattern' => '/file_get_contents\s*\(\s*("|\')https?:\/\//i',                      'score' => 20, 'desc' => 'file_get_contents() with remote URL — remote file inclusion'),

    // Dangerous or evasive functions
    array('pattern' => '/phpinfo\s*\(/i',                                                     'score' => 5,  'desc' => 'phpinfo() — configuration disclosure'),
    array('pattern' => '/die\s*\(/i',                                                         'score' => 1,  'desc' => 'die() — script termination'),
    array('pattern' => '/exit\s*\(/i',                                                        'score' => 1,  'desc' => 'exit() — script termination'),
    array('pattern' => '/register_shutdown_function\s*\(/i',                                  'score' => 5,  'desc' => 'register_shutdown_function() — registers persistent callback'),
    array('pattern' => '/ini_set\s*\(/i',                                                     'score' => 2,  'desc' => 'ini_set() — modifies PHP runtime configuration'),
    array('pattern' => '/ini_get\s*\(/i',                                                     'score' => 1,  'desc' => 'ini_get() — reads PHP runtime configuration'),
    array('pattern' => '/\$\$/i',                                                             'score' => 7,  'desc' => 'Variable variables ($$var) — obfuscation / dynamic dispatch'),

    // Superglobal use
    array('pattern' => '/\$_REQUEST/i',                                                       'score' => 5,  'desc' => '$_REQUEST — absorbs all user-controlled input types'),
    array('pattern' => '/\$_POST/i',                                                          'score' => 2,  'desc' => '$_POST — user-supplied POST input'),
    array('pattern' => '/\$_GET/i',                                                           'score' => 2,  'desc' => '$_GET — user-supplied GET input'),
    array('pattern' => '/\$_FILES/i',                                                         'score' => 3,  'desc' => '$_FILES — file upload data'),
    array('pattern' => '/\$_SERVER/i',                                                        'score' => 1,  'desc' => '$_SERVER — server variables'),
    array('pattern' => '/\$_COOKIE/i',                                                        'score' => 2,  'desc' => '$_COOKIE — user cookie data'),
    array('pattern' => '/\$_SESSION/i',                                                       'score' => 1,  'desc' => '$_SESSION — session data'),
    array('pattern' => '/\$_ENV/i',                                                           'score' => 2,  'desc' => '$_ENV — environment variables'),

    // HTTP behavior
    array('pattern' => '/\$_SERVER\s*\[\s*[\'"]HTTP_REFERER[\'"]\s*\]/i',                    'score' => 5,  'desc' => 'HTTP_REFERER check — potential bot/crawler cloaking'),
    array('pattern' => '/\$_SERVER\s*\[\s*[\'"]HTTP_USER_AGENT[\'"]\s*\]/i',                 'score' => 5,  'desc' => 'HTTP_USER_AGENT check — potential search engine cloaking'),
    array('pattern' => '/preg_match\s*\(.*(HTTP_USER_AGENT|HTTP_REFERER)/i',                  'score' => 5,  'desc' => 'Regex match on user agent or referrer'),
    array('pattern' => '/strpos\s*\(\s*\$_SERVER\s*\[\s*[\'"](HTTP_USER_AGENT|HTTP_REFERER)[\'"]\s*\]/i', 'score' => 5, 'desc' => 'String search on user agent or referrer'),
    array('pattern' => '/header\s*\(/i',                                                      'score' => 1,  'desc' => 'header() — sends raw HTTP header'),
    array('pattern' => '/setcookie\s*\(/i',                                                   'score' => 1,  'desc' => 'setcookie() — sets a cookie'),
    array('pattern' => '/setrawcookie\s*\(/i',                                                'score' => 1,  'desc' => 'setrawcookie() — sets a raw cookie'),

    // Output manipulation
    array('pattern' => '/echo\s+["\']<script/i',                                              'score' => 12, 'desc' => 'Echoed inline <script> tag — possible XSS/injection'),
    array('pattern' => '/print\s+["\']<script/i',                                             'score' => 12, 'desc' => 'Printed inline <script> tag — possible XSS/injection'),
    array('pattern' => '/printf\s*\(\s*["\']<script/i',                                       'score' => 12, 'desc' => 'printf() with <script> tag — possible XSS/injection'),
    array('pattern' => '/document\.write\s*\(/i',                                             'score' => 12, 'desc' => 'document.write() — JavaScript DOM injection'),
    array('pattern' => '/ob_start\s*\(/i',                                                    'score' => 1,  'desc' => 'ob_start() — starts output buffering'),
    array('pattern' => '/ob_get_clean\s*\(/i',                                                'score' => 1,  'desc' => 'ob_get_clean() — captures and clears output buffer'),
    array('pattern' => '/ob_end_clean\s*\(/i',                                                'score' => 1,  'desc' => 'ob_end_clean() — discards output buffer'),
    array('pattern' => '/ob_get_contents\s*\(/i',                                             'score' => 1,  'desc' => 'ob_get_contents() — reads output buffer'),

    // Network operations
    array('pattern' => '/curl_exec\s*\(/i',                                                   'score' => 2,  'desc' => 'curl_exec() — executes a cURL request'),
    array('pattern' => '/curl_multi_exec\s*\(/i',                                             'score' => 2,  'desc' => 'curl_multi_exec() — executes multiple cURL requests'),
    array('pattern' => '/fsockopen\s*\(/i',                                                   'score' => 5,  'desc' => 'fsockopen() — raw socket connection'),
    array('pattern' => '/pfsockopen\s*\(/i',                                                  'score' => 5,  'desc' => 'pfsockopen() — persistent raw socket connection'),
    array('pattern' => '/stream_socket_client\s*\(/i',                                        'score' => 5,  'desc' => 'stream_socket_client() — socket client'),
    array('pattern' => '/stream_socket_server\s*\(/i',                                        'score' => 12, 'desc' => 'stream_socket_server() — creates socket server (very unusual in web PHP)'),

    // Session handling
    array('pattern' => '/session_start\s*\(/i',                                               'score' => 1,  'desc' => 'session_start() — initiates session'),
    array('pattern' => '/session_regenerate_id\s*\(/i',                                       'score' => 1,  'desc' => 'session_regenerate_id() — regenerates session ID'),

    // Function introspection
    array('pattern' => '/ReflectionFunction\s*\(/i',                                          'score' => 5,  'desc' => 'ReflectionFunction — runtime function introspection'),
    array('pattern' => '/ReflectionMethod\s*\(/i',                                            'score' => 5,  'desc' => 'ReflectionMethod — runtime method introspection'),
    array('pattern' => '/ReflectionClass\s*\(/i',                                             'score' => 3,  'desc' => 'ReflectionClass — runtime class introspection'),

    // DB operations
    array('pattern' => '/mysql_query\s*\(/i',                                                 'score' => 2,  'desc' => 'mysql_query() — deprecated MySQL query'),
    array('pattern' => '/mysqli_query\s*\(/i',                                                'score' => 1,  'desc' => 'mysqli_query() — MySQL query'),
    array('pattern' => '/pg_query\s*\(/i',                                                    'score' => 1,  'desc' => 'pg_query() — PostgreSQL query'),
    array('pattern' => '/sqlite_query\s*\(/i',                                                'score' => 2,  'desc' => 'sqlite_query() — SQLite query'),

    // Shell tricks
    array('pattern' => '/`.*`/i',                                                             'score' => 20, 'desc' => 'Backtick shell execution'),
    array('pattern' => '/backdoor/i',                                                         'score' => 40, 'desc' => '"backdoor" — explicit backdoor indicator'),
    array('pattern' => '/shell/i',                                                            'score' => 5,  'desc' => '"shell" — references shell commands'),
    array('pattern' => '/cmd/i',                                                              'score' => 2,  'desc' => '"cmd" — references command execution'),

    // WP specific
    array('pattern' => '/add_action\s*\(.*base64_decode/i',                                   'score' => 35, 'desc' => 'WordPress hook with base64-encoded payload'),
    array('pattern' => '/add_filter\s*\(.*eval/i',                                            'score' => 35, 'desc' => 'WordPress filter with eval'),
    array('pattern' => '/wp_eval_request\s*\(/i',                                             'score' => 40, 'desc' => 'wp_eval_request() — known malicious plugin pattern'),
    array('pattern' => '/\$GLOBALS\s*\[\s*["\']wp_filter["\']\s*\]/i',                       'score' => 12, 'desc' => '$GLOBALS[wp_filter] — direct WordPress hook manipulation'),
    array('pattern' => '/functions\.php/i',                                                   'score' => 2,  'desc' => 'Reference to functions.php'),
    array('pattern' => '/wp-config\.php/i',                                                   'score' => 5,  'desc' => 'Reference to wp-config.php (possible config tampering)'),

    // Dynamic inclusion (too many false positives)
    // array('pattern' => '/include\s*\(/i',      'score' => 3, 'desc' => 'include()'),
    // array('pattern' => '/include_once\s*\(/i', 'score' => 3, 'desc' => 'include_once()'),
    // array('pattern' => '/require\s*\(/i',      'score' => 3, 'desc' => 'require()'),
    // array('pattern' => '/require_once\s*\(/i', 'score' => 3, 'desc' => 'require_once()'),

    // MIME confusion / polyglot
    array('pattern' => '/^\s*(GIF8|‰PNG|<\?xml|<svg)/i',                                     'score' => 35, 'desc' => 'Polyglot file header (MIME confusion / image-as-PHP attack)'),
);

// Counters for report
$totalFilesScanned  = 0;
$filesSkipped       = 0;
$riskCounts         = array('critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'clean' => 0);

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

// Map a numeric score to a risk label, ANSI color, and array key
function getRiskLevel($score) {
    if ($score >= SCORE_CRITICAL) return array('label' => 'CRITICAL', 'color' => "\033[35m", 'key' => 'critical'); // Magenta
    if ($score >= SCORE_HIGH)     return array('label' => 'HIGH',     'color' => "\033[31m", 'key' => 'high');     // Red
    if ($score >= SCORE_MEDIUM)   return array('label' => 'MEDIUM',   'color' => "\033[33m", 'key' => 'medium');   // Yellow
    if ($score >= SCORE_LOW)      return array('label' => 'LOW',      'color' => "\033[36m", 'key' => 'low');      // Cyan
    return                               array('label' => 'CLEAN',    'color' => "\033[32m", 'key' => 'clean');    // Green
}

// Scan file — accumulates scores for all matched patterns, returns total score.
// Returns -1 if the file cannot be read.
function scanFile($filePath) {
    global $suspiciousPatterns, $targetLog;
    $fileContent = @file_get_contents($filePath);

    if ($fileContent === false) {
        echo "\033[31mError: Unable to read file: $filePath\033[0m\n";
        logMessage("Error: Unable to read file: $filePath");
        return -1;
    }

    $totalScore = 0;
    $hits       = array();

    foreach ($suspiciousPatterns as $entry) {
        if (preg_match($entry['pattern'], $fileContent)) {
            $totalScore += $entry['score'];
            $hits[]      = $entry;
        }
    }

    if ($totalScore >= SCORE_LOW) {
        $risk  = getRiskLevel($totalScore);
        $color = $risk['color'];
        $label = $risk['label'];
        $reset = "\033[0m";

        echo "{$color}[{$label} — Score: {$totalScore}]{$reset} {$filePath}\n";
        foreach ($hits as $hit) {
            echo "  + {$hit['desc']} ({$hit['score']})\n";
        }

        logMessage("[{$label} — Score: {$totalScore}] {$filePath}");
        foreach ($hits as $hit) {
            logMessage("  + {$hit['desc']} (score: {$hit['score']}, pattern: {$hit['pattern']})");
        }
    }

    return $totalScore;
}

// Write logs
function logMessage($message) {
    global $targetLog;
    $logEntry = date('Y-m-d H:i:s') . ' - ' . $message . PHP_EOL;
    file_put_contents($targetLog, $logEntry, FILE_APPEND);
}

function scanDirectory($dir) {
    global $targetLog, $totalFilesScanned, $filesSkipped, $maxFileSize, $riskCounts;
    $hasHighRisk = false;
    $queue       = array($dir);

    while (!empty($queue)) {
        $currentDir = array_shift($queue);
        $files      = scandir($currentDir);

        foreach ($files as $file) {
            if ($file == '.' || $file == '..') {
                continue;
            }

            $filePath = $currentDir . DIRECTORY_SEPARATOR . $file;

            if (isExcluded($filePath)) {
                continue;
            }

            if (is_dir($filePath)) {
                $queue[] = $filePath;
            } else {
                if (pathinfo($filePath, PATHINFO_EXTENSION) === 'php') {
                    if ($maxFileSize > 0 && filesize($filePath) > $maxFileSize) {
                        $filesSkipped++;
                        echo "\033[33mFile skipped due to size: $filePath\033[0m\n";
                        logMessage("File skipped due to size: $filePath");
                        continue;
                    }
                    $totalFilesScanned++;
                    $score = scanFile($filePath);
                    if ($score < 0) {
                        continue; // unreadable
                    }
                    $risk = getRiskLevel($score);
                    $riskCounts[$risk['key']]++;
                    if ($score >= SCORE_MEDIUM) {
                        $hasHighRisk = true;
                    }
                }
            }
        }
    }

    if ($hasHighRisk) {
        logMessage("Suspicious files found in directory: $dir");
    } else {
        logMessage("Directory clean (no medium+ risk files): $dir");
    }

    return !$hasHighRisk;
}

try {
    checkPerms($targetDir);
    scanDirectory($targetDir);

    echo "\033[32mSuspicious file scan complete! See $targetLog for results.\033[0m";

    $flagged = $riskCounts['critical'] + $riskCounts['high'] + $riskCounts['medium'];

    echo "\n\n[Summary of Scan]\n\n";
    echo "Total files scanned:    $totalFilesScanned\n";
    echo "Files skipped (size):   $filesSkipped\n";
    echo "Flagged (medium+):      $flagged\n";
    echo "\nBy risk level:\n";
    echo "  \033[35mCritical : {$riskCounts['critical']}\033[0m\n";
    echo "  \033[31mHigh     : {$riskCounts['high']}\033[0m\n";
    echo "  \033[33mMedium   : {$riskCounts['medium']}\033[0m\n";
    echo "  \033[36mLow      : {$riskCounts['low']}\033[0m\n";
    echo "  \033[32mClean    : {$riskCounts['clean']}\033[0m\n";

} catch (Exception $e) {
    echo "\033[31m" . $e->getMessage() . "\033[0m\n";
}
?>
