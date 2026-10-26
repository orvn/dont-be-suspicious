<?php
/**
 * Don't be suspicious
 * Recursively scans a directory for potentially malicious files (esp. PHP)
 */


// Feature flags
// Heuristic score thresholds
define('SCORE_LOW',      8);
define('SCORE_MEDIUM',   20);
define('SCORE_HIGH',     35);
define('SCORE_CRITICAL', 60);

// Diminishing returns
// Low and weak hits are summed per tier, then squashed with cap * tanh(sum / cap)
// Slope is 1 at the origin so a few hits count in full, and a tier can never add more than its cap
define('LOW_SIGNAL_MAX_SCORE',  3);  // Low tier is 1..3
define('WEAK_SIGNAL_MAX_SCORE', 7);  // Weak tier is 4..7, anything higher counts in full
define('LOW_SIGNAL_CAP',        7);  // Under SCORE_LOW, so noise alone never shows up
define('WEAK_SIGNAL_CAP',       40); // Weak hits alone top out around HIGH, never CRITICAL

$minRiskScore  = SCORE_LOW;    // Minimum score for a file to appear in output. Override with --min-risk.
$flagFromScore = SCORE_MEDIUM; // Minimum score to count as "flagged" in the summary. Override with --flag-from.
$maxFileSize   = 1 * 1024 * 1024; // Maximum file size to scan in bytes. Override with --max.

// File types to scan
$phpExtensions   = array('php', 'phtml', 'pht', 'php3', 'php4', 'php5', 'php7', 'phar', 'inc'); // Override with --ext
$configFiles     = array('.htaccess', '.user.ini');
$imageExtensions = array('ico', 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'); // Only checked for hidden PHP

// WAF bootstraps that legitimately use auto_prepend_file, and a string the real file contains
$knownPrependFiles = array('wordfence-waf.php' => 'wordfence/waf/bootstrap.php');

// Config
$defaultDir = getcwd() ? getcwd() : '.';
$defaultLog = getcwd() . DIRECTORY_SEPARATOR . 'suspicious_' . date('Ymd') . '.log';

// Exit codes
define('EXIT_CLEAN',   0);
define('EXIT_FLAGGED', 1);
define('EXIT_ERROR',   2);

define('DECODED_MARK', "\x01"); // Starts a literal the decoded view unescaped or folded

// Raw --exclude args, resolved once the target is known
$excludeArgs  = array();
$excludedDirs = array();

// Risk label, score map for --min-risk and --flag-from flags
$riskLabelMap = array(
    'low'      => SCORE_LOW,
    'medium'   => SCORE_MEDIUM,
    'high'     => SCORE_HIGH,
    'critical' => SCORE_CRITICAL,
);

// CLI args: [target_directory] [log_file], flags in any position
$args       = isset($argv) ? array_slice($argv, 1) : array();
$positional = array();
$argCount   = count($args);

for ($i = 0; $i < $argCount; $i++) {
    if (strpos($args[$i], '--') !== 0) {
        $positional[] = $args[$i];
        continue;
    }

    $parts = explode('=', substr($args[$i], 2), 2);
    $flag  = $parts[0];

    if (!in_array($flag, array('exclude', 'ext', 'max', 'min-risk', 'flag-from'), true)) {
        warn("Unknown flag ignored: --$flag");
        continue;
    }

    if (isset($parts[1])) {
        $value = $parts[1];
    } elseif ($i + 1 < $argCount) {
        $value = $args[++$i];
    } else {
        warn("Missing value for --$flag");
        continue;
    }

    if ($flag === 'exclude') {
        foreach (explode(',', $value) as $path) {
            if (trim($path) !== '') {
                $excludeArgs[] = trim($path);
            }
        }
    } elseif ($flag === 'ext') {
        $phpExtensions = array();
        foreach (explode(',', strtolower($value)) as $ext) {
            if (trim($ext, " .") !== '') {
                $phpExtensions[] = trim($ext, " .");
            }
        }
    } elseif ($flag === 'max') {
        if (preg_match('/^\d+$/', $value)) {
            $maxFileSize = (int) $value;
        } else {
            warn("Invalid value for --max (expected bytes): $value");
        }
    } else {
        $label = strtolower($value);
        if (!isset($riskLabelMap[$label])) {
            warn("Invalid value for --$flag (expected " . implode(', ', array_keys($riskLabelMap)) . "): $value");
        } elseif ($flag === 'min-risk') {
            $minRiskScore = $riskLabelMap[$label];
        } else {
            $flagFromScore = $riskLabelMap[$label];
        }
    }
}

$targetDir = isset($positional[0]) ? $positional[0] : $defaultDir;
$targetLog = isset($positional[1]) ? $positional[1] : $defaultLog;

for ($i = 2; $i < count($positional); $i++) {
    warn("Extra argument ignored: {$positional[$i]}");
}

// Patterns and their corresponding sensitivity
//
// score: how much this pattern contributes to the file's suspicion score
//   1-3  : noise, extremely common in legitimate code
//   4-7  : eyebrow-raise, less common, slightly suspicious in isolation
//   12-15: concerning, uncommon in clean code, alarming when combined
//   20-25: strong indicator, rarely legitimate in web-facing PHP
//   35-40: near-certain malware, almost never seen in legitimate code
//
// scope: which view of the file to match, see getSourceViews()
//   code (default): code only, no comments, strings, inline HTML or method names
//   text          : comments stripped
//   decoded       : comments and inline HTML stripped, escapes decoded, chr(), "a"."b" and base64_decode("...") folded
//                   literals that were decoded or folded start with DECODED_MARK
//   raw           : as is
//
$suspiciousPatterns = array(

    // Obfuscation and encoding
    array('pattern' => '/(^|[^A-Za-z0-9_])base64_decode\s*\(/i',                             'score' => 2,  'desc' => 'base64_decode() — common obfuscation layer'),
    array('pattern' => '/(^|[^A-Za-z0-9_])str_rot13\s*\(/i',                                 'score' => 4,  'desc' => 'str_rot13() — ROT13 obfuscation'),
    array('pattern' => '/(^|[^A-Za-z0-9_])gzuncompress\s*\(/i',                              'score' => 4,  'desc' => 'gzuncompress() — decompression (chained obfuscation)'),
    array('pattern' => '/(^|[^A-Za-z0-9_])gzinflate\s*\(/i',                                 'score' => 4,  'desc' => 'gzinflate() — decompression (chained obfuscation)'),
    array('pattern' => '/(^|[^A-Za-z0-9_])strrev\s*\(/i',                                    'score' => 2,  'desc' => 'strrev() — string reversal'),
    // Literal first arg with an e modifier
    array('pattern' => '/(^|[^A-Za-z0-9_])preg_replace\s*\(\s*([\'"])(.)(?:\\\\.|(?!\2).)*?\3[a-z]*e[a-z]*\2/i', 'score' => 35, 'desc' => 'preg_replace() with /e modifier — eval-equivalent code execution', 'scope' => 'text'),
    array('pattern' => '/(^|[^A-Za-z0-9_])pack\s*\(/i',                                      'score' => 2,  'desc' => 'pack() — binary data packing'),
    array('pattern' => '/(^|[^A-Za-z0-9_])unpack\s*\(/i',                                    'score' => 2,  'desc' => 'unpack() — binary data unpacking'),
    array('pattern' => '/(^|[^A-Za-z0-9_])base_convert\s*\(/i',                              'score' => 7,  'desc' => 'base_convert() — used in obfuscation chains'),
    array('pattern' => '/(^|[^A-Za-z0-9_])mcrypt_encrypt\s*\(/i',                            'score' => 2,  'desc' => 'mcrypt_encrypt() — legacy encryption'),
    array('pattern' => '/(^|[^A-Za-z0-9_])mcrypt_decrypt\s*\(/i',                            'score' => 2,  'desc' => 'mcrypt_decrypt() — legacy decryption'),
    array('pattern' => '/(^|[^A-Za-z0-9_])openssl_encrypt\s*\(/i',                           'score' => 1,  'desc' => 'openssl_encrypt() — OpenSSL encryption'),
    array('pattern' => '/(^|[^A-Za-z0-9_])openssl_decrypt\s*\(/i',                           'score' => 1,  'desc' => 'openssl_decrypt() — OpenSSL decryption'),

    // Encoded strings, marked literals were hidden with escapes, chr() or concatenation
    array('pattern' => '/"\x01(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|create_function)"/i', 'score' => 35, 'desc' => 'Hidden name of a code or command execution function', 'scope' => 'decoded'),
    array('pattern' => '/"\x01(GLOBALS|_(GET|POST|REQUEST|COOKIE|SERVER))"/i',                 'score' => 15, 'desc' => 'Hidden superglobal name', 'scope' => 'decoded'),
    // Weak, the Freemius SDK writes 'base64' . '_decode' on purpose
    array('pattern' => '/"\x01(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|preg_replace|file_get_contents|file_put_contents|fwrite|fopen|unlink|move_uploaded_file|curl_exec|call_user_func(_array)?|(include|require)(_once)?)"/i', 'score' => 7, 'desc' => 'Hidden name of a decoding or file function', 'scope' => 'decoded'),
    array('pattern' => '/[\'"]\x01?(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)[\'"]\s*\(/i', 'score' => 35, 'desc' => 'Execution function called by its name as a string', 'scope' => 'decoded'),
    array('pattern' => '/(^|[^A-Za-z0-9_])(call_user_func(_array)?|array_map|array_filter|array_walk|array_reduce|usort|uasort|uksort|register_shutdown_function|ob_start|set_error_handler|iterator_apply|preg_replace_callback)\s*\((?:(?!\?>)[^;])*?[\'"]\x01?(assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|create_function)[\'"]/i', 'score' => 35, 'desc' => 'Execution function passed as a callback', 'scope' => 'decoded'),
    // Letters, digits and _ only, so regex classes like [\x00-\x20] and binary headers stay out
    array('pattern' => '/(?:\\\\(?:x(?:3[0-9]|[46][1-9a-f]|[57][0-9a]|5f)|0?[67][0-7]|1[0-7]{2})){5,}/i', 'score' => 12, 'desc' => 'Run of hex or octal escapes spelling a word', 'scope' => 'text'),
    array('pattern' => '/(\bchr\s*\(\s*(\d+|0x[0-9a-f]+)\s*\)\s*\.\s*){3,}/i',               'score' => 12, 'desc' => 'chr() chain — string built byte by byte'),
    array('pattern' => '/(?<![A-Za-z0-9+\/])(?<!base64,)[A-Za-z0-9+\/]{200,}={0,2}/',          'score' => 12, 'desc' => 'Long base64 or hex blob', 'scope' => 'raw'),
    // Legit code rarely passes 300, packed one-liners run into the thousands
    array('pattern' => '/\S{500,}/',                                                          'score' => 5,  'desc' => 'Long run of code with no whitespace — packed or minified'),
    array('pattern' => '/(^|[^A-Za-z0-9_])(eval|assert)\s*\((\s*@?\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin|pack|urldecode|rawurldecode|convert_uudecode)\s*\()+/i', 'score' => 35, 'desc' => 'eval() of a decoded or decompressed string'),

    // Code execution
    array('pattern' => '/(^|[^A-Za-z0-9_])eval\s*\(/i',                                      'score' => 20, 'desc' => 'eval() — arbitrary code execution'),
    array('pattern' => '/(^|[^A-Za-z0-9_])shell_exec\s*\(/i',                                'score' => 25, 'desc' => 'shell_exec() — shell command execution'),
    array('pattern' => '/(^|[^A-Za-z0-9_])system\s*\(/i',                                    'score' => 15, 'desc' => 'system() — system command execution'),
    array('pattern' => '/(^|[^A-Za-z0-9_])exec\s*\(/i',                                      'score' => 15, 'desc' => 'exec() — command execution'),
    array('pattern' => '/(^|[^A-Za-z0-9_])passthru\s*\(/i',                                  'score' => 25, 'desc' => 'passthru() — raw command execution'),
    array('pattern' => '/(^|[^A-Za-z0-9_])popen\s*\(/i',                                     'score' => 15, 'desc' => 'popen() — opens process pipe'),
    array('pattern' => '/(^|[^A-Za-z0-9_])proc_open\s*\(/i',                                 'score' => 15, 'desc' => 'proc_open() — opens a process'),
    array('pattern' => '/(^|[^A-Za-z0-9_])assert\s*\(/i',                                    'score' => 12, 'desc' => 'assert() — can execute PHP strings'),
    array('pattern' => '/(^|[^A-Za-z0-9_])call_user_func\s*\(/i',                            'score' => 5,  'desc' => 'call_user_func() — dynamic function dispatch'),
    array('pattern' => '/(^|[^A-Za-z0-9_])call_user_func_array\s*\(/i',                      'score' => 5,  'desc' => 'call_user_func_array() — dynamic function dispatch'),
    array('pattern' => '/(^|[^A-Za-z0-9_])create_function\s*\(/i',                           'score' => 20, 'desc' => 'create_function() — eval-equivalent, deprecated'),
    array('pattern' => '/(^|[^A-Za-z0-9_])pcntl_exec\s*\(/i',                                'score' => 25, 'desc' => 'pcntl_exec() — replaces current process image'),
    // Superglobal as the first argument, optionally wrapped in calls like base64_decode(
    array('pattern' => '/(^|[^A-Za-z0-9_])(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|create_function|call_user_func|call_user_func_array)\s*\(\s*(@?\s*[A-Za-z_]\w*\s*\(\s*)*@?\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES|ENV)/i', 'score' => 35, 'desc' => 'User input passed straight into code or command execution'),
    array('pattern' => '/(^|[^A-Za-z0-9_])(include|require)(_once)?\s*\(?\s*(@?\s*[A-Za-z_]\w*\s*\(\s*)*@?\s*\$_(GET|POST|REQUEST|COOKIE|FILES)/i', 'score' => 25, 'desc' => 'File included from user input — remote/local file inclusion'),

    // Include of a non-PHP file in the same statement, svg/css/js left out since themes inline those
    array('pattern' => '/(^|[^A-Za-z0-9_])(include|require)(_once)?\b(?:(?!\?>)[^;])*?[\'"][^\'"]*\.(ico|png|jpe?g|gif|bmp|webp)[\'"]/i', 'score' => 35, 'desc' => 'Include of an image or .ico file — hidden PHP payload', 'scope' => 'decoded'),
    array('pattern' => '/(^|[^A-Za-z0-9_])(include|require)(_once)?\b(?:(?!\?>)[^;])*?[\'"][^\'"]*\.(txt|log|dat|tmp|bak|zip|gz)[\'"]/i', 'score' => 25, 'desc' => 'Include of a data or backup file — possible hidden PHP payload', 'scope' => 'decoded'),

    // File operations
    array('pattern' => '/(^|[^A-Za-z0-9_])fopen\s*\(/i',                                     'score' => 1,  'desc' => 'fopen() — opens a file'),
    array('pattern' => '/(^|[^A-Za-z0-9_])fwrite\s*\(/i',                                    'score' => 2,  'desc' => 'fwrite() — writes to file'),
    array('pattern' => '/(^|[^A-Za-z0-9_])fread\s*\(/i',                                     'score' => 1,  'desc' => 'fread() — reads from file'),
    array('pattern' => '/(^|[^A-Za-z0-9_])file_put_contents\s*\(/i',                         'score' => 2,  'desc' => 'file_put_contents() — writes to file'),
    array('pattern' => '/(^|[^A-Za-z0-9_])file_get_contents\s*\(\s*(?!("|\')https?:\/\/)/i', 'score' => 1,  'desc' => 'file_get_contents() — reads a file', 'scope' => 'text'),
    array('pattern' => '/(^|[^A-Za-z0-9_])unlink\s*\(/i',                                    'score' => 3,  'desc' => 'unlink() — deletes a file'),
    array('pattern' => '/(^|[^A-Za-z0-9_])rename\s*\(/i',                                    'score' => 2,  'desc' => 'rename() — renames a file'),
    array('pattern' => '/(^|[^A-Za-z0-9_])chmod\s*\(/i',                                     'score' => 2,  'desc' => 'chmod() — changes file permissions'),
    array('pattern' => '/(^|[^A-Za-z0-9_])move_uploaded_file\s*\(/i',                        'score' => 3,  'desc' => 'move_uploaded_file() — stores an upload'),
    // Destination argument holds user input, $_FILES names left out since every uploader uses those
    array('pattern' => '/(^|[^A-Za-z0-9_])move_uploaded_file\s*\((?:[^;()]|\([^()]*\))*?,(?:[^;()]|\([^()]*\))*?\$_(GET|POST|REQUEST|COOKIE)/i', 'score' => 20, 'desc' => 'Upload moved to a user-chosen path — arbitrary file write'),
    array('pattern' => '/(^|[^A-Za-z0-9_])touch\s*\((?:[^;,()]|\([^()]*\))*,/i',             'score' => 3,  'desc' => 'touch() with a time — sets a file timestamp'),
    array('pattern' => '/(^|[^A-Za-z0-9_])touch\s*\([^;]*,\s*@?\s*filemtime\s*\(/i',          'score' => 20, 'desc' => 'touch() with the mtime of another file — hides a modified file'),
    array('pattern' => '/(^|[^A-Za-z0-9_])file_get_contents\s*\(\s*("|\')https?:\/\//i',    'score' => 20, 'desc' => 'file_get_contents() with remote URL — remote file inclusion', 'scope' => 'text'),

    // Dangerous or evasive functions
    array('pattern' => '/(^|[^A-Za-z0-9_])phpinfo\s*\(/i',                                   'score' => 5,  'desc' => 'phpinfo() — configuration disclosure'),
    array('pattern' => '/(^|[^A-Za-z0-9_])die\s*\(/i',                                       'score' => 1,  'desc' => 'die() — script termination'),
    array('pattern' => '/(^|[^A-Za-z0-9_])exit\s*\(/i',                                      'score' => 1,  'desc' => 'exit() — script termination'),
    array('pattern' => '/(^|[^A-Za-z0-9_])register_shutdown_function\s*\(/i',                'score' => 5,  'desc' => 'register_shutdown_function() — registers persistent callback'),
    array('pattern' => '/(^|[^A-Za-z0-9_])ini_set\s*\(/i',                                   'score' => 2,  'desc' => 'ini_set() — modifies PHP runtime configuration'),
    array('pattern' => '/(^|[^A-Za-z0-9_])ini_get\s*\(/i',                                   'score' => 1,  'desc' => 'ini_get() — reads PHP runtime configuration'),
    array('pattern' => '/(^|[^A-Za-z0-9_])error_reporting\s*\(\s*0\s*\)/i',                  'score' => 2,  'desc' => 'error_reporting(0) — hides errors'),
    // All three in one file, each alone is common in cron and import code, \K reports the first one
    array('pattern' => '/^(?=[\s\S]*?error_reporting\s*\(\s*0\s*\))(?=[\s\S]*?set_time_limit\s*\(\s*0\s*\))(?=[\s\S]*?ignore_user_abort\s*\()[\s\S]*?\K(?:error_reporting\s*\(\s*0|set_time_limit\s*\(\s*0|ignore_user_abort\s*\()/i', 'score' => 15, 'desc' => 'error_reporting(0) + set_time_limit(0) + ignore_user_abort() — shell or mailer setup'),
    array('pattern' => '/(^|[^A-Za-z0-9_])extract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',     'score' => 15, 'desc' => 'extract() of user input — overwrites variables'),
    // Single argument, so the parsed keys become variables
    array('pattern' => '/(^|[^A-Za-z0-9_])parse_str\s*\((?:[^;,()]|\([^()]*\))*\)/i',        'score' => 12, 'desc' => 'parse_str() without a result array — writes variables from a string'),
    array('pattern' => '/\$\$/i',                                                             'score' => 7,  'desc' => 'Variable variables ($$var) — obfuscation / dynamic dispatch'),
    array('pattern' => '/\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES|ENV)(\s*\[[^\]]*\])+\s*\(/i', 'score' => 35, 'desc' => '$_POST[...](...) — function name taken from user input'),
    array('pattern' => '/\$[A-Za-z_]\w*\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)/i',  'score' => 20, 'desc' => '$fn($_POST...) — variable function called with user input'),
    array('pattern' => '/\$GLOBALS(\s*\[[^\]]*\])+\s*\(/i',                                  'score' => 12, 'desc' => '$GLOBALS[...](...) — function called from a global, common in obfuscated code'),

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
    array('pattern' => '/\$_SERVER\s*\[\s*[\'"]HTTP_REFERER[\'"]\s*\]/i',                    'score' => 5,  'desc' => 'HTTP_REFERER check — potential bot/crawler cloaking', 'scope' => 'text'),
    array('pattern' => '/\$_SERVER\s*\[\s*[\'"]HTTP_USER_AGENT[\'"]\s*\]/i',                 'score' => 5,  'desc' => 'HTTP_USER_AGENT check — potential search engine cloaking', 'scope' => 'text'),
    array('pattern' => '/preg_match\s*\((?:(?!\?>)[^;])*?(HTTP_USER_AGENT|HTTP_REFERER)/i',    'score' => 5,  'desc' => 'Regex match on user agent or referrer', 'scope' => 'text'),
    array('pattern' => '/strpos\s*\(\s*\$_SERVER\s*\[\s*[\'"](HTTP_USER_AGENT|HTTP_REFERER)[\'"]\s*\]/i', 'score' => 5, 'desc' => 'String search on user agent or referrer', 'scope' => 'text'),
    array('pattern' => '/(^|[^A-Za-z0-9_])header\s*\(/i',                                    'score' => 1,  'desc' => 'header() — sends raw HTTP header'),
    array('pattern' => '/(^|[^A-Za-z0-9_])setcookie\s*\(/i',                                 'score' => 1,  'desc' => 'setcookie() — sets a cookie'),
    array('pattern' => '/(^|[^A-Za-z0-9_])setrawcookie\s*\(/i',                              'score' => 1,  'desc' => 'setrawcookie() — sets a raw cookie'),

    // Output manipulation
    array('pattern' => '/echo\s+["\']<script/i',                                              'score' => 12, 'desc' => 'Echoed inline <script> tag — possible XSS/injection', 'scope' => 'text'),
    array('pattern' => '/print\s+["\']<script/i',                                             'score' => 12, 'desc' => 'Printed inline <script> tag — possible XSS/injection', 'scope' => 'text'),
    array('pattern' => '/printf\s*\(\s*["\']<script/i',                                       'score' => 12, 'desc' => 'printf() with <script> tag — possible XSS/injection', 'scope' => 'text'),
    array('pattern' => '/(^|[^A-Za-z0-9_])document\.write\s*\(/i',                           'score' => 12, 'desc' => 'document.write() — JavaScript DOM injection', 'scope' => 'text'),
    array('pattern' => '/(^|[^A-Za-z0-9_])ob_start\s*\(/i',                                  'score' => 1,  'desc' => 'ob_start() — starts output buffering'),
    array('pattern' => '/(^|[^A-Za-z0-9_])ob_get_clean\s*\(/i',                              'score' => 1,  'desc' => 'ob_get_clean() — captures and clears output buffer'),
    array('pattern' => '/(^|[^A-Za-z0-9_])ob_end_clean\s*\(/i',                              'score' => 1,  'desc' => 'ob_end_clean() — discards output buffer'),
    array('pattern' => '/(^|[^A-Za-z0-9_])ob_get_contents\s*\(/i',                           'score' => 1,  'desc' => 'ob_get_contents() — reads output buffer'),

    // Network operations
    array('pattern' => '/(^|[^A-Za-z0-9_])curl_exec\s*\(/i',                                 'score' => 2,  'desc' => 'curl_exec() — executes a cURL request'),
    array('pattern' => '/(^|[^A-Za-z0-9_])curl_multi_exec\s*\(/i',                           'score' => 2,  'desc' => 'curl_multi_exec() — executes multiple cURL requests'),
    array('pattern' => '/(^|[^A-Za-z0-9_])fsockopen\s*\(/i',                                 'score' => 5,  'desc' => 'fsockopen() — raw socket connection'),
    array('pattern' => '/(^|[^A-Za-z0-9_])pfsockopen\s*\(/i',                                'score' => 5,  'desc' => 'pfsockopen() — persistent raw socket connection'),
    array('pattern' => '/(^|[^A-Za-z0-9_])stream_socket_client\s*\(/i',                      'score' => 5,  'desc' => 'stream_socket_client() — socket client'),
    array('pattern' => '/(^|[^A-Za-z0-9_])stream_socket_server\s*\(/i',                      'score' => 12, 'desc' => 'stream_socket_server() — creates socket server (very unusual in web PHP)'),
    array('pattern' => '/(^|[^A-Za-z0-9_])mail\s*\(/i',                                      'score' => 3,  'desc' => 'mail() — sends email'),
    array('pattern' => '/(^|[^A-Za-z0-9_])mail\s*\(\s*@?\s*(?:[A-Za-z_]\w*\s*\(\s*)*\$_(GET|POST|REQUEST|COOKIE)/i', 'score' => 12, 'desc' => 'mail() to a user-supplied address — spam relay'),

    // Session handling
    array('pattern' => '/(^|[^A-Za-z0-9_])session_start\s*\(/i',                             'score' => 1,  'desc' => 'session_start() — initiates session'),
    array('pattern' => '/(^|[^A-Za-z0-9_])session_regenerate_id\s*\(/i',                     'score' => 1,  'desc' => 'session_regenerate_id() — regenerates session ID'),

    // Function introspection
    array('pattern' => '/(^|[^A-Za-z0-9_])ReflectionFunction\s*\(/i',                        'score' => 5,  'desc' => 'ReflectionFunction — runtime function introspection'),
    array('pattern' => '/(^|[^A-Za-z0-9_])ReflectionMethod\s*\(/i',                          'score' => 5,  'desc' => 'ReflectionMethod — runtime method introspection'),
    array('pattern' => '/(^|[^A-Za-z0-9_])ReflectionClass\s*\(/i',                           'score' => 3,  'desc' => 'ReflectionClass — runtime class introspection'),

    // DB operations
    array('pattern' => '/(^|[^A-Za-z0-9_])mysql_query\s*\(/i',                               'score' => 2,  'desc' => 'mysql_query() — deprecated MySQL query'),
    array('pattern' => '/(^|[^A-Za-z0-9_])mysqli_query\s*\(/i',                              'score' => 1,  'desc' => 'mysqli_query() — MySQL query'),
    array('pattern' => '/(^|[^A-Za-z0-9_])pg_query\s*\(/i',                                  'score' => 1,  'desc' => 'pg_query() — PostgreSQL query'),
    array('pattern' => '/(^|[^A-Za-z0-9_])sqlite_query\s*\(/i',                              'score' => 2,  'desc' => 'sqlite_query() — SQLite query'),

    // Shell tricks
    array('pattern' => '/`.*`/i',                                                             'score' => 20, 'desc' => 'Backtick shell execution'),
    // Identifiers only, a security plugin's "Backdoor found" message doesn't count
    array('pattern' => '/backdoor/i',                                                         'score' => 40, 'desc' => '"backdoor" — explicit backdoor indicator'),
    array('pattern' => '/shell/i',                                                            'score' => 0,  'desc' => '"shell" — references shell commands'),
    array('pattern' => '/cmd/i',                                                              'score' => 0,  'desc' => '"cmd" — references command execution'),

    // WP specific
    // Spans lines but stays inside the statement, stops at a semicolon or closing tag
    array('pattern' => '/(^|[^A-Za-z0-9_])add_action\s*\((?:(?!\?>)[^;])*?[^A-Za-z0-9_]base64_decode/i', 'score' => 35, 'desc' => 'WordPress hook with base64-encoded payload', 'scope' => 'text'),
    array('pattern' => '/(^|[^A-Za-z0-9_])add_filter\s*\((?:(?!\?>)[^;])*?[^A-Za-z0-9_]eval(?![A-Za-z0-9_])/i', 'score' => 35, 'desc' => 'WordPress filter with eval', 'scope' => 'text'),
    array('pattern' => '/(^|[^A-Za-z0-9_])wp_eval_request\s*\(/i',                           'score' => 40, 'desc' => 'wp_eval_request() — known malicious plugin pattern'),
    array('pattern' => '/\$GLOBALS\s*\[\s*["\']wp_filter["\']\s*\]/i',                       'score' => 12, 'desc' => '$GLOBALS[wp_filter] — direct WordPress hook manipulation', 'scope' => 'text'),
    array('pattern' => '/functions\.php/i',                                                   'score' => 0,  'desc' => 'Reference to functions.php', 'scope' => 'text'),
    array('pattern' => '/wp-config\.php/i',                                                   'score' => 0,  'desc' => 'Reference to wp-config.php (possible config tampering)', 'scope' => 'text'),

    // Dynamic inclusion (too many false positives)
    // array('pattern' => '/include\s*\(/i',      'score' => 3, 'desc' => 'include()'),
    // array('pattern' => '/include_once\s*\(/i', 'score' => 3, 'desc' => 'include_once()'),
    // array('pattern' => '/require\s*\(/i',      'score' => 3, 'desc' => 'require()'),
    // array('pattern' => '/require_once\s*\(/i', 'score' => 3, 'desc' => 'require_once()'),

    // MIME confusion / polyglot
    array('pattern' => '/^\s*(GIF8|\x89PNG|<\?xml|<svg)/i',                                  'score' => 35, 'desc' => 'Polyglot file header (MIME confusion / image-as-PHP attack)', 'scope' => 'raw'),
);

// Server config files (.htaccess, .user.ini)
$configPatterns = array(
    array('pattern' => '/auto_(prepend|append)_file/i',                                                    'score' => 20, 'desc' => 'auto_prepend_file / auto_append_file — runs a file on every request', 'scope' => 'raw', 'id' => 'auto_prepend'),
    array('pattern' => '/(AddHandler|AddType)\s+\S*(php|x-httpd)\S*\s+.*\.(jpe?g|png|gif|ico|bmp|webp|txt)\b/i', 'score' => 35, 'desc' => 'Image or text extension run as PHP', 'scope' => 'raw'),
    // Any line in the block before </Files, not just the first
    array('pattern' => '/<Files(Match)?\s[^>]*(?<![a-z])(jpe?g|png|gif|ico|bmp|webp)(?![a-z])[^>]*>(?:(?!<\/Files)[\s\S])*?(SetHandler|ForceType)\s+\S*php/i', 'score' => 35, 'desc' => 'Image files set to run as PHP', 'scope' => 'raw'),
    // Negated conditions, quoted or not, are hotlink whitelists, not cloaking
    array('pattern' => '/RewriteCond\s+%\{HTTP_REFERER\}\s+(?!"?!)[^\n]*(?<![a-z])(google|bing|yahoo|yandex|baidu)(?![a-z])/i', 'score' => 25, 'desc' => 'Rewrite on search engine referrer — SEO redirect cloaking', 'scope' => 'raw'),
    array('pattern' => '/RewriteCond\s+%\{HTTP_USER_AGENT\}\s+(?!"?!)[^\n]*(?<![a-z])(google|bing)(bot)?(?![a-z])/i', 'score' => 12, 'desc' => 'Rewrite on search engine user agent — possible cloaking', 'scope' => 'raw'),
);

// Counters for report
$totalFilesScanned  = 0;
$filesSkipped       = 0;
$filesUnreadable    = 0;
$dirsUnreadable     = 0;
$riskCounts         = array('critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'clean' => 0);

function warn($message) {
    fwrite(STDERR, "\033[33mWarning: $message\033[0m\n");
}

// php, config, image (hidden PHP only) or null to skip
function getFileKind($fileName) {
    global $phpExtensions, $configFiles, $imageExtensions;
    /** @var string[] $phpExtensions */
    /** @var string[] $configFiles */
    /** @var string[] $imageExtensions */
    if (in_array($fileName, $configFiles, true)) {
        return 'config';
    }
    $ext = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
    if (in_array($ext, $phpExtensions, true)) {
        return 'php';
    }
    if (in_array($ext, $imageExtensions, true)) {
        return 'image';
    }
    return null;
}

// Resolve excludes, as given or relative to the target
function resolveExcludes($excludeArgs, $targetDir) {
    $resolved = array();
    foreach ($excludeArgs as $path) {
        $real = realpath($path);
        if ($real === false) {
            $real = realpath($targetDir . DIRECTORY_SEPARATOR . $path);
        }
        if ($real === false) {
            warn("Exclude path not found, ignored: $path");
            continue;
        }
        $resolved[] = $real;
    }
    return $resolved;
}

// Check if path is excluded or inside an excluded dir
function isExcluded($path) {
    global $excludedDirs;
    /** @var string[] $excludedDirs */
    if (empty($excludedDirs)) {
        return false;
    }
    $real = realpath($path);
    if ($real === false) {
        return false;
    }
    foreach ($excludedDirs as $excludedDir) {
        if ($real === $excludedDir || strpos($real, rtrim($excludedDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) === 0) {
            return true;
        }
    }
    return false;
}

/**
 * @return array{label: string, color: string, key: string}
 */
function getRiskLevel($score) {
    if ($score >= SCORE_CRITICAL) return array('label' => 'CRITICAL', 'color' => "\033[35m", 'key' => 'critical'); // Magenta
    if ($score >= SCORE_HIGH)     return array('label' => 'HIGH',     'color' => "\033[31m", 'key' => 'high');     // Red
    if ($score >= SCORE_MEDIUM)   return array('label' => 'MEDIUM',   'color' => "\033[33m", 'key' => 'medium');   // Yellow
    if ($score >= SCORE_LOW)      return array('label' => 'LOW',      'color' => "\033[36m", 'key' => 'low');      // Cyan
    return                               array('label' => 'CLEAN',    'color' => "\033[32m", 'key' => 'clean');    // Green
}

// Views for pattern scopes, line breaks preserved
/**
 * @return array{raw: string, text: string, decoded: string, code: string}
 */
function getSourceViews($content) {
    if (!function_exists('token_get_all')) {
        return array('raw' => $content, 'text' => $content, 'decoded' => $content, 'code' => $content);
    }

    // Treat bare <? as PHP even when short_open_tag is off
    $source = ini_get('short_open_tag') ? $content : preg_replace('/<\?(?!php|=|xml)/i', '<?php ', $content);

    // Names after these are methods or declarations, not built-in calls
    $nameOperators = array(T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION);
    if (defined('T_NULLSAFE_OBJECT_OPERATOR')) {
        $nameOperators[] = constant('T_NULLSAFE_OBJECT_OPERATOR');
    }

    $text    = '';
    $decoded = '';
    $code    = '';
    $prev    = null; // Last significant token

    foreach (token_get_all($source) as $token) {
        if (is_string($token)) {
            $text    .= $token;
            $decoded .= $token;
            $code    .= $token;
            if (!($token === '&' && $prev === T_FUNCTION)) {
                $prev = $token;
            }
            continue;
        }

        list($id, $value) = $token;
        $lines = str_repeat("\n", substr_count($value, "\n"));

        if ($id === T_COMMENT || $id === T_DOC_COMMENT) {
            // Space keeps eval/**/( matching and return/**/eval apart
            $blank = $lines === '' ? ' ' : $lines;
            $text    .= $blank;
            $decoded .= $blank;
            $code    .= $blank;
            continue;
        }

        $text .= $value;

        if ($id === T_CONSTANT_ENCAPSED_STRING && $value[0] === '"') {
            $inner    = substr($value, 1, -1);
            $mark     = preg_match('/\\\\(x[0-9a-f]|[0-7])/i', $inner) ? DECODED_MARK : '';
            $decoded .= '"' . $mark . decodeString($inner, $lines) . '"';
        } elseif ($id === T_ENCAPSED_AND_WHITESPACE) {
            $decoded .= decodeString($value, $lines);
        } elseif ($id === T_INLINE_HTML) {
            $decoded .= $lines;
        } else {
            $decoded .= $value;
        }

        if ($id === T_CONSTANT_ENCAPSED_STRING) {
            $code .= $value[0] . $value[0] . $lines;
        } elseif ($id === T_ENCAPSED_AND_WHITESPACE || $id === T_INLINE_HTML) {
            $code .= $lines;
        } elseif (!($id === T_STRING && in_array($prev, $nameOperators, true))) {
            $code .= $value;
        }

        if ($id !== T_WHITESPACE) {
            $prev = $id;
        }
    }

    return array('raw' => $content, 'text' => $text, 'decoded' => foldDecoded($decoded), 'code' => $code);
}

// Unescape \x41, \101, \n etc., with line breaks moved to the end so line numbers hold
function decodeString($value, $lines) {
    return str_replace(array("\r", "\n"), ' ', stripcslashes($value)) . $lines;
}

// Turn chr(N), "a" . "b" and decoders of a literal into one marked literal, so hidden names read whole
function foldDecoded($view) {
    $view = preg_replace_callback('/\bchr\s*\(\s*(\d+|0x[0-9a-f]+)\s*\)/i', 'foldChr', $view);
    $view = foldConcats($view);
    $view = preg_replace_callback('/\b(base64_decode|str_rot13|strrev)\s*\(\s*(["\'])([^"\']*)\2\s*\)/i', 'foldDecoder', $view);
    return foldConcats($view);
}

function foldConcats($view) {
    do {
        $view = preg_replace_callback('/(["\'])([^"\']*)\1\s*\.\s*(["\'])([^"\']*)\3/', 'foldConcat', $view, -1, $count);
    } while ($count);
    return $view;
}

function foldChr($m) {
    $n = (int) (stripos($m[1], '0x') === 0 ? hexdec($m[1]) : $m[1]);
    return '"' . DECODED_MARK . strtr(chr($n), "\"'\r\n", '    ') . '"';
}

function foldConcat($m) {
    $inner = str_replace(array("\r", "\n", DECODED_MARK), '', $m[2] . $m[4]);
    return '"' . DECODED_MARK . $inner . '"' . str_repeat("\n", substr_count($m[0], "\n"));
}

// Left as is unless the result is printable text, so code payloads stay with the blob rules
function foldDecoder($m) {
    $fn    = strtolower($m[1]);
    $value = str_replace(DECODED_MARK, '', $m[3]);
    $value = $fn === 'base64_decode' ? base64_decode($value, true) : ($fn === 'strrev' ? strrev($value) : str_rot13($value));
    if ($value === false || preg_match('/[^\x20-\x7e]/', $value)) {
        return $m[0];
    }
    return '"' . DECODED_MARK . strtr($value, "\"'", '  ') . '"' . str_repeat("\n", substr_count($m[0], "\n"));
}

function getPatternHits($fileContent, $patterns) {
    $views = getSourceViews($fileContent);
    $hits  = array();

    foreach ($patterns as $entry) {
        $scope = isset($entry['scope']) ? $entry['scope'] : 'code';
        if (preg_match($entry['pattern'], $views[$scope], $match, PREG_OFFSET_CAPTURE)) {
            // Skip a line break eaten by the leading boundary group
            $offset        = $match[0][1] + strspn($match[0][0], "\r\n");
            $entry['line'] = substr_count(substr($views[$scope], 0, $offset), "\n") + 1;
            $hits[]        = $entry;
        }
    }

    return $hits;
}

// Zero the auto_prepend_file hit when every prepended file is a real WAF bootstrap, not just one named like it
function clearVerifiedPrependHits($hits, $content) {
    global $knownPrependFiles;
    /** @var array<string, string> $knownPrependFiles */
    preg_match_all('/auto_(prepend|append)_file\s*=?\s*[\'"]?([^\'"\s]+)/i', $content, $match);
    $names = array();

    foreach ($match[2] as $path) {
        if (strtolower($path) === 'none') {
            continue;
        }
        $name = basename($path);
        // Only read regular, small files, so a planted FIFO or device can't stall the scan
        if (!isset($knownPrependFiles[$name]) || !is_file($path) || filesize($path) > 65536) {
            return $hits;
        }
        if (strpos((string) @file_get_contents($path), $knownPrependFiles[$name]) === false) {
            return $hits;
        }
        $names[$name] = true;
    }

    foreach ($hits as $i => $hit) {
        if (isset($hit['id']) && $hit['id'] === 'auto_prepend') {
            $hits[$i]['score'] = 0;
            $hits[$i]['desc']  = empty($names)
                ? 'auto_prepend_file — set to none'
                : 'auto_prepend_file — verified WAF bootstrap (' . implode(', ', array_keys($names)) . ')';
        }
    }

    return $hits;
}

// Trimmed source line, control chars masked so a file can't inject terminal escapes
function getSnippet($lines, $lineNumber) {
    $line = isset($lines[$lineNumber - 1]) ? trim($lines[$lineNumber - 1]) : '';
    $line = preg_replace('/[\x00-\x08\x0B-\x1F\x7F]/', '?', $line);
    return strlen($line) > 100 ? substr($line, 0, 100) . '...' : $line;
}

function getCurvedScore($score, $cap) {
    if ($score <= 0) {
        return 0;
    }

    return $cap * tanh($score / $cap);
}

/**
 * @return array{low: int, weak: int, full: int, lowCurved: float, weakCurved: float, total: int}
 */
function getScoreBreakdown($hits) {
    $score = array('low' => 0, 'weak' => 0, 'full' => 0);

    foreach ($hits as $hit) {
        if ($hit['score'] >= 1 && $hit['score'] <= LOW_SIGNAL_MAX_SCORE) {
            $score['low'] += $hit['score'];
        } elseif ($hit['score'] > LOW_SIGNAL_MAX_SCORE && $hit['score'] <= WEAK_SIGNAL_MAX_SCORE) {
            $score['weak'] += $hit['score'];
        } else {
            $score['full'] += $hit['score'];
        }
    }

    $score['lowCurved']  = getCurvedScore($score['low'], LOW_SIGNAL_CAP);
    $score['weakCurved'] = getCurvedScore($score['weak'], WEAK_SIGNAL_CAP);
    $score['total']      = (int) round($score['full'] + $score['lowCurved'] + $score['weakCurved']);

    return $score;
}

// "full 20 + weak 25→22.2 + low 17→6.9", omitting empty tiers
function formatScoreBreakdown($score) {
    $parts = array();
    if ($score['full'] > 0) {
        $parts[] = "full {$score['full']}";
    }
    if ($score['weak'] > 0) {
        $parts[] = sprintf('weak %d→%.1f', $score['weak'], $score['weakCurved']);
    }
    if ($score['low'] > 0) {
        $parts[] = sprintf('low %d→%.1f', $score['low'], $score['lowCurved']);
    }
    return implode(' + ', $parts);
}

// Scan file and return its risk score
// Returns -1 if the file cannot be read
function scanFile($filePath, $kind) {
    global $targetLog, $minRiskScore, $suspiciousPatterns, $configPatterns;
    /** @var string $targetLog */
    /** @var int $minRiskScore */
    $fileContent = @file_get_contents($filePath);

    if ($fileContent === false) {
        echo "\033[31mError: Unable to read file: $filePath\033[0m\n";
        logMessage("Error: Unable to read file: $filePath");
        return -1;
    }

    if ($kind === 'config') {
        $hits = clearVerifiedPrependHits(getPatternHits($fileContent, $configPatterns), $fileContent);
    } elseif ($kind === 'image') {
        $start = stripos($fileContent, '<?php');
        if ($start === false) {
            return 0;
        }
        // Blank the image bytes before the payload, keeping line numbers
        $prefixLines = substr_count(substr($fileContent, 0, $start), "\n");
        $hits = getPatternHits(str_repeat("\n", $prefixLines) . substr($fileContent, $start), $suspiciousPatterns);
        array_unshift($hits, array(
            'pattern' => '<?php',
            'score'   => 35,
            'desc'    => 'PHP code inside a .' . strtolower(pathinfo($filePath, PATHINFO_EXTENSION)) . ' file',
            'line'    => $prefixLines + 1,
        ));
    } else {
        $hits = getPatternHits($fileContent, $suspiciousPatterns);
    }
    $score      = getScoreBreakdown($hits);
    $totalScore = $score['total'];
    $isCurved   = $score['low'] + $score['weak'] > 0;

    if ($totalScore >= $minRiskScore) {
        $risk  = getRiskLevel($totalScore);
        $color = $risk['color'];
        $label = $risk['label'];
        $reset = "\033[0m";

        $lines = explode("\n", $fileContent);

        echo "{$color}[{$label} — Score: {$totalScore}]{$reset} {$filePath}\n";
        foreach ($hits as $hit) {
            if ($hit['score'] > 0) {
                echo "  + {$hit['desc']} ({$hit['score']}) line {$hit['line']}\n";
                echo "\033[2m      " . getSnippet($lines, $hit['line']) . "{$reset}\n";
            }
        }
        if ($isCurved) {
            echo "  = " . formatScoreBreakdown($score) . "\n";
        }

        logMessage("[{$label} — Score: {$totalScore}] {$filePath}");
        foreach ($hits as $hit) {
            logMessage("  + {$hit['desc']} (score: {$hit['score']}, line: {$hit['line']}, pattern: {$hit['pattern']})");
            logMessage("      " . getSnippet($lines, $hit['line']));
        }
        if ($isCurved) {
            logMessage("  = " . formatScoreBreakdown($score));
        }
    }

    return $totalScore;
}

// Write logs
function logMessage($message) {
    global $targetLog;
    /** @var string $targetLog */
    $logEntry = date('Y-m-d H:i:s') . ' - ' . $message . PHP_EOL;
    file_put_contents($targetLog, $logEntry, FILE_APPEND);
}

function scanDirectory($dir) {
    global $targetLog, $totalFilesScanned, $filesSkipped, $filesUnreadable, $dirsUnreadable, $maxFileSize, $riskCounts, $flagFromScore;
    /** @var string $targetLog */
    /** @var int $totalFilesScanned */
    /** @var int $filesSkipped */
    /** @var int $filesUnreadable */
    /** @var int $dirsUnreadable */
    /** @var int $maxFileSize */
    /** @var array<string, int> $riskCounts */
    /** @var int $flagFromScore */
    $hasHighRisk = false;
    $selfName    = basename(__FILE__);
    $selfPath    = realpath(__FILE__);
    /** @var string[] $queue */
    $queue = array($dir);
    // Real paths walked so far, guards against symlink loops
    /** @var array<string, bool> $visited */
    $visited = array();

    while (!empty($queue)) {
        $currentDir = array_shift($queue);

        $realDir = realpath($currentDir);
        if ($realDir !== false && isset($visited[$realDir])) {
            logMessage("Skipped already scanned directory (symlink): $currentDir");
            continue;
        }
        if ($realDir !== false) {
            $visited[$realDir] = true;
        }

        $files = @scandir($currentDir);
        if ($files === false) {
            $dirsUnreadable++;
            echo "\033[31mError: Unable to read directory: $currentDir\033[0m\n";
            logMessage("Error: Unable to read directory: $currentDir");
            continue;
        }

        $dirPrefix = rtrim($currentDir, '/\\') . DIRECTORY_SEPARATOR;

        foreach ($files as $file) {
            if ($file == '.' || $file == '..') {
                continue;
            }

            $filePath = $dirPrefix . $file;

            if (isExcluded($filePath)) {
                continue;
            }

            if (is_dir($filePath)) {
                $queue[] = $filePath;
            } else {
                $kind = getFileKind($file);
                if ($kind !== null) {
                    if ($kind === 'php' && $file === $selfName && realpath($filePath) === $selfPath) {
                        logMessage("Skipped the scanner itself: $filePath");
                        continue;
                    }
                    $size = filesize($filePath);
                    if ($maxFileSize > 0 && $size !== false && $size > $maxFileSize) {
                        // Large photos are expected, only report skipped code and config
                        if ($kind !== 'image') {
                            $filesSkipped++;
                            echo "\033[33mFile skipped due to size: $filePath\033[0m\n";
                            logMessage("File skipped due to size: $filePath");
                        }
                        continue;
                    }
                    $score = scanFile($filePath, $kind);
                    if ($score < 0) {
                        $filesUnreadable++;
                        continue;
                    }
                    $totalFilesScanned++;
                    $risk = getRiskLevel($score);
                    $riskCounts[$risk['key']]++;
                    if ($score >= $flagFromScore) {
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
    if (!is_dir($targetDir) || !is_readable($targetDir)) {
        throw new Exception("Error: unable to read directory: $targetDir");
    }
    if (@file_put_contents($targetLog, '', FILE_APPEND) === false) {
        throw new Exception("Error: unable to write log file: $targetLog");
    }

    $excludedDirs = resolveExcludes($excludeArgs, $targetDir);
    $isClean      = scanDirectory($targetDir);

    echo "\033[32mSuspicious file scan complete! See $targetLog for results.\033[0m";

    $flagged = 0;
    foreach ($riskLabelMap as $label => $threshold) {
        if ($threshold >= $flagFromScore) {
            $flagged += $riskCounts[$label];
        }
    }

    echo "\n\n[Summary of Scan]\n\n";
    echo "Total files scanned:    $totalFilesScanned\n";
    echo "Files skipped (size):   $filesSkipped\n";
    echo "Unreadable files:       $filesUnreadable\n";
    echo "Unreadable dirs:        $dirsUnreadable\n";
    echo "Flagged (medium+):      $flagged\n";
    echo "\nBy risk level:\n";
    echo "  \033[35mCritical : {$riskCounts['critical']}\033[0m\n";
    echo "  \033[31mHigh     : {$riskCounts['high']}\033[0m\n";
    echo "  \033[33mMedium   : {$riskCounts['medium']}\033[0m\n";
    echo "  \033[36mLow      : {$riskCounts['low']}\033[0m\n";
    echo "  \033[32mClean    : {$riskCounts['clean']}\033[0m\n";

    exit($isClean ? EXIT_CLEAN : EXIT_FLAGGED);

} catch (Exception $e) {
    echo "\033[31m" . $e->getMessage() . "\033[0m\n";
    exit(EXIT_ERROR);
}
?>
