<?php

class Logger {

    /* This folder must be writable by the www-data group (apache2 process) */
    private const logDir = __DIR__ . "/../logs";

    /* Appends a log entry to the daily log file */
    private static function log(string $message, string $level) : void {
        try {
            $timestamp = date("Y-m-d H:i:s");
            $context = [
                "ip"    => $_SERVER["REMOTE_ADDR"] ?? "N/A",
                "url"   => $_SERVER["REQUEST_URI"] ?? "N/A",
                "method"=> $_SERVER["REQUEST_METHOD"] ?? "N/A",
                "agent" => $_SERVER["HTTP_USER_AGENT"] ?? "N/A"
            ];

            // JSON_UNESCAPED_SLASHES: Do not escape / in the resulting json string
            // JSON_PARTIAL_OUTPUT_ON_ERROR: Prevents failure if binary data is accidentally passed
            $contextString = json_encode($context, JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);
            $formattedMessage = "[$timestamp] [$level] {$contextString} - $message" . PHP_EOL;

            // FILE_APPEND: Appends to the file instead of overwriting
            // LOCK_EX:     Applies an exclusive lock to prevent race conditions
            $logFile = self::logDir . "/security-report-" . date("Ymd") . ".log";

            $result = file_put_contents($logFile, $formattedMessage, FILE_APPEND | LOCK_EX);
            if ($result === false) {
                throw new Exception("Unable to write to '$logFile'");
            }
        } 
        catch (Exception) { /* Not much you can do if the logger itself fails... */ } 
    }

    public static function info(string $message) : void {
        self::log($message, "INFO");
    }

    public static function warn(string $message) : void{
        self::log($message, "WARN");
    }

    public static function error(string $message) : void {
        self::log($message, "ERROR");
    }

}

?>

