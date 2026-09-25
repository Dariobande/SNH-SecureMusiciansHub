<?php

class Config {

    // Database configuration
    // [In a real application, we would have used environment variables]
    const dbHost = "127.0.0.1";
    const dbName = "snh_db";
    const dbUsername = "snh_user";
    const dbPassword = "super-strong-password";
    const dbConnectionString = "mysql:host=" . self::dbHost . ";dbname=" . self::dbName . ";charset=utf8mb4";

    // Constraints
    const usernameLenMax = 32;
    const passwordLenMin = 12;
    // at least one lowercase, one uppercase, one special
    const passwordPattern = "(?=.*[A-Z])(?=.*[a-z])(?=.*[^A-Za-z0-9]).*";
    const failedLoginAttemptsMax = 10;
    const audioSizeMax = 10 * 1024 * 1024;          // 10 MB
    const sessionTTL = 10 * 60;                     // 10 minutes
    const passwordRecoveryTokenTTL = 5 * 60;        // 5 minutes
    const accountUnlockTokenTTL = 72 * 60 * 60;     // 72 hours
    const accountActivationTokenTTL = 24 * 60 * 60; // 24 hours

    // SMTP configuration
    const serverEmailAddress = "noreply@snh.com";
    const serverIpAddress = "127.0.0.1";

}

?>

