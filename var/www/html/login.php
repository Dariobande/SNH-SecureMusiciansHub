<?php 

require_once __DIR__ . "/../private/config.php";
require_once __DIR__ . "/../private/logger.php";
require_once __DIR__ . "/../private/session.php";
require_once __DIR__ . "/../private/csrf.php";
require_once __DIR__ . "/../private/database.php";

Session::secureStart();

if (Session::isLoggedIn()) {
    header("Location: index.php");
    exit("Already logged in"); 
}

if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["username"], $_POST["password"])) 
{
    $username = $_POST["username"];
    $password = $_POST["password"];

    if (!CSRF::validateToken()) {
        Logger::warn("Invalid csrf token received");
        http_response_code(400); // Bad request
        exit("Bad request");
    }

    if (!is_string($username) || !is_string($password)) {
        Logger::warn("Invalid input type received (expected strings)");
        http_response_code(400); // Bad request
        exit("Invalid credentials");
    }

    $pdo = Database::init();
    
    try {
        // NOTE: There is a race condition between the fetch of the
        //  old failed_login_attempts counter, its usage, and its increment. 
        //  It allows an attacker to try as many passwords as the number of
        //  concurrent requests he can make to the server.
        // To avoid this, we wrap everything in a transaction and mark
        //  the row of the counter as FOR UPDATE (locks it)
        $pdo->beginTransaction();

        $sql = "
            SELECT id, email, password_hash, failed_login_attempts 
            FROM users 
            WHERE username = :username
            FOR UPDATE
        ";
        $statement = $pdo->prepare($sql);
        $statement->bindValue(":username", $username);
        $statement->execute();
        $user = $statement->fetch();
        
        // Username does not exist
        if (!$user) {
            $pdo->rollBack();
            Logger::warn("Attemped to login as non-existing user '$username'");
            http_response_code(400); // Bad request
            exit("Invalid credentials");
        }

        // Account blocked
        if ($user["failed_login_attempts"] > Config::failedLoginAttemptsMax) {
            $pdo->rollBack();
            Logger::warn("Attempted to login as a blocked user '$username'");
            http_response_code(400); // Bad request
            exit("Invalid credentials");
        }
    
        // Wrong password 
        if (!password_verify($password, $user["password_hash"])) 
        {
            Logger::warn("Failed to login as '$username' (" . $user["failed_login_attempts"]
                . "/" . Config::failedLoginAttemptsMax . " failed attempts in a row)");

            // Increment the failed login counter
            $sql = "
                UPDATE users 
                SET failed_login_attempts = failed_login_attempts + 1
                WHERE username = :username
            ";
            $statement = $pdo->prepare($sql);
            $statement->bindValue(":username", $username);
            $statement->execute();

            // Reached the limit of failed login attempts in a row (send the account unlocking email)
            if ($user["failed_login_attempts"] + 1 === Config::failedLoginAttemptsMax) 
            {
                $token = bin2hex(random_bytes(32));
                $sql = "
                    INSERT INTO account_unlocking (user_id, token) 
                    VALUES (:user_id, :token)
                    ON DUPLICATE KEY UPDATE
                        token = :token,
                        timestamp = NOW()
                ";
                $statement = $pdo->prepare($sql);
                $statement->bindValue(":user_id", $user["id"], PDO::PARAM_INT);
                $statement->bindValue(":token", $token);
                $statement->execute();
                
                $subject = "SNH account unlocking";
                $accountUnlockURL = "http://" . Config::serverIpAddress . "/unlock_account.php?token=" . urlencode($token); 
                $passwordChangeURL = "http://" . Config::serverIpAddress . "/password_recovery.php";
                $body = "Dear $username,\n" . 
                        "We experienced an unusual number of failed login attempts on your account and decided to temporarily block new log in attempts.\n" .
                        "In order to unlock the account without having to change your credentials, log in using the following link: $accountUnlockURL\n" .
                        "If the link expired, you can unlock the account by changing your password ($passwordChangeURL)";
                $headers = "From: " . Config::serverEmailAddress . "\r\nContent-Type: text/plain; charset=UTF-8\r\n";
                $parameters = "-f" . Config::serverEmailAddress;

                if (!mail($user["email"], $subject, $body, $headers, $parameters)) {
                    Logger::error("Unable to send account unlocking email to '" . $user["email"] . "')"); 
                    http_response_code(503); // Service unavailable
                    exit("Service unavailable");
                }
                
                Logger::info("Account unlocking email sent to '" . $user["email"] . "')");
            } 

            // Commit the counter update (and, optionally, the creation of the token)
            $pdo->commit();

            http_response_code(400); // Bad request
            exit("Invalid credentials");
        }
 
        // Login successfull

        // Redundant defense against session fixation
	    session_regenerate_id(true);

        // Reset the failed login attempts counter 
        if ($user["failed_login_attempts"] > 0) {
            $sql = "UPDATE users SET failed_login_attempts = 0 WHERE username = :username";
            $statement = $pdo->prepare($sql);
            $statement->bindValue(":username", $username);
            $statement->execute();
        } 

        // Commit the counter reset
        $pdo->commit();
      
        Logger::info("Logged in as '$username'");

        $_SESSION[Session::username] = $username;
        $_SESSION[Session::userId] = $user["id"];
	    $_SESSION[Session::lastAccess] = time();

        header("Location: index.php");
        exit("Login successful");
    }
    catch (PDOException $e) {
        if ($pdo->inTransaction()) { $pdo->rollBack(); }
        Logger::error("PDOException: " . $e->getMessage());
        http_response_code(503); // Service unavailable
        exit("Service unavailable");
    }
}

?>
<!DOCTYPE html>
<html>
<head>
    <title>SNH{Login.}</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
	<h1>Login</h1>
	<form method="post">

        <label for="username">Username</label>
        <input type="text" name="username" id="username" required>
	    
        <label for="password">Password</label>
        <input type="password" name="password" id="password" required>

        <?= CSRF::embedToken() ?> 
        <input type="submit" value="Login" class="button">

    </form>
    <p><a href="register.php">Don't have an account? Register</a></p>
    <p><a href="password_recovery.php">Forgot your password?</a></p>
</body>
</html>

