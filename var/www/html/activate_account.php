<?php 

require_once __DIR__ . "/../private/config.php";
require_once __DIR__ . "/../private/logger.php";
require_once __DIR__ . "/../private/database.php";

if ($_SERVER["REQUEST_METHOD"] !== "GET" || !isset($_GET["token"]) || !is_string($_GET["token"])) {
    Logger::warn("Invalid request format for account activation");
    http_response_code(400); // Bad request
    exit("Invalid or expired token"); 
}

$token = $_GET["token"];
$pdo = Database::init();

try {
    $sql = "
        SELECT email, username, password_hash
        FROM pending_users 
        WHERE token = :token
        AND timestamp > (NOW() - INTERVAL :seconds SECOND)
    ";
    $statement = $pdo->prepare($sql);
    $statement->bindValue(":token", $token);
    $statement->bindValue(":seconds", Config::accountActivationTokenTTL, PDO::PARAM_INT);
    $statement->execute();
    $pendingUser = $statement->fetch();

    // Token does not exist or is expired
    if (!$pendingUser) {
        // Note: expired tokens are cleaned with a database procedure
        Logger::warn("Invalid or expired token");
        http_response_code(400); // Bad request
        exit("Invalid or expired token");
    }

    // A transaction keeps the database in a consistent state
    // (operations such as token deletion and account activation are treated as atomic)
    $pdo->beginTransaction();

    // Invalidate the token
    $sql = "DELETE FROM pending_users WHERE token = :token";
    $statement = $pdo->prepare($sql);
    $statement->bindValue(":token", $token);
    $statement->execute();
    
    // Reset the failed login attempts counter 
    $sql = "
        INSERT INTO users (email, username, password_hash) 
        VALUES (:email, :username, :password_hash)
    ";
    $statement = $pdo->prepare($sql);
    $statement->bindValue(":email", $pendingUser["email"]);
    $statement->bindValue(":username", $pendingUser["username"]);
    $statement->bindValue(":password_hash", $pendingUser["password_hash"]);
    $statement->execute();

    $pdo->commit();
    Logger::info("User '" . $pendingUser["username"] . "' successfully activated his account");
    header("Location: login.php");
    exit("Account successfully activated");
}
catch (PDOException $e) {
    if ($pdo->inTransaction()) { $pdo->rollBack(); }
    Logger::error("PDOException: " . $e->getMessage());
    http_response_code(503); // Service unavailable
    exit("Service unavailable");
}

?>

