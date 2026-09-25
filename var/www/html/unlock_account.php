<?php 

require_once __DIR__ . "/../private/config.php";
require_once __DIR__ . "/../private/logger.php";
require_once __DIR__ . "/../private/database.php";

if ($_SERVER["REQUEST_METHOD"] !== "GET" || !isset($_GET["token"]) || !is_string($_GET["token"])) {
    Logger::warn("Invalid request format for account unlocking");
    http_response_code(400); // Bad request
    exit("Invalid or expired token"); 
}

$token = $_GET["token"];
$pdo = Database::init();

try {
    $sql = "
        SELECT user_id
        FROM account_unlocking 
        WHERE token = :token
        AND timestamp > (NOW() - INTERVAL :seconds SECOND)
    ";
    $statement = $pdo->prepare($sql);
    $statement->bindValue(":token", $token);
    $statement->bindValue(":seconds", Config::accountUnlockTokenTTL, PDO::PARAM_INT);
    $statement->execute();
    $row = $statement->fetch();

    // Token does not exist or is expired
    if (!$row) {
        // Note: expired tokens are cleaned with a database procedure
        Logger::warn("Invalid or expired token");
        http_response_code(400); // Bad request
        exit("Invalid or expired token");
    }

    $userId = $row["user_id"];
    
    // A transaction keeps the database in a consistent state
    // (operations such as token deletion and account unlocking are treated as atomic)
    $pdo->beginTransaction();

    // Invalidate the token
    $sql = "DELETE FROM account_unlocking WHERE token = :token";
    $statement = $pdo->prepare($sql);
    $statement->bindValue(":token", $token);
    $statement->execute();
    
    // Reset the failed login attempts counter 
    $sql = "UPDATE users SET failed_login_attempts = 0 WHERE id = :id";
    $statement = $pdo->prepare($sql);
    $statement->bindValue(":id", $userId);
    $statement->execute();

    $pdo->commit();
    Logger::info("User with id '$userId' successfully unlocked its account");
    header("Location: login.php");
    exit("Account successfully unlocked");
}
catch (PDOException $e) {
    if ($pdo->inTransaction()) { $pdo->rollBack(); }
    Logger::error("PDOException: " . $e->getMessage());
    http_response_code(503); // Service unavailable
    exit("Service unavailable");
}

?>

