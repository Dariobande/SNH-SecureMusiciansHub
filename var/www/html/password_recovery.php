<?php

require_once __DIR__ . '/../private/config.php';
require_once __DIR__ . '/../private/csrf.php';
require_once __DIR__ . '/../private/session.php';
require_once __DIR__ . '/../private/logger.php';
require_once __DIR__ . '/../private/database.php';

Session::secureStart();

$error = '';
$success = false;

const GENERIC_ERROR_MSG = "Oops! Something went wrong. Please try again.";
const INVALID_EMAIL_ERROR_MSG = "Invalid email format.";

/**
 * handles token generation and email sending.
 * throws Exception on failure is caught by the main block.
 */
function processRecoveryRequest($pdo, $user, $email) {
    $rawToken = bin2hex(random_bytes(32));
    $tokenHash = hash('sha256', $rawToken); 

    $sql = "INSERT INTO password_recovery (user_id, token) 
            VALUES (:user_id, :token)
            ON DUPLICATE KEY UPDATE 
                token = :token, 
                timestamp = NOW()";

    $stmt = $pdo->prepare($sql);
    $stmt->execute([
        'user_id' => $user['id'],
        'token' => $tokenHash
    ]);

    $resetLink = "http://" . Config::serverIpAddress . "/reset_confirm.php?token=" . urlencode($rawToken);
    
    $subject = "Password Reset Request";
    $messageBody = "Hello " . $user['username'] . ",\n\nClick here to reset: " . $resetLink . "\n\nExpires in 5 minutes.";
    
    $headers = "From: " . Config::serverEmailAddress . "\r\nContent-Type: text/plain; charset=UTF-8\r\n";
    $parameters = "-f" . Config::serverEmailAddress;

    if (!mail($email, $subject, $messageBody, $headers, $parameters)) {
        throw new Exception("Mail sending failed.");
    }

    logger::info("Password reset email sent to " . $email);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['email'])) {
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    if (!is_string($_POST['email'])) {
        logger::warn("Invalid input type received (expected strings)");
        $error = GENERIC_ERROR_MSG;
    } else if (!CSRF::validateToken()) {
        logger::warn("Invalid CSRF token during password reset.");
        $error = GENERIC_ERROR_MSG;
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        logger::warn("Invalid email format: " . $email);
        $error = INVALID_EMAIL_ERROR_MSG;
    } else {
        $pdo = Database::init();
        try {
            $stmt = $pdo->prepare("SELECT id, username FROM users WHERE email = ?");
            $stmt->execute([$email]);
            $user = $stmt->fetch();
            
            if ($user !== false) {
                processRecoveryRequest($pdo, $user, $email);
            } else {
                logger::warn("Password reset requested for non-existent email: $email");
            }
            $success = true;
        } catch (Exception $e) {
            logger::error("Recovery mail: error for $email: " . $e->getMessage());
            $error = GENERIC_ERROR_MSG;
        }
    }
}

?>
<!DOCTYPE html>
<html>
<head>
    <title>SNH{Password recovery.}</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <h1>Password recovery</h1>
    <?php if ($error): ?>
        <div><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    <?php if ($success): ?>
        <div>If an account with that email exists, we have sent password reset instructions.</div>
    <?php else: ?>
        <form method="POST">
            <label for="email">Email</label>
            <input type="email" id="email" name="email" required>
            <?= CSRF::embedToken() ?>
            <input type="submit" value="Send reset instructions" class="button">
        </form>
    <?php endif; ?>
    <p><a href="login.php">Back to login</a></p>
</body>
</html>

