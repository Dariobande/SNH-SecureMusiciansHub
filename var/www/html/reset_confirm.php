<?php

require_once __DIR__ . '/../private/config.php';
require_once __DIR__ . '/../private/logger.php';
require_once __DIR__ . '/../private/session.php';
require_once __DIR__ . '/../private/database.php';

$error = '';
$show_form = false;
$success = false;

$token = $_GET['token'] ?? $_POST['token'] ?? '';

const GENERIC_ERROR_MSG = "Oops! Something went wrong. Please try again.";
const PASSWORD_BAD_MATCH_ERROR_MSG = "Passwords do not match.";
const PASSWORD_MIN_LENGTH = Config::passwordLenMin;
const PASSWORD_TOO_SHORT_ERROR_MSG = "Password must be at least " . PASSWORD_MIN_LENGTH . " characters long.";

// GET Request: Initial Validation
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if (!is_string($token)) {
        logger::warn("Invalid token type received (expected string)");
        $error = GENERIC_ERROR_MSG;
    } elseif($token === '') { 
        logger::warn("No token received.");
        $error = GENERIC_ERROR_MSG;
    } else {
        $pdo = Database::init();
        try {
            $token_hash = hash('sha256', $token);

            $stmt = $pdo->prepare("
                SELECT user_id 
                FROM password_recovery 
                WHERE token = ? AND timestamp > DATE_SUB(NOW(), INTERVAL " . Config::passwordRecoveryTokenTTL . " SECOND)
            ");
            $stmt->execute([$token_hash]);
            $row = $stmt->fetch();

            if ($row !== false) {
                $show_form = true;
            } else {
                logger::warn("Invalid or expired token.");
                $error = GENERIC_ERROR_MSG;
            }
        } catch (PDOException $e) {
            logger::error("PDOException: " . $e->getMessage());
            $error = GENERIC_ERROR_MSG;
        }
    }
}

// POST Request: Final Processing
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'], $_POST['confirm_password'], $_POST['token'])) {
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    if(!is_string($password) || !is_string($confirm_password)) {
        logger::warn("Invalid input type received (expected strings)");
        $error = GENERIC_ERROR_MSG;
    } elseif (strlen($password) < PASSWORD_MIN_LENGTH) {
        logger::warn("Password too short.");
        $error = PASSWORD_TOO_SHORT_ERROR_MSG;
        $show_form = true; 
    } elseif ($password !== $confirm_password) {
        logger::warn("Passwords do not match.");
        $error = PASSWORD_BAD_MATCH_ERROR_MSG;
        $show_form = true; 
    } else {
        $pdo = Database::init();
        try {
            $pdo->beginTransaction();

            $token_hash = hash('sha256', $token);
            $stmt = $pdo->prepare("SELECT user_id FROM password_recovery WHERE token = ? AND timestamp > DATE_SUB(NOW(), INTERVAL 5 MINUTE)");
            $stmt->execute([$token_hash]);
            $row = $stmt->fetch();

            if ($row !== false) {
                $password_hash = password_hash($password, PASSWORD_DEFAULT);

                $update_sql = "UPDATE users
                               SET password_hash = ?, failed_login_attempts = 0
                               WHERE id = ?";
                $pdo->prepare($update_sql)->execute([$password_hash, $row['user_id']]);

                // Delete the used token
                $pdo->prepare("DELETE FROM password_recovery WHERE user_id = ?")->execute([$row['user_id']]);
                
                $pdo->commit();
                $success = true;

                Session::secureDestroy(false);

                logger::info("Password updated successfully for user with id " . $row['user_id']);
            } else {
                $pdo->rollBack();
                logger::warn("Invalid token hash during update.");
                $error = GENERIC_ERROR_MSG;
            }
        } catch (PDOException $e) {
            if (isset($pdo) && $pdo->inTransaction())
                $pdo->rollBack();
            logger::error("PDOException in update password: " . $e->getMessage());
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
    <?php if ($error !== ''): ?>
        <div><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    <?php if ($success === true): ?>
        <div>Password updated successfully. You can now login.</div>
    <?php elseif ($show_form === true): ?>
        <form method="POST" action="">
            <input type="hidden" name="token" value="<?= htmlspecialchars($token) ?>">
            <div>
                <label>New password [At least <?= Config::passwordLenMin ?> characters, 1 lowercase, 1 uppercase and 1 special character]</label>
                <input type="password" name="password" required minlength="<?= PASSWORD_MIN_LENGTH ?>" pattern=<?= Config::passwordPattern ?> >
            </div>
            <div><label>Confirm password</label><input type="password" name="confirm_password" required minlength="<?= PASSWORD_MIN_LENGTH ?>" pattern=<?= Config::passwordPattern ?> ></div>
            <input type="submit" value="Reset password" class="button">
        </form>
    <?php elseif ($error === ''): ?>
        <p><a href="password_recovery.php">Request a new reset link</a></p>
    <?php endif; ?>
    <p><a href="login.php">Back to login</a></p>
</body>
</html>

