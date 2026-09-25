<?php 

require_once __DIR__ . "/../private/config.php";
require_once __DIR__ . "/../private/logger.php";
require_once __DIR__ . "/../private/session.php";
require_once __DIR__ . "/../private/csrf.php";
require_once __DIR__ . "/../private/database.php";

Session::secureStart();

if (!Session::isLoggedIn()) {
    header("Location: login.php");
    exit("Must be logged in"); 
}

$pdo = Database::init(); 

if (Database::fetchUpdatedRole($pdo, $_SESSION[Session::userId]) !== ROLE::ADMIN) {
    Logger::warn("'" . $_SESSION[Session::username] . "' tried to access the admin dashboard");
    http_response_code(403); // Forbidden
    exit("You must be an admin to view this page");
}

try {
     if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["userId"], $_POST["newRole"])) {

        if (!is_numeric($_POST["userId"]) || !is_string($_POST["newRole"])) {
            Logger::warn("Invalid input type received (expected numeric and string)");
            http_response_code(400); // Bad request
            exit("Invalid input format"); 
        }

        $targetUserId = (int) $_POST["userId"];
        $newRole = ROLE::tryFrom($_POST["newRole"]);

        if ($newRole === null) {
            Logger::warn("Invalid role '" . $_POST["newRole"] . "' submitted by " . $_SESSION[Session::username]);
            http_response_code(400); // Bad request
            exit("Invalid input format"); 
        }

        if (!CSRF::validateToken()) {
            Logger::warn("Invalid csrf token received");
            http_response_code(400); // Bad request
            exit("Bad request");
        }

        if ($newRole !== ROLE::REGULAR && $newRole !== ROLE::PREMIUM) {
            Logger::warn("'" . $_SESSION[Session::username] .
                "' tried to set user id '$targetUserId' role to " . $newRole->name);
            http_response_code(403); // Forbidden
            exit("Something went wrong");
        }

        $sql = "UPDATE users SET role = :new_role WHERE id = :target_user_id";
        $statement = $pdo->prepare($sql);
        $statement->bindValue(":new_role", $newRole->value, PDO::PARAM_INT);
        $statement->bindValue(":target_user_id", $targetUserId, PDO::PARAM_INT);
        $statement->execute();

        if ($statement->rowCount() === 1) {
            Logger::info("'" . $_SESSION[Session::username] . 
                "' changed user id '$targetUserId' role to " . $newRole->name);
        } else {
            Logger::warn("'" . $_SESSION[Session::username] . 
                "' tried to change non-existing user id '$targetUserId' role");
        }
    }

    $sql = "
        SELECT id, username, role
        FROM users 
        WHERE role IN (" . ROLE::REGULAR->value . ", " . ROLE::PREMIUM->value . ")
    ";
    $statement = $pdo->prepare($sql);
    $statement->execute();
    $users = $statement->fetchAll(PDO::FETCH_ASSOC);
    // PERF: In a real application, one should implement pagination instead of fetching all users
}
catch (PDOException $e) {
    Logger::error("PDOException: " . $e->getMessage());
    http_response_code(503); // Service unavailable
    exit("Service unavailable");
} 

?>
<!DOCTYPE html>
<html>
<head>
    <title>SNH{Dashboard.}</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <h1>Admin dashboard</h1>
    <table>
        <tr>
            <th>Username</th>
            <th>Current role</th>
            <th>Action</th>
        </tr>
        <?php $token = CSRF::generateToken(); // One for all the forms in this page ?>
        <?php foreach ($users as $user): ?>
            <?php $role = ROLE::tryFrom($user["role"]) ?>
            <tr>
                <td><?= htmlspecialchars($user["username"]) ?></td>
                <td><?= $role->name ?></td>
                <td>
                    <form method="POST">
                        <input type="hidden" name="userId" value="<?= htmlspecialchars($user["id"]) ?>">
                        <?= CSRF::embedToken($token) ?>
                        <?php if ($role === ROLE::PREMIUM): ?>
                            <input type="hidden" name="newRole" value="<?= ROLE::REGULAR->value ?>">
                            <button type="submit">Revoke premium</button>
                        <?php else: ?>
                            <input type="hidden" name="newRole" value="<?= ROLE::PREMIUM->value ?>">
                            <button type="submit">Make premium</button>
                        <?php endif; ?>
                    </form>
                </td>
            </tr>
        <?php endforeach; ?>
    </table>
    <p><a href="index.php">Index</a></p>
</body>
</html>

