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

if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["username"], $_POST["email"], $_POST["password"])) {

    $username = $_POST["username"];
    $email = $_POST["email"];
    $password = $_POST["password"];

    if (!CSRF::validateToken()) {
        Logger::warn("Invalid csrf token received");
        http_response_code(400);
        exit("Bad request");
    }

    if (!is_string($username) || !is_string($email) || !is_string($password)) {
        Logger::warn("Invalid input type received (expected strings)");
        http_response_code(400);
        exit("Invalid input format");
    }

    if (strlen($username) < 1) {
        Logger::warn("Received an empty username");
        http_response_code(400);
        exit("The username must not be empty");
    }

    if (strlen($username) > Config::usernameLenMax) {
        Logger::warn("Username too long. Expected at most " . Config::usernameLenMax .
            " characters, got " . strlen($username) . " instead");
        http_response_code(400);
        exit("The username must be at most " . Config::usernameLenMax . " characters long");
    }
    
    if (preg_match("/^[a-zA-Z0-9]+$/", $username) !== 1) {
        Logger::warn("Received an username containing invalid characters");
        http_response_code(400);
        exit("The username can only contain letters and numbers");
    } 
    
    if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
        Logger::warn("Received an invalid email");
        http_response_code(400);
        exit("Invalid email");
    }

    $pdo = Database::init();

    try {
        // Uniqueness check, pending user insertion and email sending must all be one atomic operation
        $pdo->beginTransaction();

        // Check username and email uniqueness against the registred users
        $sql = "SELECT 1 FROM users WHERE email = :email OR username = :username";
        $statement = $pdo->prepare($sql);
        $statement->bindValue(":email", $email);
        $statement->bindValue(":username", $username);
        $statement->execute();

        if($statement->fetch()) {
            throw new PDOException("Username or email already in use", 23000);
        } 
        
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);
        $token = bin2hex(random_bytes(32));

        $sql = "
            INSERT INTO pending_users (email, username, password_hash, token) 
            VALUES (:email, :username, :password_hash, :token)
        ";
        $statement = $pdo->prepare($sql);
        $statement->bindValue(":email", $email);
        $statement->bindValue(":username", $username);
        $statement->bindValue(":password_hash", $passwordHash);
        $statement->bindValue(":token", $token);
        $statement->execute();

        $subject = "SNH account activation";
        $emailConfirmationURL = "http://" . Config::serverIpAddress . "/activate_account.php?token=" . urlencode($token); 
        $body = "Dear $username,\n" . 
                "To activate your SNH account, click on the following link: $emailConfirmationURL";
        $headers = "From: " . Config::serverEmailAddress . "\r\nContent-Type: text/plain; charset=UTF-8\r\n";
        $parameters = "-f" . Config::serverEmailAddress;

        if (!mail($email, $subject, $body, $headers, $parameters)) {
            Logger::error("Unable to send account activation email to '$email')"); 
            http_response_code(503); // Service unavailable
            exit("Service unavailable");
        }

        $pdo->commit();
        Logger::info("Account activation email sent to '$email')"); 
        exit("Check you email to complete the registration procedure");
    }
    catch (PDOException $e) {
        $pdo->rollBack();
        // SQLSTATE 23000 is the integrity constraint violation
        if ($e->getCode() == "23000") {
            Logger::warn("Tried to register a user with username or email already in use");
            http_response_code(409); // Conflict
            exit("Username or email already taken");
        } else {
            Logger::error("PDOException: " . $e->getMessage());
            http_response_code(503); // Service unavailable
            exit("Service unavailable");
        }
    }

}

?>
<!DOCTYPE html>
<html>
<head>
    <title>SNH{Register.}</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
	<h1>Register</h1>
	<form method="post">

        <label for="username">Username [Between 1 and <?= Config::usernameLenMax ?> letters and numbers]</label>
        <input type="text" name="username" id="username" pattern="[a-zA-Z0-9]{1,<?= Config::usernameLenMax ?>}" required>

        <label for="email">E-mail</label>
        <input type="email" name="email" id="email" required>
	    
        <label for="password">Password [At least <?= Config::passwordLenMin ?> characters, 1 lowercase, 1 uppercase and 1 special character]</label>
        <input type="password" name="password" id="password" minlength="<?= Config::passwordLenMin ?>" pattern=<?= Config::passwordPattern ?> required>

        <?= CSRF::embedToken() ?> 
        <input type="submit" value="Register" class="button">
    </form>
    <p><a href="login.php">Already have an account? Login</a></p>
</body>
</html>

