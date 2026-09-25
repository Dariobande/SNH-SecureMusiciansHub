<?php 

require_once __DIR__ . "/../private/config.php";
require_once __DIR__ . "/../private/session.php";
require_once __DIR__ . "/../private/csrf.php";
require_once __DIR__ . "/../private/logger.php";
require_once __DIR__ . "/../private/database.php";

Session::secureStart();

if (!Session::isLoggedIn()) {
    header("Location: login.php");
    exit("Must be logged in"); 
}

$pdo = Database::init();
$role = Database::fetchUpdatedRole($pdo, $_SESSION[Session::userId]);

// Handle audio download via GET: index.php?download=<id>
if ($_SERVER["REQUEST_METHOD"] === "GET" && isset($_GET["download"]) && is_numeric($_GET["download"])) {

    $postId = (int)$_GET["download"];

    try {
        $statement = $pdo->prepare("SELECT p.audio, p.premium FROM posts p WHERE p.id = :post_id");
        $statement->bindValue("post_id", $postId);
        $statement->execute();

        $post = $statement->fetch();
        if (!$post) {
            Logger::warn("Download requested for non-existing post id $postId");
            http_response_code(404); // Not found
            exit("Not found");
        }

        // If the user tries to download premium content without permission, reject
        if ((int)$post["premium"] === 1) {
            if (!in_array($role, [ROLE::PREMIUM, ROLE::ADMIN])) {
                http_response_code(403); // Forbidden
                exit("Premium content — upgrade to access");
            }
        }

        if (!$post["audio"]) {
            http_response_code(404); // Not found
            exit("No audio available");
        }

        // Set headers for file download
        header("Content-Type: audio/mpeg");
        header("Content-Disposition: attachment; filename=\"audio-track-$postId.mp3\"");
        header("Content-Length: " . strlen($post["audio"])); // Tells the browser the file size
        header("Cache-Control: no-cache"); // Prevent browsers from caching the file

        // Output the binary data of the audio file
        echo $post["audio"];

        // Download started... 
        exit();

    } catch (PDOException $e) {
        Logger::error("Download failed for post id $postId: " . $e->getMessage());
        http_response_code(503); // Service unavailable
        exit("Service unavailable");
    }
}

// Handle post upload via POST
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["lyrics"]) && isset($_FILES["audio"])) {

    // Validate CSRF
    if (!CSRF::validateToken()) {
        Logger::warn("Invalid csrf token received");
        http_response_code(400); // Bad request
        exit("Bad request");
    }

    if (!is_string($_POST["lyrics"])){
        Logger::warn("Invalid lyrics input type received (expected string)");
        http_response_code(400); // Bad request
        exit("Invalid input format");
    }

    $hasAudio = $_FILES["audio"]["error"] !== UPLOAD_ERR_NO_FILE;
    $lyrics = trim($_POST["lyrics"]);

    // At least one of lyrics or audio must be provided
    if ($lyrics === "" && !$hasAudio) {
        Logger::warn("Empty post attempt by user " . $_SESSION[Session::username]);
        http_response_code(400); // Bad request
        exit("At least lyrics or audio must be provided");
    }

    $premium = isset($_POST["premium"]) ? 1 : 0;

    // If the user marked the post as premium, but is not premium or admin, reject
    if ($premium === 1) {
        if (!in_array($role, [ROLE::PREMIUM, ROLE::ADMIN])) {
            Logger::warn("User " . $_SESSION[Session::username] . " attempted to upload premium content without permission");
            http_response_code(403); // Forbidden
            exit("You do not have permission to upload premium content");
        }
    }

    // If no audio uploaded, set to empty
    $audioBlob = "";
    if ($hasAudio) {
        $file = $_FILES["audio"];

        if ($file["error"] !== UPLOAD_ERR_OK) {
            Logger::warn("File upload error code " . $file["error"] . " for user " . $_SESSION[Session::username]);
            http_response_code(400); // Bad request
            exit("File upload error");
        }

        // Size limit to prevent large uploads
	    if ($file["size"] > Config::audioSizeMax) {
            Logger::warn("Rejected upload due to size limit for user " . $_SESSION[Session::username]);
            http_response_code(400); // Bad request
            exit("File too large (max " . Config::audioSizeMax . " bytes)");
        }

        // Validate file content via MIME: ensure it's a real MP3 regardless of extension
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime = $finfo->file($file["tmp_name"]);
        $allowed = ["audio/mpeg", "audio/mp3", "audio/x-mpeg-3"];
        if (!in_array($mime, $allowed)) {
            Logger::warn("Rejected upload due to unsupported MIME: $mime for user " . $_SESSION[Session::username]);
            http_response_code(400); // Bad request
            exit("Unsupported audio format (only MP3 allowed)");
        }
        $audioBlob = file_get_contents($file["tmp_name"]);
    }    
    
    try {
        $statement = $pdo->prepare("
            INSERT INTO posts (user_id, timestamp, lyrics, audio, premium) 
            VALUES (:user_id, NOW(), :lyrics, :audio, :premium)");
        $statement->bindValue("user_id", $_SESSION[Session::userId], PDO::PARAM_INT);
        $statement->bindValue("lyrics", $lyrics);
        $statement->bindValue("audio", $audioBlob);
        $statement->bindValue("premium", $premium, PDO::PARAM_INT);
        $statement->execute();
        header("Location: index.php");
        exit("Upload successful");
    } 
    catch (PDOException $e) {
        Logger::error("Upload failed: " . $e->getMessage());
        http_response_code(503); // Service unavailable
        exit("Service unavailable");
    }
}

// Fetch recent posts
try {
    $statement = $pdo->prepare("
        SELECT p.id, p.timestamp, p.lyrics, p.premium, u.username, OCTET_LENGTH(p.audio) AS audio_len 
        FROM posts p JOIN users u ON p.user_id = u.id 
        ORDER BY p.timestamp DESC 
        LIMIT 20
    ");
    $statement->execute();
    $posts = $statement->fetchAll();
} 
catch (PDOException $e) {
    Logger::error("Fetching posts failed: " . $e->getMessage());
    http_response_code(503); // Service unavailable
    exit("Service unavailable");
}

?>
<!DOCTYPE html>
<html>
<head>
    <title>SNH{Index.}</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <h1>Welcome back, <?= htmlspecialchars($_SESSION[Session::username]) ?></h1>
    <p><a href="logout.php">Logout</a></p>
    <?php if ($role === ROLE::ADMIN): ?>
        <p><a href="dashboard.php">Open admin dashboard</a></p>
    <?php endif; ?>

    <h2>Recent posts</h2>
    <?php if (empty($posts)): ?>
        <p>No posts yet.</p>
    <?php else: ?>
        <?php foreach ($posts as $post): ?>
            <div class="post">
                <div class="meta">By 
                    <?= htmlspecialchars($post["username"]) ?> at <?= htmlspecialchars($post["timestamp"]) ?>
                    <?php if ((int)$post["premium"] === 1): ?><strong>(Premium)</strong><?php endif; ?>
                </div>
                <?php if ((int)$post["premium"] === 1 && !in_array($role, [ROLE::PREMIUM, ROLE::ADMIN])): ?>
                    <div class="locked">This is premium content. Upgrade to access.</div>
                <?php else: ?>
                    <pre class="lyrics"><?= htmlspecialchars($post["lyrics"]) ?></pre>
                    <?php if ((int)$post["audio_len"] > 0): ?>
                        <div class="audio"><a href="index.php?download=<?= (int)$post["id"] ?>">Download audio</a></div>
                    <?php else: ?>
                        <div class="no-audio">No audio attached</div>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
            <hr>
        <?php endforeach; ?>
    <?php endif; ?>

    <h2>Upload new post</h2>
    <form method="post" enctype="multipart/form-data">
        <?= CSRF::embedToken() ?>
        <div>
            <label for="lyrics">Lyrics (text):</label><br>
            <textarea name="lyrics" id="lyrics" rows="6" cols="60" required></textarea>
        </div>
        <div>
            <label for="audio">Audio file (max 10MB):</label><br>
            <input type="file" name="audio" id="audio" accept="audio/mpeg,audio/mp3,audio/x-mpeg-3">
        </div>
        <div>
            <label><input type="checkbox" name="premium" value="1">Mark as premium</label>
        </div>
        <div>
            <button type="submit">Upload</button>
        </div>
    </form>

</body>
</html>

