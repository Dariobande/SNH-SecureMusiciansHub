<?php

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/logger.php';

class Database {

    /* Initializes a PDO object and returns it. Automatically exits on failure */
    public static function init() : PDO {
        try {
            $pdo = new PDO(Config::dbConnectionString, Config::dbUsername, Config::dbPassword);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            return $pdo;        
        }
        catch (PDOException $e) {
            Logger::error("PDOException: " . $e->getMessage());
            http_response_code(503); // Service unavailable
            exit("Service unavailable");
        }
    }

    /* Fetches the updated user role from the database. Automatically exits on failure */
    public static function fetchUpdatedRole(PDO $pdo, int $userId) : ROLE {
        try {
            $sql = "SELECT role FROM users WHERE id = :id";
            $statement = $pdo->prepare($sql);
            $statement->bindValue(":id", $userId);
            $statement->execute();

            $user = $statement->fetch();
            if (!$user) {
                Logger::error("Unable to fetch updated role, user id '$userId' does not exist");
                http_response_code(404); // Not found
                exit("User ID not found");
            }

            $role = ROLE::tryFrom($user["role"]);
            if (!$role) {
                Logger::error("Unable to parse role " . $user["role"]);
                http_response_code(503); // Service unavailable
                exit("Service unavailable"); 
            }

            return $role;
        }
        catch (PDOException $e) {
            Logger::error("PDOException: " . $e->getMessage());
            http_response_code(503); // Service unavailable
            exit("Service unavailable");
        }
    }

}

/* Represents the roles that users can have */
enum ROLE: int {
    case REGULAR = 0;
    case PREMIUM = 1;
    case ADMIN = 2;
}

?>

