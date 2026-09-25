<?php

/* Cross Site Request Forgery protection features */
class CSRF {

    private const tokenKey = "CSRFtoken";
    private const tokenSize = 32;

    /* Generates a cryptographically secure token and stores it in the user session */
    public static function generateToken() : string {
        $token = bin2hex(random_bytes(self::tokenSize));
        $_SESSION[self::tokenKey] = $token;
        return $token;
    }

    /* Validates the token present in the POST request against the one saved in the session */
    public static function validateToken() : bool {
        if (!isset($_SESSION[self::tokenKey]) ||
            !is_string($_SESSION[self::tokenKey]) ||
            !isset($_POST[self::tokenKey]) || 
            !is_string($_POST[self::tokenKey])) {
            return false;   
        }
        // hash_equals prevents timing attacks
        if (hash_equals($_SESSION[self::tokenKey], $_POST[self::tokenKey])) {
            // Tokens are single use
            unset($_SESSION[self::tokenKey]);
            return true;
        }
        return false;
    }

    /**
     * Returns a string representing hidden HTML input field containing the token.
     * If no token is passed, a new one is automatially generated 
     */
    public static function embedToken(?string $token = null) : string {
        if (empty($token)) { $token = self::generateToken(); }
        return sprintf(
            '<input type="hidden" name="%s" value="%s">',
            self::tokenKey,
            htmlspecialchars($token)
        );
    }

}

?>

