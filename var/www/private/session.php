<?php

require_once __DIR__ . '/config.php';

class Session {

    /* Session variables */
    const username = "username";
    const userId = "id";
    const lastAccess = "lastAccess";

    /* Equivalent to session_start but with security tweaks to the session cookies and request headers */
    public static function secureStart() : void {    
        session_start([
    	    // Send session cookies only over HTTPS [disabled because the website does not run over HTTPS]
    	    //"cookie_secure" => true,
    	    // Prevents the session id to be passed over anything other than cookies
    	    "use_only_cookies" => true,     
    	    // The session cookie should not be accessible via javascript (XSS counter-measure)
    	    "cookie_httponly" => true,     
    	    // Prevents the browser to send the session cookie if the request comes from a different website (CSRF counter-measure)
    	    "cookie_samesite" => "strict"   
	    ]);

	    // Blocks inline JS and JS coming from different websites (XSS counter-measure)
	    // Also tells the browser that this page can not be displayed inside an iframe (Clickjacking counter-measure)
	    header("Content-Security-Policy: script-src 'self'; frame-ancestors 'none';");

        self::timeoutGuard();
    }

    /* Completely destroys a session and the associated cookie */
    public static function secureDestroy(bool $redirectToLogin = True) : void {

        // A session must be active in order to perform the following steps
        if (session_status() === PHP_SESSION_NONE) { session_start(); }

        // Free the $_SESSION array
        session_unset();
        
        // Invalidates the current session
        session_destroy();
        
        // Deletes the client-side session cookie
        // [Source of the code snippet - official PHP docs:
        //   https://www.php.net/manual/en/function.session-destroy.php]
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }

        if ($redirectToLogin) { header("Location: login.php"); }
    }

    /* Checks that all session variables are set */
    public static function isLoggedIn() : bool {
        return isset(
            $_SESSION[self::username],
            $_SESSION[self::userId],
            $_SESSION[self::lastAccess]
        );
    }
    
    /* Logs out the user if too much time passed from the last request */
    private static function timeoutGuard() : void {
        if (isset($_SESSION[self::lastAccess])) {
	        $lastAccess = $_SESSION[self::lastAccess];
            if (time() - $lastAccess >= Config::sessionTTL) {
                self::secureDestroy(true);
		        exit("Session expired");
	        }
	    }	
	    $_SESSION[self::lastAccess] = time();
    }

}

?>

