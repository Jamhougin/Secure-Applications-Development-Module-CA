<?php
// Initialize the session
header("Content-Security-Policy: frame-ancestors 'none'", false);
header('X-Frame-Options: SAMEORIGIN');
header('X-XSS-Protection: 1; mode=block');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
session_cache_limiter('nocache');
session_start();
 
// Unset all of the session variables
$_SESSION = array();

function generateRandomString($length = 26) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
        }
    return $randomString;
}

// Destroy the session.
session_unset();
session_destroy();
session_id(generateRandomString(26));
session_start();
 
// Redirect to login page
header("location: login.php");
exit;
?>