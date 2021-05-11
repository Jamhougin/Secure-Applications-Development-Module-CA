<?php
// Initialize the session
require "SanitiseFunctions.php";
header("Content-Security-Policy: frame-ancestors 'none'", false);
header('X-Frame-Options: SAMEORIGIN');
header('X-XSS-Protection: 1; mode=block');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
session_cache_limiter('nocache');
session_start();

if (!isset($_SESSION['last_activity'])){
    $_SESSION['last_activity'] = time();
}

if(time() - $_SESSION['last_activity'] > 600 || time() -$_SESSION["login_time"] > 3600) { 
    
    header("location: logout.php");
    exit;
}
$_SESSION['last_activity'] = time();

// Check if the user is logged in, if not then redirect him to login page
if(!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true){
    header("location: logout.php");
    exit;
}
?>
 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Welcome</title>
    <link rel="stylesheet" href="css/styles.css">
    <style type="text/css">
        body{ font: 14px sans-serif; text-align: center; }
    </style>
</head>
<body>
    <div class="page-header">
        <h1>Hi, <b><?php echo Sanitise($_SESSION["username"]); ?></b>. Welcome to our site.</h1>
        <p><?php echo session_id() ?></p>
    </div>
    <p>
        <a href="logout.php" class="btn btn-danger">Sign Out of Your Account</a>
        <a href="Page2.php" class="btn btn-primary">Page 2</a>
        <a href="AdminPage.php" class="btn btn-primary">Admin Page</a>
        <a href="ResetPassword.php" class="btn btn-warning">Reset Password</a>
    </p>
</body>
</html>