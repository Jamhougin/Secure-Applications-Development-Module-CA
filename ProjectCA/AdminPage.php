<?php
// Initialize the session
require "SanitiseFunctions.php";
require_once "config.php";
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

if($_SESSION['isadmin'] != 1){
    header("location: Welcome.php");
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
        <h1>Hi, <b><?php echo Sanitise($_SESSION["username"]); ?></b>. These are the super secret log files.</h1>
    </div>
    <p>
        <a href="logout.php" class="btn btn-danger">Sign Out of Your Account</a>
        <a href="Welcome.php" class="btn btn-primary">Welcome</a>
        <a href="Page2.php" class="btn btn-primary">Page 2</a>
        <a href="ResetPassword.php" class="btn btn-warning">Reset Password</a>
    </p>
    <li>
        <?php 
        $sql = "SELECT ip, useragent, success, logintime, usernameused FROM login_logs ORDER BY logintime DESC";
        //$result = mysqli_query($link, $sql);
        
        if($result = $link->query($sql)){

        echo '<table class="table" border="0" cellspacing="2" cellpadding="2"> 
              <tr> 
                  <td> <font face="Arial">IP Address</font> </td> 
                  <td> <font face="Arial">User Agent</font> </td> 
                  <td> <font face="Arial">Successful</font> </td> 
                  <td> <font face="Arial">Login Time</font> </td> 
                  <td> <font face="Arial">Username</font> </td> 
              </tr>';

            while ($row = $result->fetch_assoc()) {
                $ipadd = $row["ip"];
                $useradd = $row["useragent"];
                $success = $row["success"];
                $logintime = $row["logintime"];
                $nameused = $row["usernameused"]; 

                echo '<tr> 
                          <td>'.$ipadd.'</td> 
                          <td>'.$useradd.'</td> 
                          <td>'.$success.'</td> 
                          <td>'.$logintime.'</td> 
                          <td>'.$nameused.'</td> 
                      </tr>';
            }
            $result->free();
        }
        ?>
    </li>
    
</body>
</html>