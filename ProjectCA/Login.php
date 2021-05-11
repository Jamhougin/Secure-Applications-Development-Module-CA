<?php
define('DB_SERVERF', 'localhost');
define('DB_USERNAMEF', 'root');
define('DB_PASSWORDF', '');

$prelink = mysqli_connect(DB_SERVERF, DB_USERNAMEF, DB_PASSWORDF);
$sql = "SELECT SCHEMA_NAME
        FROM INFORMATION_SCHEMA.SCHEMATA
        WHERE SCHEMA_NAME = 'ProjectCA'
        ";

$dbexists = mysqli_query($prelink, $sql);

$sql = "-- phpMyAdmin SQL Dump
-- version 5.0.2
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Mar 03, 2021 at 04:44 PM
-- Server version: 10.4.14-MariaDB
-- PHP Version: 7.2.33

SET SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO';
START TRANSACTION;
SET time_zone = '+00:00';


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `projectca`
--

CREATE DATABASE IF NOT EXISTS `ProjectCA` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
    USE `ProjectCA`;

-- --------------------------------------------------------

--
-- Table structure for table `logins`
--

CREATE TABLE `logins` (
  `ipaddress` char(16) COLLATE utf8_bin NOT NULL,
  `timestamp` timestamp NOT NULL DEFAULT current_timestamp(),
  `success` int(11) DEFAULT NULL,
  `failedattemptscount` int(11) DEFAULT NULL,
  `useragent` varchar(255) COLLATE utf8_bin DEFAULT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

--
-- Dumping data for table `logins`
--

INSERT INTO `logins` (`ipaddress`, `timestamp`, `success`, `failedattemptscount`, `useragent`) VALUES
('127.0.0.1', '2021-02-25 19:37:30', 1, 0, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:85.0) Gecko/20100101 Firefox/85.0'),
('127.0.0.1', '2021-03-03 15:33:02', 1, 0, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0');

-- --------------------------------------------------------

--
-- Table structure for table `login_logs`
--

CREATE TABLE `login_logs` (
  `ip` char(16) DEFAULT NULL,
  `useragent` varchar(255) DEFAULT NULL,
  `success` char(3) DEFAULT NULL,
  `logintime` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `usernameused` varchar(50) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `login_logs`
--

INSERT INTO `login_logs` (`ip`, `useragent`, `success`, `logintime`, `usernameused`) VALUES
('127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0', 'no', '2021-03-03 15:30:21', 'Jamhougin'),
('127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0', 'no', '2021-03-03 15:30:29', 'Jamhougin'),
('127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0', 'yes', '2021-03-03 15:30:34', 'Jamhougin'),
('127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0', 'no', '2021-03-03 15:30:47', 'Jamhougi'),
('127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0', 'yes', '2021-03-03 15:30:54', 'ADMIN'),
('127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0', 'no', '2021-03-03 15:31:44', '&ltbody onload&#61alert(document.cookie)&gt'),
('127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0', 'yes', '2021-03-03 15:33:02', 'ADMIN');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `salt` varchar(255) DEFAULT NULL,
  `isadmin` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `password`, `created_at`, `salt`, `isadmin`) VALUES
(25, 'ADMIN', '\$2y\$10\$GKpye1hE6cCnPh6cZKwdVO7dJP6GqUPFYq7RVJwbY6RB3V70brWIG', '2021-02-25 17:51:39', 'lUizpfrFbK4u8ceBh?SrpSp%1k5B4sMG5MN9FHzJMqdpnDRPTxN5AsXU5tmhxa5G', 1),

--
-- Indexes for dumped tables
--

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=29;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
";
    
mysqli_multi_query($prelink, $sql);

// Initialize the session
require "SanitiseFunctions.php";
header("Content-Security-Policy: frame-ancestors 'none'", false);
header('X-Frame-Options: SAMEORIGIN');
header('X-XSS-Protection: 1; mode=block');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
session_cache_limiter('nocache');
session_start();

// Check if the user is logged in, if yes redirect them to welcome page
if(isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true){
    //session_unset();
    //session_destroy();
    //session_start();
    header("location: welcome.php");
    exit;
}
 
// Include config file
require_once "config.php";
 
// Define variables and initialize with empty values
$username = $password = "";
$username_err = $password_err = "";
 
// Processing form data when form is submitted
if($_SERVER["REQUEST_METHOD"] == "POST"){
 
    // Check if username is empty
    if(empty(trim($_POST["username"]))){
        $username_err = "Please enter username.";
    } else{
        $username = Sanitise(trim($_POST["username"]));
    }
    
    // Check if password is empty
    if(empty(trim($_POST["password"]))){
        $password_err = "Please enter your password.";
    } else{
        $password = trim($_POST["password"]);
    }
    
    // Validate credentials
    if(empty($username_err) && empty($password_err)){
        // Prepare a select statement
        $sql = "SELECT id, username, password, salt, isadmin FROM users WHERE username = ?";
        
        if($stmt = mysqli_prepare($link, $sql)){
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "s", $param_username);
            
            // Set parameters
            $param_username = $username;
            
            // Attempt to execute the prepared statement
            if(mysqli_stmt_execute($stmt)){
                // Store result
                mysqli_stmt_store_result($stmt);
                
                // Check if username exists, if yes then verify password
                if(mysqli_stmt_num_rows($stmt) == 1){                    
                    // Bind result variables
                    mysqli_stmt_bind_result($stmt, $id, $username, $hashed_password, $salt, $isadmin);
                    
                    if(mysqli_stmt_fetch($stmt)){
                        $saltAndPwd = $salt.$password;
                        
                        //Get user agent and ip
                        $useragent = $_SERVER['HTTP_USER_AGENT'];
                        $ip = $_SERVER["REMOTE_ADDR"];
                        
                        //Get number of failed attempts at login
                        $num = mysqli_query($link, "SELECT failedattemptscount FROM logins WHERE ipaddress LIKE '$ip' and useragent LIKE '$useragent' and timestamp = (SELECT MAX(timestamp) FROM logins WHERE ipaddress LIKE '$ip' and useragent LIKE '$useragent')");
                        //Convert to num array
                        $count = mysqli_fetch_array($num, MYSQLI_NUM);
                        //Get last login within previous 3 minutes
                        $lastlog = mysqli_query($link, "SELECT MAX(timestamp) FROM logins WHERE ipaddress LIKE '$ip' and useragent LIKE '$useragent' and timestamp > (now() - interval 3 minute) and failedattemptscount >= 5");
                        //Convert to array
                        $logprint = mysqli_fetch_array($lastlog);
                        
                        //If password is correct and user has not failed login 5 times and 3 minutes has not elapsed
                        if(password_verify($saltAndPwd, $hashed_password) && ($count[0] < 5 || $logprint[0] == "")){
                            //Update logins table
                            mysqli_query($link, "INSERT INTO `logins` (`ipaddress`,`timestamp`,`success`,`failedattemptscount`,`useragent`)VALUES ('$ip',CURRENT_TIMESTAMP,1,0,'$useragent')");
                            mysqli_query($link, "DELETE FROM logins WHERE ipaddress LIKE '$ip' AND useragent LIKE '$useragent' AND timestamp != (SELECT MAX(timestamp) FROM logins WHERE ipaddress LIKE '$ip' AND useragent LIKE '$useragent')");
                            mysqli_query($link, "INSERT INTO `login_logs` (`ip`,`useragent`,`success`,`logintime`,`usernameused`)VALUES ('$ip','$useragent','yes',CURRENT_TIMESTAMP,'$username')");
                            
                            function generateRandomString($length = 26) {
                                $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
                                $charactersLength = strlen($characters);
                                $randomString = '';
                                for ($i = 0; $i < $length; $i++) {
                                    $randomString .= $characters[rand(0, $charactersLength - 1)];
                                    }
                                return $randomString;
                            }
                            // Password is correct, so start a new session
                            session_unset();
                            session_destroy();
                            session_id(generateRandomString(26));
                            session_start();
                            
                            // Store data in session variables
                            $_SESSION["login_time"] = time();
                            $_SESSION["loggedin"] = true;
                            $_SESSION["id"] = $id;
                            $_SESSION["username"] = $username; 
                            $_SESSION["isadmin"] = $isadmin;
                            
                            // Redirect user to welcome page
                            header("location: Welcome.php");
                        //If user has failed 5 times and 3 minutes has not elapsed
                        } elseif(($count[0] >= 5) && ($logprint[0] != "")){
                            mysqli_query($link, "INSERT INTO logins (ipaddress,timestamp,success,failedattemptscount,useragent)VALUES ('$ip',CURRENT_TIMESTAMP,0,((SELECT l1.failedattemptscount FROM logins l1 WHERE l1.ipaddress LIKE '$ip' AND l1.timestamp = (SELECT MAX(l2.timestamp)FROM logins l2 WHERE l2.ipaddress LIKE '$ip'))+1),'$useragent')");
                            mysqli_query($link, "DELETE FROM logins WHERE ipaddress LIKE '$ip' AND useragent LIKE '$useragent' AND timestamp != (SELECT MAX(timestamp) FROM logins WHERE ipaddress LIKE '$ip' AND useragent LIKE '$useragent')");
                            mysqli_query($link, "INSERT INTO `login_logs` (`ip`,`useragent`,`success`,`logintime`,`usernameused`)VALUES ('$ip','$useragent','no',CURRENT_TIMESTAMP,'$username')");
                            $password_err = "Only 5 attempts allowed in 3 minutes. $count[0] $logprint[0]";
                        } else{
                            // Display an error message if password is not valid
                            mysqli_query($link, "INSERT INTO logins (ipaddress,timestamp,success,failedattemptscount,useragent)VALUES ('$ip',CURRENT_TIMESTAMP,0,((select l1.failedattemptscount from logins l1 where l1.ipaddress LIKE '$ip' and l1.timestamp = (SELECT MAX(l2.timestamp)FROM logins l2 WHERE l2.ipaddress LIKE '$ip'))+1),'$useragent')");
                            mysqli_query($link, "INSERT INTO `login_logs` (`ip`,`useragent`,`success`,`logintime`,`usernameused`)VALUES ('$ip','$useragent','no',CURRENT_TIMESTAMP,'$username')");
                            $password_err = "The username $username and password you entered could not be authenticated. $count[0]";
                        }
                    }
                } else{
                    $useragent = $_SERVER['HTTP_USER_AGENT'];
                    $ip = $_SERVER["REMOTE_ADDR"];
                    mysqli_query($link, "INSERT INTO `login_logs` (`ip`,`useragent`,`success`,`logintime`,`usernameused`)VALUES ('$ip','$useragent','no',CURRENT_TIMESTAMP,'$username')");
                    // Display an error message if username doesn't exist
                    $username_err = "No account found with that username.";
                }
            } else{
                echo "Oops! Something went wrong. Please try again later.";
            }

            // Close statement
            mysqli_stmt_close($stmt);
        }
    }
    
    // Close connection
    mysqli_close($link);
}
?>
 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="css/styles.css">
    <style type="text/css">
        body{ font: 14px sans-serif; }
        .wrapper{ width: 350px; padding: 20px; }
    </style>
</head>
<body>
    <div class="wrapper">
        <h2>Login</h2>
        <p>Please fill in your username and password to login.</p>
        <!-- <p><?php// echo session_id() ?></p> -->
        <form action="<?php echo Sanitise($_SERVER["PHP_SELF"]); ?>" method="post">
            <div class="form-group <?php echo (!empty($username_err)) ? 'has-error' : ''; ?>">
                <label>Username</label>
                <input type="text" name="username" class="form-control" value="<?php echo Sanitise($username); ?>">
                <span class="help-block"><?php echo $username_err; ?></span>
            </div>    
            <div class="form-group <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">
                <label>Password</label>
                <input type="password" name="password" class="form-control">
                <span class="help-block"><?php echo $password_err; ?></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Login">
            </div>
            <p>New here? <a href="register.php">Register</a>.</p>
        </form>
    </div>    
</body>
</html>