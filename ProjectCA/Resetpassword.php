<?php
// Initialize the session
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
 
// Check if the user is logged in, if not then redirect to login page
if(!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true){
    header("location: logout.php");
    exit;
}

// Include config file
require "SanitiseFunctions.php";
require_once "config.php";
 
// Define variables and initialize with empty values
$new_password = $confirm_password = "";
$new_password_err = $confirm_password_err = "";
 
// Processing form data when form is submitted
if(isset($_GET["new_password"])&&isset($_GET["confirm_password"])&&(isset($_GET["token"]))){
    if(($_GET["token"])==($_SESSION["CSRF_Token"])){

        // Validate new password ///////////////
        //Enter characters you want to check for
        $correctPassword = false;

        $uppercase = preg_match('@[A-Z]@', $_GET["new_password"]);
        $lowercase = preg_match('@[a-z]@', $_GET["new_password"]);
        $number    = preg_match('@[0-9]@', $_GET["new_password"]);
        $specialChars = preg_match('@[^\w]@', $_GET["new_password"]);

        if($uppercase && $lowercase && $number && $specialChars) {

            $correctPassword = true;
        }

        if(empty(trim($_GET["new_password"]))){
            $new_password_err = "Please enter the new password.";     
        } elseif(strlen(trim($_GET["new_password"])) < 6){
            $new_password_err = "Password must have atleast 6 characters.";
        } elseif($correctPassword == false){
            $new_password_err = "Password must contain at least 1 upper and lowercase letter, 1 number and 1 special character";
        } else{
            $new_password = trim(Sanitise($_GET["new_password"]));
        }

        // Validate confirm password
        if(empty(trim($_GET["confirm_password"]))){
            $confirm_password_err = "Please confirm the password.";
        } else{
            $confirm_password = trim(Sanitise($_GET["confirm_password"]));
            if(empty($new_password_err) && ($new_password != $confirm_password)){
                $confirm_password_err = "Password did not match.";
            }
        }

        // Check input errors before updating the database
        if(empty($new_password_err) && empty($confirm_password_err)){

            //Function to generate salt
            function generateRandomString($length = 64) {
                $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ?*%';
                $charactersLength = strlen($characters);
                $randomString = '';
                for ($i = 0; $i < $length; $i++) {
                    $randomString .= $characters[rand(0, $charactersLength - 1)];
                    }
                return $randomString;
            }
            //Create salt
            $salt = generateRandomString(64);

            // Prepare an update statement
            $sql = "UPDATE users SET password = ?, salt = ? WHERE id = ?";

            if($stmt = mysqli_prepare($link, $sql)){
                // Bind variables to the prepared statement as parameters
                mysqli_stmt_bind_param($stmt, "ssi", $param_password, $salt, $param_id);

                // Set parameters
                
                $saltAndPwd = $salt.$new_password;
                $param_password = password_hash($saltAndPwd, PASSWORD_DEFAULT);
                $param_id = $_SESSION["id"];

                // Attempt to execute the prepared statement
                if(mysqli_stmt_execute($stmt)){
                    header("location: logout.php");
                    exit();
                } else{
                    $confirm_password_err = "Oops! Something went wrong. Please try again later.";
                }

                // Close statement
                mysqli_stmt_close($stmt);
            }
        }

        // Close connection
        mysqli_close($link);
    } else {
        $confirm_password_err = "Oops! Something went wrong. Please try again later.";
        //header("location: logout.php");
        //exit();
    }
    
}
?>
 
<!DOCTYPE html>
<html lang="en">
<head>
    <?php $_SESSION["CSRF_Token"] = base64_encode(openssl_random_pseudo_bytes(64)); ?>
    <meta charset="UTF-8">
    <title>Reset Password</title>
    <link rel="stylesheet" href="css/styles.css">
    <style type="text/css">
        body{ font: 14px sans-serif; }
        .wrapper{ width: 350px; padding: 20px; }
    </style>
</head>
<body>
    <div class="wrapper">
        <h2>Reset Password</h2>
        <p>Please fill out this form to reset your password.</p>
        <p><?php echo session_id() ?></p>
        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="GET"> 
            <div class="form-group <?php echo (!empty($new_password_err)) ? 'has-error' : ''; ?>">
                <label>New Password</label>
                <input type="password" name="new_password" class="form-control" value="<?php echo $new_password; ?>">
                <span class="help-block"><?php echo $new_password_err; ?></span>
            </div>
            <div class="form-group <?php echo (!empty($confirm_password_err)) ? 'has-error' : ''; ?>">
                <label>Confirm Password</label>
                <input type="password" name="confirm_password" class="form-control">
                <span class="help-block"><?php echo $confirm_password_err; ?></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Submit">
                <input type="hidden" name="token" value="<?= $_SESSION['CSRF_Token'] ?>">
                <a class="btn btn-link" href="Welcome.php">Cancel</a>
            </div>
        </form>
    </div>    
</body>
</html>