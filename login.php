<?php

session_start();
require 'conn.php';

$my_secret_key = "my_secret_key";

if (isset($_SESSION['admin']) || isset($_SESSION['basic'])) {
    header('Location: index.php');
    exit;
}

if (isset($_POST['login'])) {
    $email = $_POST['email'];
    $password = $_POST['password'];

    $stmt = $bdd->prepare("SELECT id, username, email, AES_DECRYPT(password, :my_secret_key) AS password, date FROM users WHERE email = :email");
    $stmt->bindParam(':my_secret_key', $my_secret_key);
    $stmt->bindParam(':email', $email);
    $stmt->execute();

    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user) {
        $decryptedPassword = $user['password'];

        if ($password === $decryptedPassword || password_verify($password, $decryptedPassword)) {
            if (strpos($email, '@admin') !== false) {
                $_SESSION['admin'] = true;
                $_SESSION['basic'] = false;
            } else {
                $_SESSION['admin'] = false;
                $_SESSION['basic'] = true;
            }

            header('Location: index.php');
            exit;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="login.css">
    <title>SGBD - Login</title>
</head>
<body>
    <h1>SGBD - Login Panel</h1>
    <form action="login.php" method="POST">
        <input autocomplete="off" required type="email" name="email" placeholder="Email">
        <input autocomplete="off" required type="password" name="password" placeholder="Password">
        <button type="submit" name="login">Login</button>
    </form>
</body>
</html>
