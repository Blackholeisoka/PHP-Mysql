<?php
require 'conn.php';

if (isset($_POST['id'])) {
    $id = $_POST['id'];

    $stmt = $bdd->prepare("SELECT id, username, email FROM users WHERE id = ?");
    $stmt->execute([$id]);
    $userInput = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($userInput) {
        $_SESSION['selected_user'] = $userInput;
    }
    exit;
}
?>
