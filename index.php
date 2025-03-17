<?php
session_start();
require 'conn.php';

if (!isset($_SESSION['admin']) || !isset($_SESSION['basic'])) {
    header('Location: login.php');
    exit;
}

$my_secret_key = "my_secret_key";

if ($_SESSION['admin'] === true) {
    $stmt = $bdd->prepare("SELECT id, username, email, AES_DECRYPT(password, :my_secret_key) AS password, date FROM users");
    $stmt->bindParam(':my_secret_key', $my_secret_key);
} else {
    $stmt = $bdd->prepare("SELECT id, username, email, password, date FROM users");
}

$stmt->execute();

$users = $stmt->fetchAll(PDO::FETCH_ASSOC);


if (isset($_POST['delete'])) {
    $id = $_POST['id'];

    $stmt = $bdd->prepare("SELECT username FROM users WHERE id = ?");
    $stmt->execute([$id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user) {
        $_SESSION['username_delete'] = $user['username']; 
    }

    $stmt = $bdd->prepare("DELETE FROM users WHERE id = ?");
    $stmt->execute([$id]);

    header('Location: index.php');
    exit;
}


if (isset($_POST['add_user'])) {
    $user = $_POST['username'];
    $email = $_POST['email'];
    $password = $_POST['password'];

    $stmt = $bdd->prepare("INSERT INTO users (username, email, password) VALUES (:username, :email, AES_ENCRYPT(:password, :my_secret_key))");
    $stmt->bindParam(':username', $user);
    $stmt->bindParam(':email', $email);
    $stmt->bindParam(':password', $password);
    $stmt->bindParam(':my_secret_key', $my_secret_key);
    $stmt->execute();

    header('Location: index.php');
    exit;
}

if (isset($_POST['update_user'])) {
    $id = $_POST['select_id'];
    $user = $_POST['username'];
    $email = $_POST['email'];
    $password = $_POST['password'];

    $stmt = $bdd->prepare("UPDATE users SET username = :username, email = :email, password = AES_ENCRYPT(:password, :my_secret_key) WHERE id = :id");
    $stmt->bindParam(':username', $user);
    $stmt->bindParam(':email', $email);
    $stmt->bindParam(':password', $password);
    $stmt->bindParam(':my_secret_key', $my_secret_key);
    $stmt->bindParam(':id', $id);
    $stmt->execute();

    $_SESSION['username_update'] = $user;

    header('Location: index.php');
    exit;
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.7.2/css/all.min.css" integrity="sha512-Evv84Mr4kqVGRNSgIGL/F/aIDqQb7xQ2vcrdIwxfjThSH8CSR7PBEakCr51Ck+w+/U6swU2Im1vVX0SVk9ABhg==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    <title>SGBD - Index</title>
    <link rel="stylesheet" href="style.css">
</head>
<body style="flex-direction: column;">
    <h2>SGBD - <?php echo $_SESSION['admin'] === true ? 'Admin' : 'Basic' ?> Panel</h2>
<div class="table_component" role="region" tabindex="0">
    <table>
        <caption>
            <p>User Account: <em><?= count($users) ?></em></p>
            <p>Last User Added: <em><?= count($users) > 0 ? htmlspecialchars($users[count($users) - 1]['username']) : '' ?></em></p>
            <p>Last User Updated : <em><?php echo isset($_SESSION['username_update']) ? $_SESSION['username_update'] : 'none'; ?></em></p>
            <p>Last User Deleted : <em><?php echo isset($_SESSION['username_delete']) ? $_SESSION['username_delete'] : 'none'; ?></em> </p>
        </caption>
        <thead>
            <tr>
                <th>id</th>
                <th>username</th>
                <th>email</th>
                <th>password</th>
                <th>date</th>
                <th class="trash">action</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <form method="POST">
                    <td><input autocomplete="off" required type="text" name="id" value="<?= count($users) + 1 ?>" id="id" disabled></td>
                    <td><input autocomplete="off" required type="text" placeholder="Add a username" name="username" id="username"></td>
                    <td><input autocomplete="off" required type="email" placeholder="Add an email" name="email" id="email"></td>
                    <td><input autocomplete="off" required type="password" placeholder="Add a password" name="password" id="password"></td>
                    <td><input autocomplete="off" required value="" type="text" disabled name="date" id="date"></td>
                    <td><button type="submit" name="add_user" style="background-color: transparent; border: none; cursor: pointer;">Add <i class="fa-solid fa-plus"></i></button></td>
                </form>
            </tr>
            <?php if($_SESSION['admin'] === true) : ?>
            <tr>
                <form method="POST">
                    <td>
                        <select name="select_id" id="select_id" style="border: none; outline: none;">
                            <option selected disabled value="1">Select a user</option>
                            <?php foreach ($users as $user) : ?>
                                <option value="<?= $user['id'] ?>"><?= $user['id'] ?></option>
                            <?php endforeach; ?>
                        </select>
                    </td>
                    <td><input value="" autocomplete="off" required type="text" placeholder="Update a username" name="username" id="username_update"></td>
                    <td><input value="" autocomplete="off" required type="email" placeholder="Update an email" name="email" id="email_update"></td>
                    <td><input value="" autocomplete="off" required type="text" placeholder="Update a password" name="password" id="password_update"></td>
                    <td></td>
                    <td><button type="submit" name="update_user" style="background-color: transparent; border: none; cursor: pointer;">Update <i class="fa-solid fa-pencil"></i></button></td>
                </form>
            </tr>
            <?php endif;  ?>
            <?php foreach ($users as $user) : ?>
                <tr>
                    <td><?= $user['id'] ?></td>
                    <td><?= htmlspecialchars($user['username']) ?></td>
                    <td><?= htmlspecialchars($user['email']) ?></td>
                    <td><?= htmlspecialchars($user['password']) ?></td>
                    <td><?= htmlspecialchars($user['date']) ?></td>
                    <td style="cursor: pointer;">
                        <?php if($_SESSION['admin'] === true) : ?>
                        <form method="POST">
                            <input type="hidden" name="id" value="<?= htmlspecialchars($user['id']) ?>">
                            <button type="submit" name="delete" class="trash_btn"><i class="fa-solid fa-trash"></i></button>
                        </form>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    <button class="logout_btn"><a href="logout.php">Logout</a></button>
</div>
</body>
<script>
    const inputDate = document.querySelector('#date');
    const date = new Date();
    inputDate.value = `${date.getFullYear()}-${date.getMonth() + 1}-${date.getDate()}`;

    document.getElementById("select_id").addEventListener("change", function () {
    let userId = this.value;

    if (userId) {
        let users = <?= json_encode($users) ?>;
        let selectedUser = users.find(user => user.id == userId);

        if (selectedUser) {
            localStorage.setItem("selectedUser", JSON.stringify(selectedUser));

            document.getElementById("username_update").value = selectedUser.username || "";
            document.getElementById("email_update").value = selectedUser.email || "";
            document.getElementById("password_update").value = selectedUser.password || ""; 
        }
    }
});

    document.querySelector("form").addEventListener("submit", function () {
        localStorage.removeItem("selectedUserId");
    });

    window.addEventListener("load", function () {
        let storedUserId = localStorage.getItem("selectedUserId");
        if (storedUserId) {
            document.getElementById("select_id").value = storedUserId;
        }
    });
</script>
</html>