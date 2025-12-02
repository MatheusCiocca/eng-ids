<?php
include("db.php");

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $user = $_POST["user"];
    $pass = $_POST["pass"];

    // VULNERÁVEL: concatenação direta da entrada do usuário
    $sql = "SELECT * FROM users WHERE username='$user' AND password='$pass'";
    $result = $conn->query($sql);

    if ($result && $result->num_rows > 0) {
        echo "<h2>Welcome, $user!</h2>";
    } else {
        echo "<h2>Login failed!</h2>";
    }
}
?>

<form method="POST">
    <input type="text" name="user" placeholder="Username"><br>
    <input type="password" name="pass" placeholder="Password"><br>
    <button type="submit">Login</button>
</form>