<?php
$servername = "db";
$username = "root";
$password = "";
$dbname = "vulnerable";

$conn = new mysqli($servername, $username, $password, $dbname);
if ($conn->connect_error) {
    die("DB connection failed: " . $conn->connect_error);
}
?>