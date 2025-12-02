<?php
include("db.php");

if (isset($_GET['q'])) {
    $q = $_GET['q'];
    // vulnerável a SQLi + carga pesada simulando busca
    $sql = "SELECT * FROM users WHERE username LIKE '%$q%'";
    $result = $conn->query($sql);
    usleep(100000); // delay para simular carga (100ms)
    echo "<h3>Results for '$q':</h3>";
    if ($result && $result->num_rows > 0) {
        while ($row = $result->fetch_assoc()) {
            echo "<p>User: " . $row['username'] . "</p>";
        }
    } else {
        echo "<p>No results.</p>";
    }
} else {
    echo '<form><input name="q" placeholder="Search user..."><button>Search</button></form>';
}
?>