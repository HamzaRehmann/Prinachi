<?php
session_start();

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    $email = $_POST['email'];
    $password = $_POST['password'];

    // Database connection
    $conn = new mysqli('localhost', 'root', '', 'prinachi_db');

    // Check connection
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    // Sanitize input (email)
    $email = $conn->real_escape_string($email);

    // Prepare a SQL statement (prevents SQL injection)
    $sql = "SELECT * FROM users WHERE email=?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param('s', $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        if (password_verify($password, $row['password'])) {
            // Set session variable
            $_SESSION['user_id'] = $row['id'];
            header("Location: index.html"); // Redirect to homepage
            exit();
        } else {
            $error = "Login failed. Please try again."; // Generic error message
        }
    } else {
        $error = "Login failed. Please try again."; // Generic error message
    }

    $stmt->close();
    $conn->close();
}
?>