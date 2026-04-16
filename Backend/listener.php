<?php
// ── Config ──────────────────────────────────────────────────────────────────
define('DB_HOST', '10.0.158.186');     // Database VM private IP
define('DB_USER', 'eventhub_user');
define('DB_PASS', 'eventhub_password');
define('DB_NAME', 'eventhub_db');

// ── CORS & Headers ──────────────────────────────────────────────────────────
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");
header("Content-Type: application/json");

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// ── DB Connection ───────────────────────────────────────────────────────────
function getDB() {
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if ($conn->connect_error) {
        http_response_code(500);
        echo json_encode(["message" => "Database connection failed."]);
        exit();
    }
    return $conn;
}

// ── Helper: send JSON response ──────────────────────────────────────────────
function respond($status, $data) {
    http_response_code($status);
    echo json_encode($data);
    exit();
}

// ── Helper: get JSON request body ──────────────────────────────────────────
function getBody() {
    return json_decode(file_get_contents("php://input"), true) ?? [];
}

// ── Router ──────────────────────────────────────────────────────────────────
$method = $_SERVER['REQUEST_METHOD'];
$path   = trim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/');

// Strip a leading directory prefix if the script sits in a subdirectory
// e.g. if URL is /api/register, $path becomes "api/register"
switch (true) {

    // POST /api/register
    case $path === 'api/register' && $method === 'POST':
        handleRegister();
        break;

    // POST /api/login
    case $path === 'api/login' && $method === 'POST':
        handleLogin();
        break;

    // GET /api/users
    case $path === 'api/users' && $method === 'GET':
        handleGetUsers();
        break;

    // GET /api/events
    case $path === 'api/events' && $method === 'GET':
        handleGetEvents();
        break;

    // POST /api/events
    case $path === 'api/events' && $method === 'POST':
        handleCreateEvent();
        break;

    default:
        respond(404, ["message" => "Endpoint not found."]);
}

// ── POST /api/register ──────────────────────────────────────────────────────
function handleRegister() {
    $body = getBody();

    $fullname        = trim($body['fullname']        ?? '');
    $email           = trim($body['email']           ?? '');
    $password        = $body['password']              ?? '';
    $confirmPassword = $body['confirmPassword']       ?? '';
    $role            = trim($body['role']            ?? '');

    // Validation
    if (!$fullname || !$email || !$password || !$confirmPassword || !$role) {
        respond(400, ["message" => "All fields are required."]);
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        respond(400, ["message" => "Invalid email address."]);
    }

    if ($password !== $confirmPassword) {
        respond(400, ["message" => "Passwords do not match."]);
    }

    if (strlen($password) < 6) {
        respond(400, ["message" => "Password must be at least 6 characters."]);
    }

    if ($role === 'admin') {
        respond(403, ["message" => "Admin accounts cannot be self-registered."]);
    }

    if (!in_array($role, ['user', 'host'])) {
        respond(400, ["message" => "Invalid account type selected."]);
    }

    $db = getDB();

    // Check for duplicate email
    $stmt = $db->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        $stmt->close();
        $db->close();
        respond(409, ["message" => "An account with that email already exists."]);
    }
    $stmt->close();

    // Hash password & insert
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

    $stmt = $db->prepare(
        "INSERT INTO users (fullname, email, password, role) VALUES (?, ?, ?, ?)"
    );
    $stmt->bind_param("ssss", $fullname, $email, $hashedPassword, $role);

    if ($stmt->execute()) {
        $stmt->close();
        $db->close();
        respond(201, ["message" => "Registration successful."]);
    } else {
        $stmt->close();
        $db->close();
        respond(500, ["message" => "Could not create account. Please try again."]);
    }
}

// ── POST /api/login ─────────────────────────────────────────────────────────
function handleLogin() {
    $body = getBody();

    $email    = trim($body['email']    ?? '');
    $password = $body['password']       ?? '';

    if (!$email || !$password) {
        respond(400, ["message" => "Email and password are required."]);
    }

    $db = getDB();

    $stmt = $db->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        $stmt->close();
        $db->close();
        // Use a generic message to avoid revealing whether the email exists
        respond(401, ["message" => "Invalid email or password."]);
    }

    $user = $result->fetch_assoc();
    $stmt->close();
    $db->close();

    if (!password_verify($password, $user['password'])) {
        respond(401, ["message" => "Invalid email or password."]);
    }

    // Never send the password back to the client
    respond(200, [
        "message" => "Login successful.",
        "user" => [
            "id"       => $user['id'],
            "fullname" => $user['fullname'],
            "email"    => $user['email'],
            "role"     => $user['role'],
        ]
    ]);
}

// ── GET /api/users ──────────────────────────────────────────────────────────
function handleGetUsers() {
    $db = getDB();

    $result = $db->query(
        "SELECT id, fullname, email, role, created_at FROM users ORDER BY created_at DESC"
    );

    $users = [];
    while ($row = $result->fetch_assoc()) {
        $users[] = $row;
    }

    $db->close();
    respond(200, $users);
}

// ── GET /api/events ─────────────────────────────────────────────────────────
function handleGetEvents() {
    $db = getDB();

    $result = $db->query("SELECT * FROM events ORDER BY date ASC");

    $events = [];
    while ($row = $result->fetch_assoc()) {
        $events[] = $row;
    }

    $db->close();
    respond(200, $events);
}

// ── POST /api/events ────────────────────────────────────────────────────────
function handleCreateEvent() {
    $body = getBody();

    $title       = trim($body['title']       ?? '');
    $date        = trim($body['date']        ?? '');
    $location    = trim($body['location']    ?? '');
    $description = trim($body['description'] ?? '');
    $createdBy   = trim($body['createdBy']   ?? '');

    if (!$title || !$date || !$location || !$description || !$createdBy) {
        respond(400, ["message" => "All event fields are required."]);
    }

    $db = getDB();

    $stmt = $db->prepare(
        "INSERT INTO events (title, date, location, description, createdBy) VALUES (?, ?, ?, ?, ?)"
    );
    $stmt->bind_param("sssss", $title, $date, $location, $description, $createdBy);

    if ($stmt->execute()) {
        $eventId = $stmt->insert_id;
        $stmt->close();
        $db->close();
        respond(201, [
            "message" => "Event created successfully.",
            "eventId" => $eventId
        ]);
    } else {
        $stmt->close();
        $db->close();
        respond(500, ["message" => "Could not create event. Please try again."]);
    }
}
