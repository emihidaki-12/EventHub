<?php
// ── Config (all secrets live in config.php, which is gitignored) ────────────
require_once __DIR__ . '/config.php';

// ── CORS & Headers ──────────────────────────────────────────────────────────
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");
header("Content-Type: application/json");

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

// ── Helpers ──────────────────────────────────────────────────────────────────
function respond($status, $data) {
    http_response_code($status);
    echo json_encode($data);
    exit();
}

function getBody() {
    return json_decode(file_get_contents("php://input"), true) ?? [];
}

// ── Router ──────────────────────────────────────────────────────────────────
$method = $_SERVER['REQUEST_METHOD'];
$path   = trim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/');

switch (true) {

    case $path === 'api/register' && $method === 'POST':
        handleRegister();
        break;

    case $path === 'api/login' && $method === 'POST':
        handleLogin();
        break;

    case $path === 'api/verify-otp' && $method === 'POST':
        handleVerifyOTP();
        break;

    case $path === 'api/resend-otp' && $method === 'POST':
        handleResendOTP();
        break;

    case $path === 'api/users' && $method === 'GET':
        handleGetUsers();
        break;

    case $path === 'api/events' && $method === 'GET':
        handleGetEvents();
        break;

    case $path === 'api/events' && $method === 'POST':
        handleCreateEvent();
        break;

    case (bool)preg_match('/^api\/events\/(\d+)$/', $path, $m) && $method === 'GET':
        handleGetEvent((int)$m[1]);
        break;

    case (bool)preg_match('/^api\/events\/(\d+)$/', $path, $m) && $method === 'PUT':
        handleUpdateEvent((int)$m[1]);
        break;

    // GET /api/events/{id}/summary  (AI-generated event summary)
    case (bool)preg_match('/^api\/events\/(\d+)\/summary$/', $path, $m) && $method === 'GET':
        handleGetEventSummary((int)$m[1]);
        break;

    // POST /api/ai/chat  (AI event-discovery assistant)
    case $path === 'api/ai/chat' && $method === 'POST':
        handleAIChat();
        break;

    case $path === 'api/attendance' && $method === 'GET':
        handleGetAttendance();
        break;

    case $path === 'api/attendance' && $method === 'POST':
        handleAddAttendance();
        break;

    case $path === 'api/attendance' && $method === 'DELETE':
        handleRemoveAttendance();
        break;

    default:
        respond(404, ["message" => "Endpoint not found."]);
}

// ── POST /api/register ───────────────────────────────────────────────────────
function handleRegister() {
    $body = getBody();

    $fullname        = trim($body['fullname']        ?? '');
    $email           = trim($body['email']           ?? '');
    $password        = $body['password']              ?? '';
    $confirmPassword = $body['confirmPassword']       ?? '';
    $role            = trim($body['role']            ?? '');

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

    $stmt = $db->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();
    if ($stmt->num_rows > 0) {
        $stmt->close(); $db->close();
        respond(409, ["message" => "An account with that email already exists."]);
    }
    $stmt->close();

    $hashed = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    $stmt   = $db->prepare("INSERT INTO users (fullname, email, password, role) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $fullname, $email, $hashed, $role);

    if ($stmt->execute()) {
        $stmt->close(); $db->close();
        respond(201, ["message" => "Registration successful."]);
    } else {
        $stmt->close(); $db->close();
        respond(500, ["message" => "Could not create account. Please try again."]);
    }
}

// ── POST /api/login ──────────────────────────────────────────────────────────
// Validates password, generates OTP, sends email. Does NOT return user data yet.
function handleLogin() {
    $body     = getBody();
    $email    = trim($body['email']    ?? '');
    $password = $body['password']       ?? '';

    if (!$email || !$password) {
        respond(400, ["message" => "Email and password are required."]);
    }

    $db   = getDB();
    $stmt = $db->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        $stmt->close(); $db->close();
        respond(401, ["message" => "Invalid email or password."]);
    }

    $user = $result->fetch_assoc();
    $stmt->close();

    if (!password_verify($password, $user['password'])) {
        $db->close();
        respond(401, ["message" => "Invalid email or password."]);
    }

    // Invalidate any previous unused OTPs for this user
    $stmt = $db->prepare("UPDATE otp_tokens SET used = 1 WHERE user_id = ? AND used = 0");
    $stmt->bind_param("i", $user['id']);
    $stmt->execute();
    $stmt->close();

    // Generate and store new OTP
    $otp     = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    $expires = date('Y-m-d H:i:s', time() + OTP_TTL);

    $stmt = $db->prepare("INSERT INTO otp_tokens (user_id, token, expires_at) VALUES (?, ?, ?)");
    $stmt->bind_param("iss", $user['id'], $otp, $expires);
    $stmt->execute();
    $stmt->close();
    $db->close();

    // Send OTP email
    if (!sendOTPEmail($user['email'], $user['fullname'], $otp)) {
        respond(500, ["message" => "Could not send verification email. Please try again."]);
    }

    respond(200, [
        "status" => "otp_sent",
        "userId" => (int)$user['id'],
        "message" => "Verification code sent to your email."
    ]);
}

// ── POST /api/verify-otp ─────────────────────────────────────────────────────
function handleVerifyOTP() {
    $body   = getBody();
    $userId = (int)($body['userId'] ?? 0);
    $token  = trim($body['token']   ?? '');

    if (!$userId || !$token) {
        respond(400, ["message" => "userId and token are required."]);
    }

    $db   = getDB();
    $stmt = $db->prepare(
        "SELECT id FROM otp_tokens
         WHERE user_id = ? AND token = ? AND used = 0 AND expires_at > NOW()
         ORDER BY created_at DESC LIMIT 1"
    );
    $stmt->bind_param("is", $userId, $token);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        $stmt->close(); $db->close();
        respond(401, ["message" => "Invalid or expired code. Please try again."]);
    }

    $otpRow = $result->fetch_assoc();
    $stmt->close();

    // Mark OTP as used
    $stmt = $db->prepare("UPDATE otp_tokens SET used = 1 WHERE id = ?");
    $stmt->bind_param("i", $otpRow['id']);
    $stmt->execute();
    $stmt->close();

    // Fetch user to return
    $stmt = $db->prepare("SELECT id, fullname, email, role FROM users WHERE id = ?");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $result = $stmt->get_result();
    $user   = $result->fetch_assoc();
    $stmt->close();
    $db->close();

    respond(200, [
        "message" => "Login successful.",
        "user" => [
            "id"       => (int)$user['id'],
            "fullname" => $user['fullname'],
            "email"    => $user['email'],
            "role"     => $user['role'],
        ]
    ]);
}

// ── POST /api/resend-otp ─────────────────────────────────────────────────────
function handleResendOTP() {
    $body   = getBody();
    $userId = (int)($body['userId'] ?? 0);

    if (!$userId) {
        respond(400, ["message" => "userId is required."]);
    }

    $db   = getDB();
    $stmt = $db->prepare("SELECT fullname, email FROM users WHERE id = ?");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        $stmt->close(); $db->close();
        respond(404, ["message" => "User not found."]);
    }

    $user = $result->fetch_assoc();
    $stmt->close();

    // Invalidate existing OTPs
    $stmt = $db->prepare("UPDATE otp_tokens SET used = 1 WHERE user_id = ? AND used = 0");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $stmt->close();

    // Generate new OTP
    $otp     = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    $expires = date('Y-m-d H:i:s', time() + OTP_TTL);

    $stmt = $db->prepare("INSERT INTO otp_tokens (user_id, token, expires_at) VALUES (?, ?, ?)");
    $stmt->bind_param("iss", $userId, $otp, $expires);
    $stmt->execute();
    $stmt->close();
    $db->close();

    if (!sendOTPEmail($user['email'], $user['fullname'], $otp)) {
        respond(500, ["message" => "Could not send verification email."]);
    }

    respond(200, ["message" => "New code sent to your email."]);
}

// ── Anthropic Claude Helper ──────────────────────────────────────────────────
function callClaude($systemPrompt, $messages, $maxTokens = 512) {
    if (!ANTHROPIC_API_KEY || ANTHROPIC_API_KEY === 'YOUR_ANTHROPIC_API_KEY') {
        return null;
    }

    $payload = json_encode([
        'model'      => 'claude-haiku-4-5-20251001',
        'max_tokens' => $maxTokens,
        'system'     => $systemPrompt,
        'messages'   => $messages,
    ]);

    $ch = curl_init('https://api.anthropic.com/v1/messages');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_HTTPHEADER     => [
            'Content-Type: application/json',
            'x-api-key: ' . ANTHROPIC_API_KEY,
            'anthropic-version: 2023-06-01',
        ],
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode !== 200) return null;

    $data = json_decode($response, true);
    return $data['content'][0]['text'] ?? null;
}

// ── GET /api/events/{id}/summary ─────────────────────────────────────────────
function handleGetEventSummary($id) {
    $db   = getDB();
    $stmt = $db->prepare("SELECT * FROM events WHERE id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        $stmt->close(); $db->close();
        respond(404, ["message" => "Event not found."]);
    }

    $event = $result->fetch_assoc();
    $stmt->close();

    // Return cached summary if it already exists
    if (!empty($event['ai_summary'])) {
        $db->close();
        respond(200, ["summary" => $event['ai_summary']]);
    }

    // Generate a new summary via Claude
    $system = "You are an event copywriter. Write engaging, concise summaries that make people excited to attend.";
    $prompt = "Write a 2-3 sentence engaging summary for this event. Highlight what makes it exciting and who would enjoy it.\n\n"
            . "Title: {$event['title']}\n"
            . "Date: {$event['date']}\n"
            . "Location: {$event['location']}\n"
            . "Description: {$event['description']}";

    $summary = callClaude($system, [['role' => 'user', 'content' => $prompt]], 200);

    if (!$summary) {
        $db->close();
        respond(503, ["message" => "AI summary unavailable. Please try again later."]);
    }

    // Cache in the database so future requests are instant
    $stmt = $db->prepare("UPDATE events SET ai_summary = ? WHERE id = ?");
    $stmt->bind_param("si", $summary, $id);
    $stmt->execute();
    $stmt->close();
    $db->close();

    respond(200, ["summary" => $summary]);
}

// ── POST /api/ai/chat ────────────────────────────────────────────────────────
function handleAIChat() {
    $body    = getBody();
    $message = trim($body['message'] ?? '');
    $history = $body['history']      ?? [];

    if (!$message) {
        respond(400, ["message" => "message is required."]);
    }

    // Fetch all events to give the AI full context
    $db     = getDB();
    $result = $db->query("SELECT title, date, location, description, status FROM events ORDER BY date ASC");
    $events = [];
    while ($row = $result->fetch_assoc()) $events[] = $row;
    $db->close();

    $eventsList = "";
    foreach ($events as $i => $e) {
        $n = $i + 1;
        $eventsList .= "{$n}. {$e['title']} — {$e['date']}, {$e['location']} [{$e['status']}]\n"
                     . "   {$e['description']}\n\n";
    }
    if (!$eventsList) $eventsList = "No events are currently listed.";

    $system = "You are a friendly EventHub assistant helping users discover events they will love. "
            . "Here are all current events on the platform:\n\n"
            . $eventsList
            . "Help users find events matching their interests. Be warm and conversational. "
            . "When recommending events mention their title, date, and location. "
            . "If nothing matches perfectly, suggest the closest option or encourage checking back soon. "
            . "Keep every reply under 120 words.";

    // Build the conversation: prior history + the new user message
    $messages = [];
    foreach ($history as $h) {
        if (in_array($h['role'] ?? '', ['user', 'assistant']) && isset($h['content'])) {
            $messages[] = ['role' => $h['role'], 'content' => (string)$h['content']];
        }
    }
    // Cap history at last 10 messages to stay within token limits
    $messages   = array_slice($messages, -10);
    $messages[] = ['role' => 'user', 'content' => $message];

    $reply = callClaude($system, $messages, 400);

    if (!$reply) {
        respond(503, ["message" => "AI assistant unavailable. Please try again later."]);
    }

    respond(200, ["reply" => $reply]);
}

// ── Gmail SMTP Email Sender ──────────────────────────────────────────────────
function sendOTPEmail($toEmail, $fullname, $otp) {
    $firstName = explode(' ', trim($fullname))[0];

    $context = stream_context_create([
        'ssl' => [
            'verify_peer'      => false,
            'verify_peer_name' => false,
        ]
    ]);

    $sock = @stream_socket_client(
        'ssl://' . SMTP_HOST . ':' . SMTP_PORT,
        $errno, $errstr, 15,
        STREAM_CLIENT_CONNECT,
        $context
    );

    if (!$sock) return false;

    stream_set_timeout($sock, 15);

    // Read one full SMTP response (handles multi-line responses like EHLO)
    $read = function() use ($sock) {
        $out = '';
        while (($line = fgets($sock, 515)) !== false) {
            $out .= $line;
            // Last line of an SMTP response has a space at position 3, not a dash
            if (strlen($line) < 4 || $line[3] === ' ') break;
        }
        return $out;
    };

    $cmd = function($c) use ($sock, $read) {
        fwrite($sock, $c . "\r\n");
        return $read();
    };

    $read();                                    // 220 greeting
    $ehlo = $cmd("EHLO localhost");
    if (substr($ehlo, 0, 3) !== '250') { fclose($sock); return false; }

    $cmd("AUTH LOGIN");
    $cmd(base64_encode(SMTP_USER));
    $auth = $cmd(base64_encode(SMTP_PASS));
    if (substr($auth, 0, 3) !== '235') { fclose($sock); return false; }

    $cmd("MAIL FROM:<" . SMTP_USER . ">");
    $cmd("RCPT TO:<{$toEmail}>");
    $cmd("DATA");                               // server replies 354

    $html = "
    <div style='font-family:Arial,sans-serif;background:#f5efe6;padding:40px 20px;'>
      <div style='max-width:480px;margin:0 auto;background:#fffaf5;border-radius:24px;
                  padding:40px 36px;box-shadow:0 8px 24px rgba(0,0,0,0.08);'>
        <h2 style='color:#e4574f;margin:0 0 6px;font-size:1.6rem;'>EventHub Verification</h2>
        <p style='color:#7a5a58;margin:0 0 28px;font-size:1rem;line-height:1.6;'>
          Hey, {$firstName}! Here is your one-time login code:
        </p>
        <div style='background:#f5efe6;border-radius:18px;padding:28px;text-align:center;margin-bottom:28px;'>
          <span style='font-size:3rem;font-weight:bold;letter-spacing:16px;color:#e4574f;'>
            {$otp}
          </span>
        </div>
        <p style='color:#7a5a58;font-size:0.88rem;margin:0;line-height:1.6;'>
          This code expires in <strong>10 minutes</strong>.<br>
          If you did not try to log in, you can safely ignore this email.
        </p>
      </div>
    </div>";

    $msg = "From: EventHub <" . SMTP_USER . ">\r\n"
         . "To: {$fullname} <{$toEmail}>\r\n"
         . "Subject: Your EventHub Verification Code\r\n"
         . "MIME-Version: 1.0\r\n"
         . "Content-Type: text/html; charset=UTF-8\r\n"
         . "\r\n"
         . $html
         . "\r\n.\r\n";

    fwrite($sock, $msg);
    $sent = $read();                            // 250 OK
    $cmd("QUIT");
    fclose($sock);

    return substr($sent, 0, 3) === '250';
}

// ── GET /api/users ───────────────────────────────────────────────────────────
function handleGetUsers() {
    $db     = getDB();
    $result = $db->query("SELECT id, fullname, email, role, created_at FROM users ORDER BY created_at DESC");
    $users  = [];
    while ($row = $result->fetch_assoc()) $users[] = $row;
    $db->close();
    respond(200, $users);
}

// ── GET /api/events ──────────────────────────────────────────────────────────
function handleGetEvents() {
    $db     = getDB();
    $result = $db->query("SELECT * FROM events ORDER BY date ASC");
    $events = [];
    while ($row = $result->fetch_assoc()) {
        $row['id'] = (int)$row['id'];
        $events[]  = $row;
    }
    $db->close();
    respond(200, $events);
}

// ── GET /api/events/{id} ─────────────────────────────────────────────────────
function handleGetEvent($id) {
    $db   = getDB();
    $stmt = $db->prepare("SELECT * FROM events WHERE id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        $stmt->close(); $db->close();
        respond(404, ["message" => "Event not found."]);
    }

    $row       = $result->fetch_assoc();
    $row['id'] = (int)$row['id'];
    $stmt->close();
    $db->close();
    respond(200, $row);
}

// ── POST /api/events ─────────────────────────────────────────────────────────
function handleCreateEvent() {
    $body        = getBody();
    $title       = trim($body['title']       ?? '');
    $date        = trim($body['date']        ?? '');
    $location    = trim($body['location']    ?? '');
    $description = trim($body['description'] ?? '');
    $createdBy   = trim($body['createdBy']   ?? '');

    if (!$title || !$date || !$location || !$description || !$createdBy) {
        respond(400, ["message" => "All event fields are required."]);
    }

    $db   = getDB();
    $stmt = $db->prepare(
        "INSERT INTO events (title, date, location, description, createdBy) VALUES (?, ?, ?, ?, ?)"
    );
    $stmt->bind_param("sssss", $title, $date, $location, $description, $createdBy);

    if ($stmt->execute()) {
        $id = $stmt->insert_id;
        $stmt->close(); $db->close();
        respond(201, ["message" => "Event created successfully.", "eventId" => $id]);
    } else {
        $stmt->close(); $db->close();
        respond(500, ["message" => "Could not create event. Please try again."]);
    }
}

// ── PUT /api/events/{id} ─────────────────────────────────────────────────────
function handleUpdateEvent($id) {
    $body    = getBody();
    $action  = trim($body['action']  ?? '');
    $newDate = trim($body['newDate'] ?? '');

    if (!in_array($action, ['postpone', 'cancel'])) {
        respond(400, ["message" => "Invalid action. Use 'postpone' or 'cancel'."]);
    }
    if ($action === 'postpone' && !$newDate) {
        respond(400, ["message" => "newDate is required when postponing an event."]);
    }

    $db = getDB();

    if ($action === 'cancel') {
        $stmt = $db->prepare("UPDATE events SET status = 'cancelled' WHERE id = ?");
        $stmt->bind_param("i", $id);
    } else {
        $stmt = $db->prepare("UPDATE events SET status = 'postponed', date = ? WHERE id = ?");
        $stmt->bind_param("si", $newDate, $id);
    }

    if ($stmt->execute()) {
        $stmt->close(); $db->close();
        respond(200, ["message" => "Event updated successfully."]);
    } else {
        $stmt->close(); $db->close();
        respond(500, ["message" => "Could not update event."]);
    }
}

// ── GET /api/attendance?userId=X ─────────────────────────────────────────────
function handleGetAttendance() {
    $userId = (int)($_GET['userId'] ?? 0);
    if (!$userId) respond(400, ["message" => "userId is required."]);

    $db   = getDB();
    $stmt = $db->prepare("SELECT event_id FROM attendance WHERE user_id = ?");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $result = $stmt->get_result();
    $ids    = [];
    while ($row = $result->fetch_assoc()) $ids[] = (int)$row['event_id'];
    $stmt->close();
    $db->close();
    respond(200, $ids);
}

// ── POST /api/attendance ─────────────────────────────────────────────────────
function handleAddAttendance() {
    $body    = getBody();
    $eventId = (int)($body['eventId'] ?? 0);
    $userId  = (int)($body['userId']  ?? 0);
    if (!$eventId || !$userId) respond(400, ["message" => "eventId and userId are required."]);

    $db   = getDB();
    $stmt = $db->prepare("INSERT IGNORE INTO attendance (event_id, user_id) VALUES (?, ?)");
    $stmt->bind_param("ii", $eventId, $userId);
    $stmt->execute();
    $stmt->close();
    $db->close();
    respond(201, ["message" => "RSVP registered."]);
}

// ── DELETE /api/attendance ───────────────────────────────────────────────────
function handleRemoveAttendance() {
    $body    = getBody();
    $eventId = (int)($body['eventId'] ?? 0);
    $userId  = (int)($body['userId']  ?? 0);
    if (!$eventId || !$userId) respond(400, ["message" => "eventId and userId are required."]);

    $db   = getDB();
    $stmt = $db->prepare("DELETE FROM attendance WHERE event_id = ? AND user_id = ?");
    $stmt->bind_param("ii", $eventId, $userId);
    $stmt->execute();
    $stmt->close();
    $db->close();
    respond(200, ["message" => "RSVP removed."]);
}
