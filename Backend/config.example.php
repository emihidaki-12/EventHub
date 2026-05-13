<?php
// ── Database ─────────────────────────────────────────────────────────────────
define('DB_HOST', '10.0.158.186');
define('DB_USER', 'eventhub_user');
define('DB_PASS', 'eventhub_password');
define('DB_NAME', 'eventhub_db');

// ── Anthropic AI ─────────────────────────────────────────────────────────────
define('ANTHROPIC_API_KEY', '');

// ── Gmail SMTP (2MFA) ─────────────────────────────────────────────────────────
define('SMTP_HOST', 'smtp.gmail.com');
define('SMTP_PORT', 465);
define('SMTP_USER', 'eventhubit342@gmail.com');
define('SMTP_PASS', 'dgrezapoydyqglfg');
define('OTP_TTL',   600);   // OTP lifetime in seconds (10 min)