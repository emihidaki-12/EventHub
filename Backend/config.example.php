<?php
// ── Database ─────────────────────────────────────────────────────────────────
define('DB_HOST', 'YOUR_DB_HOST');
define('DB_USER', 'YOUR_DB_USER');
define('DB_PASS', 'YOUR_DB_PASSWORD');
define('DB_NAME', 'YOUR_DB_NAME');

// ── Anthropic AI ─────────────────────────────────────────────────────────────
// Get your key at: https://console.anthropic.com/
define('ANTHROPIC_API_KEY', 'YOUR_ANTHROPIC_API_KEY');

// ── Gmail SMTP (2MFA) ─────────────────────────────────────────────────────────
// Use a Gmail App Password: https://myaccount.google.com/apppasswords
define('SMTP_HOST', 'smtp.gmail.com');
define('SMTP_PORT', 465);
define('SMTP_USER', 'YOUR_GMAIL_ADDRESS');
define('SMTP_PASS', 'YOUR_GMAIL_APP_PASSWORD');
define('OTP_TTL',   600);   // OTP lifetime in seconds (10 min)
