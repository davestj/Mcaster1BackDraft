<?php
/**
 * config.php — BackDraft frontend configuration
 */
define('BD_CONFIG', true);

// Database
define('BD_DB_HOST', '127.0.0.1');
define('BD_DB_PORT', 3306);
define('BD_DB_USER', 'your_db_username_here');
define('BD_DB_PASS', 'your_db_password_here');
define('BD_DB_NAME', 'mcaster1_backdraft');

// C++ Admin API
define('BD_API_URL', 'https://127.0.0.1:8832');
define('BD_API_TOKEN', 'bd9f4a2c8e1d7b3f6a0e5c9d2b8f4a1c7e3d0b6f9a2c5e8d1b4f7a0c3e6d9b');

// Session
define('BD_SESSION_NAME', 'backdraft_session');
define('BD_COOKIE_TTL', 3600);

// Timezone
date_default_timezone_set('America/Los_Angeles');
