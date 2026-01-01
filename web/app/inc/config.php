<?php
/**
 * config.php — BackDraft frontend configuration
 */
define('BD_CONFIG', true);

// Database
define('BD_DB_HOST', '127.0.0.1');
define('BD_DB_PORT', 3306);
define('BD_DB_USER', 'DUMMY_MARIADB_USER_SET_VIA_VAULT');
define('BD_DB_PASS', 'DUMMY_MARIADB_PWD_SET_VIA_VAULT');
define('BD_DB_NAME', 'mcaster1_backdraft');

// C++ Admin API
define('BD_API_URL', 'https://127.0.0.1:8832');
define('BD_API_TOKEN', 'DUMMY_BACKDRAFT_APP_KEY_SET_VIA_VAULT');

// Session
define('BD_SESSION_NAME', 'backdraft_session');
define('BD_COOKIE_TTL', 3600);

// Timezone
date_default_timezone_set('America/Los_Angeles');
