<?php
/**
 * Legitimate configuration file
 * This should NOT trigger detection
 */

define('DB_HOST', 'localhost');
define('DB_NAME', 'myapp');
define('DB_USER', 'admin');
define('DB_PASS', 'secret123');

// Normal function
function get_config($key) {
    return defined($key) ? constant($key) : null;
}
