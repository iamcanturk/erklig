<?php
/**
 * Legitimate WordPress-like core file
 * This should be in whitelist and NOT trigger detection
 */

// Safe usage of these functions in core context
function wp_debug_mode() {
    if (defined('WP_DEBUG') && WP_DEBUG) {
        // Legitimate debug output
        phpinfo(INFO_GENERAL);
    }
}

// Safe file operations
function wp_upload_handler($file) {
    $allowed = array('jpg', 'png', 'gif');
    $ext = pathinfo($file['name'], PATHINFO_EXTENSION);
    
    if (in_array($ext, $allowed)) {
        move_uploaded_file($file['tmp_name'], '/uploads/' . $file['name']);
    }
}
