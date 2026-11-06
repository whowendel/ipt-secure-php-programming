<?php
/**
 * csrf.php — CSRF token helpers (separated responsibility).
 *
 * FIX #5 — All state-changing POST forms must carry a valid CSRF token.
 */

declare(strict_types=1);

/** Generate (once per session) and return the CSRF token. */
function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/** Emit a hidden <input> containing the current CSRF token. */
function csrf_input(): string
{
    return '<input type="hidden" name="csrf_token" value="'
        . htmlspecialchars(csrf_token(), ENT_QUOTES, 'UTF-8')
        . '">';
}

/**
 * Verify that the submitted token matches the session token.
 * Terminates the request with 403 on failure.
 */
function csrf_verify(): void
{
    $submitted = $_POST['csrf_token'] ?? '';
    if (!hash_equals(csrf_token(), $submitted)) {
        http_response_code(403);
        exit('Invalid or missing CSRF token.');
    }
}
