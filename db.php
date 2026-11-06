<?php
/**
 * db.php — Database connection factory (separated responsibility).
 *
 * Returns a shared PDO instance configured for the notes_lab database.
 * Credentials are read from environment variables only; no fallback to root
 * in a real deployment. The lab fallback is kept for local convenience but
 * marked clearly so students know to remove it.
 */

declare(strict_types=1);

function get_db(): PDO
{
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }

    $host = 'localhost';
    $dbname = 'notes_lab';
    $user = getenv('LAB_DB_USER');
    $pass = getenv('LAB_DB_PASSWORD');

    // LAB ONLY: fallback to root so the README quick-start still works without
    // env vars. Remove this fallback before any non-local deployment.
    if ($user === false || $user === '') {
        $user = 'root';
        $pass = '';
    }

    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,  // use native prepared statements
    ];

    try {
        $pdo = new PDO(
            "mysql:host={$host};dbname={$dbname};charset=utf8mb4",
            $user,
            $pass,
            $options
        );
    } catch (PDOException $e) {
        // FIX #8 — Never expose DB errors to the browser.
        // Log a sanitised message; return a generic response to the caller.
        error_log('DB connection failed: ' . $e->getMessage());
        http_response_code(500);
        exit('A database error occurred. Please contact the administrator.');
    }

    return $pdo;
}
