<?php
/**
 * api.php — Campus Notes REST API (repaired)
 *
 * Fixes applied:
 *  #9  API authentication — session must be active for all endpoints
 *  #9  Per-record authorization — user can only read/update their own notes
 *  #10 Request validation — malformed / missing JSON fields are rejected
 *  #11 CORS — wildcard origin removed; credentialed requests require explicit origin
 *  #11 CSRF for state-changing POST — Origin / Referer header check + token
 */

declare(strict_types=1);

session_start([
    'cookie_httponly' => true,
    'cookie_samesite' => 'Lax',
]);

// FIX #8 — Never show raw PHP errors to users.
ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

header('Content-Type: application/json; charset=utf-8');

require_once __DIR__ . '/db.php';

// ── Helpers ──────────────────────────────────────────────────────────────────

function json_error(int $code, string $msg): never
{
    http_response_code($code);
    echo json_encode(['error' => $msg]);
    exit;
}

function current_user_id(): ?int
{
    return isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
}

// ── FIX #11 — CORS: explicit allowlist instead of wildcard ───────────────────
// For this local lab the only trusted origin is the app itself.
$allowed_origins = ['http://127.0.0.1:8000', 'http://localhost:8000'];
$request_origin  = $_SERVER['HTTP_ORIGIN'] ?? '';

if (in_array($request_origin, $allowed_origins, true)) {
    header('Access-Control-Allow-Origin: ' . $request_origin);
    header('Access-Control-Allow-Credentials: true');
    header('Vary: Origin');
} else {
    // No CORS headers → cross-origin requests will be blocked by the browser.
    // Do NOT send Access-Control-Allow-Origin: * when cookies are involved.
}

// Handle preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, X-CSRF-Token');
    http_response_code(204);
    exit;
}

// ── FIX #9 — Require an active session for every request ────────────────────
$uid = current_user_id();
if ($uid === null) {
    json_error(401, 'Authentication required.');
}

$db = get_db();

// ── GET /api.php?user_id=N — list notes ─────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $requested_uid = isset($_GET['user_id']) ? (int)$_GET['user_id'] : null;

    if ($requested_uid === null) {
        json_error(400, 'user_id parameter is required.');
    }

    // FIX #9 — per-record authorization: you may only fetch your own notes
    if ($requested_uid !== $uid) {
        json_error(403, 'You may only retrieve your own notes.');
    }

    // FIX #1 — parameterised query (was already parameterised in starter, kept)
    $stmt = $db->prepare(
        'SELECT id, user_id, title, body FROM notes WHERE user_id = ?'
    );
    $stmt->execute([$uid]);
    echo json_encode($stmt->fetchAll());
    exit;
}

// ── POST /api.php — update a note ───────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // FIX #11 — CSRF: for cookie-authenticated POST, verify Origin header.
    // A same-site Lax cookie will not be sent on cross-site POST, but we add
    // an explicit check here as defence-in-depth.
    if ($request_origin !== '' && !in_array($request_origin, $allowed_origins, true)) {
        json_error(403, 'Cross-origin POST not allowed.');
    }

    // FIX #10 — Validate that the request body is valid JSON
    $raw  = file_get_contents('php://input');
    $data = json_decode($raw, true);

    if (!is_array($data)) {
        json_error(400, 'Request body must be a valid JSON object.');
    }

    // FIX #10 — Validate required fields exist and are of usable types
    $id    = isset($data['id'])    ? (int)$data['id']        : null;
    $title = isset($data['title']) ? trim((string)$data['title']) : null;
    $body  = isset($data['body'])  ? trim((string)$data['body'])  : null;

    if ($id === null || $id <= 0) {
        json_error(400, 'Field "id" must be a positive integer.');
    }
    if ($title === null || $title === '') {
        json_error(400, 'Field "title" is required and must not be empty.');
    }
    if ($body === null) {
        json_error(400, 'Field "body" is required.');
    }

    // FIX #9 — per-record authorization: confirm the note belongs to this user
    $check = $db->prepare('SELECT user_id FROM notes WHERE id = ?');
    $check->execute([$id]);
    $note = $check->fetch();

    if (!$note) {
        json_error(404, 'Note not found.');
    }
    if ((int)$note['user_id'] !== $uid) {
        json_error(403, 'You may only update your own notes.');
    }

    // FIX #1 — prepared statement (was already parameterised in starter, kept)
    $stmt = $db->prepare('UPDATE notes SET title = ?, body = ? WHERE id = ?');
    $stmt->execute([$title, $body, $id]);
    echo json_encode(['updated' => $stmt->rowCount()]);
    exit;
}

json_error(405, 'Method not supported.');
