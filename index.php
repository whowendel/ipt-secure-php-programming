<?php


declare(strict_types=1);

session_start([
    'cookie_httponly' => true,   // FIX #6 — no JS access to session cookie
    'cookie_samesite' => 'Lax',  // FIX #6 — basic CSRF mitigation at cookie level
    // Add 'cookie_secure' => true when served over HTTPS
]);


ini_set('log_errors', '1');
error_reporting(E_ALL);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/csrf.php';

$db = get_db();

// ── Helpers ─────────────────────────────────────────────────────────────────

/** Escape a value for safe HTML output. */
function e(mixed $v): string
{
    return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** Return the current logged-in user ID, or null. */
function current_user_id(): ?int
{
    return isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
}

// ── Action handlers ──────────────────────────────────────────────────────────

$action = $_POST['action'] ?? '';

// --- Register ----------------------------------------------------------------
if ($action === 'register') {
    csrf_verify(); // FIX #5

    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($email === '' || $password === '') {
        $message = 'Email and password are required.';
    } else {
        // FIX #2 — bcrypt instead of MD5
        $hash = password_hash($password, PASSWORD_BCRYPT);

        // FIX #7 — role is always 'student' on self-registration (server-side)
        $role = 'student';

        // FIX #1 — prepared statement
        $stmt = $db->prepare('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)');
        try {
            $stmt->execute([$email, $hash, $role]);
            header('Location: /?message=' . urlencode('Account created. Please sign in.'));
            exit;
        } catch (PDOException $e) {
            error_log('Register error: ' . $e->getMessage());
            $message = 'Registration failed — that email may already be in use.';
        }
    }
}

// --- Login -------------------------------------------------------------------
if ($action === 'login') {
    csrf_verify(); // FIX #5

    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    // FIX #1 — parameterised query; no string interpolation
    $stmt = $db->prepare('SELECT id, password_hash, role FROM users WHERE email = ?');
    $stmt->execute([$email]);
    $row = $stmt->fetch();

    // FIX #2 — password_verify() (works with bcrypt hashes)
    if ($row && password_verify($password, $row['password_hash'])) {
        // FIX #6 — regenerate session ID on privilege change
        session_regenerate_id(true);
        $_SESSION['user_id'] = $row['id'];
        $_SESSION['role']    = $row['role']; // FIX #7 — role from DB, not form
        header('Location: /');
        exit;
    }

    // FIX #4 — do NOT reflect the email back unescaped
    $message = 'Login failed.';
}

// --- Save note ---------------------------------------------------------------
if ($action === 'save') {
    csrf_verify(); // FIX #5

    $uid = current_user_id();
    if ($uid === null) {
        http_response_code(403);
        exit('Not logged in.');
    }

    $title = trim($_POST['title'] ?? '');
    $body  = trim($_POST['body'] ?? '');

    if ($title === '' || $body === '') {
        $message = 'Title and body are required.';
    } else {
        // FIX #3 / #7 — owner is always the session user, not a form field
        // FIX #1 — prepared statement
        $stmt = $db->prepare('INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)');
        $stmt->execute([$uid, $title, $body]);
        header('Location: /');
        exit;
    }
}

// --- Update note -------------------------------------------------------------
if ($action === 'update') {
    csrf_verify(); // FIX #5

    $uid = current_user_id();
    if ($uid === null) {
        http_response_code(403);
        exit('Not logged in.');
    }

    $id    = (int)($_POST['id'] ?? 0);
    $title = trim($_POST['title'] ?? '');
    $body  = trim($_POST['body'] ?? '');

    // FIX #3 — WHERE clause restricts update to the owner's notes
    $stmt = $db->prepare(
        'UPDATE notes SET title = ?, body = ? WHERE id = ? AND user_id = ?'
    );
    $stmt->execute([$title, $body, $id, $uid]);
    header('Location: /');
    exit;
}

// --- Delete note -------------------------------------------------------------
if (isset($_GET['delete'])) {
    // FIX #5 — DELETE must be a POST with CSRF; GET-based delete is unsafe.
    // If reached via GET, redirect to a POST-confirmation form instead.
    // For this lab we simply block it here.
    http_response_code(405);
    exit('Use POST to delete.');
}

if ($action === 'delete') {
    csrf_verify(); // FIX #5

    $uid = current_user_id();
    if ($uid === null) {
        http_response_code(403);
        exit('Not logged in.');
    }

    $id = (int)($_POST['id'] ?? 0);

    // FIX #3 — only owner can delete
    $stmt = $db->prepare('DELETE FROM notes WHERE id = ? AND user_id = ?');
    $stmt->execute([$id, $uid]);
    header('Location: /');
    exit;
}

// --- Logout ------------------------------------------------------------------
if (isset($_GET['logout'])) {
    // FIX #6 — destroy session properly
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    }
    session_destroy();
    // FIX #6 — start fresh session so CSRF token is clean for next login
    session_start(['cookie_httponly' => true, 'cookie_samesite' => 'Lax']);
    session_regenerate_id(true);
    header('Location: /');
    exit;
}

// ── Page data ────────────────────────────────────────────────────────────────

$message = $message ?? e($_GET['message'] ?? '');
$notes   = [];
$editing = false;
$uid     = current_user_id();

if ($uid !== null) {
    // FIX #3 — only fetch the logged-in user's own notes
    $stmt = $db->prepare(
        'SELECT id, user_id, title, body FROM notes WHERE user_id = ? ORDER BY id DESC'
    );
    $stmt->execute([$uid]);
    $notes = $stmt->fetchAll();

    if (isset($_GET['edit'])) {
        $editId = (int)$_GET['edit'];
        // FIX #3 — verify ownership before showing edit form
        $stmt = $db->prepare(
            'SELECT id, title, body FROM notes WHERE id = ? AND user_id = ?'
        );
        $stmt->execute([$editId, $uid]);
        $editing = $stmt->fetch();
    }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Campus Notes</title>
  <style>
    body { font: 16px sans-serif; max-width: 750px; margin: 2rem auto }
    label { display: block; margin: .5rem 0 }
    article { border: 1px solid #aaa; padding: 1rem; margin: 1rem 0 }
  </style>
</head>
<body>
<h1>Campus Notes</h1>
<?php if ($message !== ''): ?>
  <p><?= e($message) /* FIX #4 — escaped */ ?></p>
<?php endif ?>

<?php if ($uid === null): ?>
  <h2>Register or sign in</h2>
  <form method="post">
    <?= csrf_input() /* FIX #5 */ ?>
    <label>Email   <input name="email"    type="email"    required></label>
    <label>Password <input name="password" type="password" required></label>
    <!-- FIX #7 — role select removed; self-registrations are always 'student' -->
    <button name="action" value="register">Register</button>
    <button name="action" value="login">Sign in</button>
  </form>
<?php else: ?>
  <p>
    User ID: <?= e($uid) ?> | Role: <?= e($_SESSION['role']) ?> |
    <a href="?logout=1">Log out</a>
  </p>

  <?php if ($editing): ?>
    <h2>Edit note</h2>
    <form method="post">
      <?= csrf_input() ?>
      <input type="hidden" name="id" value="<?= e($editing['id']) ?>">
      <label>Title
        <input name="title" value="<?= e($editing['title']) /* FIX #4 */ ?>" required>
      </label>
      <label>Body
        <textarea name="body" required><?= e($editing['body']) /* FIX #4 */ ?></textarea>
      </label>
      <button name="action" value="update">Update</button>
      <a href="/">Cancel</a>
    </form>
  <?php endif ?>

  <h2>Create a note</h2>
  <form method="post">
    <?= csrf_input() ?>
    <!-- FIX #7 — Owner ID input removed; set server-side from session -->
    <label>Title <input name="title" required></label>
    <label>Body  <textarea name="body" required></textarea></label>
    <button name="action" value="save">Save</button>
  </form>

  <h2>My Notes</h2>
  <?php foreach ($notes as $note): ?>
    <article>
      <h3><?= e($note['title']) /* FIX #4 */ ?></h3>
      <p><?= e($note['body'])   /* FIX #4 */ ?></p>
      <small>Owner: <?= e($note['user_id']) ?></small>
      <a href="?edit=<?= e($note['id']) ?>">Edit</a>
      <!-- FIX #5 — delete via POST form, not GET link -->
      <form method="post" style="display:inline"
            onsubmit="return confirm('Delete this note?')">
        <?= csrf_input() ?>
        <input type="hidden" name="id" value="<?= e($note['id']) ?>">
        <button name="action" value="delete">Delete</button>
      </form>
    </article>
  <?php endforeach ?>
<?php endif ?>
</body>
</html>
