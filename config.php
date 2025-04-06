<?php
// --- Datenbank Konfiguration ---
define('DB_HOST', 'localhost'); // Oder deine Datenbank-Host-Adresse
define('DB_NAME', 'virtual_mail');
define('DB_USER', 'USERNAME');      // Dein Datenbank-Benutzername
define('DB_PASS', 'PASSWORD');          // Dein Datenbank-Passwort

// --- Allgemeine Einstellungen ---
define('SITE_TITLE', 'Virtuelles Mail System');
define('BASE_URL', ''); // Falls nötig, z.B. 'http://localhost/virtualmail' - ansonsten leer lassen für relative Pfade

// --- Fehleranzeige (Nur für Entwicklung!) ---
// In Produktion auf 0 setzen!
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// --- Zeitzone ---
date_default_timezone_set('Europe/Berlin');

// --- Session Start ---
if (session_status() === PHP_SESSION_NONE) {
    // Sicherere Session-Einstellungen (Beispiel)
    // session_set_cookie_params(['lifetime' => 7200, 'path' => '/', 'domain' => '', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
    session_start();
}

// In config.php hinzufügen:
define('UPLOAD_DIR', __DIR__ . '/uploads/'); // Verzeichnis für Anhänge relativ zur config.php
define('MAX_UPLOAD_SIZE', 5 * 1024 * 1024); // Max. 5 MB pro Datei (Beispiel)
define('ALLOWED_MIME_TYPES', [
    'image/jpeg', 'image/png', 'image/gif',
    'application/pdf',
    'text/plain',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document', // .docx
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', // .xlsx
    'application/vnd.ms-excel', // .xls
    'application/msword', // .doc
]); // Erlaubte Dateitypen (Beispiel)

// Sicherstellen, dass Helferfunktionen aus früheren Versionen da sind:
// format_sender_display(), create_quoted_body(), get_email_details(), format_bytes(), get_folder_name() etc.
// ...

// --- Datenbankverbindung herstellen ---
try {
    $pdo = new PDO(
        "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4",
        DB_USER,
        DB_PASS,
        [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false, // Wichtig für Sicherheit
        ]
    );
} catch (\PDOException $e) {
    // In Produktion sollte hier eine generische Fehlermeldung stehen und der Fehler geloggt werden.
    throw new \PDOException($e->getMessage(), (int)$e->getCode());
}

// --- Hilfsfunktionen ---
function redirect($url = 'index.php') {
    header("Location: " . $url);
    exit;
}

function fetch_user($userId) {
    global $pdo;
    $stmt = $pdo->prepare("SELECT u.*, d.domain_name FROM users u JOIN domains d ON u.domain_id = d.id WHERE u.id = ?");
    $stmt->execute([$userId]);
    return $stmt->fetch();
}

function get_user_email($user) {
    return htmlspecialchars($user['username']) . '@' . htmlspecialchars($user['domain_name']);
}

function is_logged_in() {
    return isset($_SESSION['user_id']);
}

function is_admin() {
    return isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === true;
}

function require_login() {
    if (!is_logged_in()) {
        redirect('index.php?page=login');
    }
}

function require_admin() {
    require_login();
    if (!is_admin()) {
        $_SESSION['error_message'] = "Zugriff verweigert. Administratorrechte erforderlich.";
        redirect('index.php?page=inbox'); // Oder eine andere Standardseite
    }
}

// Bereinigt die Superglobals von potentiellen Session-Daten vorheriger Admin-Ansichten
function clear_admin_view_session() {
    unset($_SESSION['viewing_user_id']);
    unset($_SESSION['viewing_user_email']);
}

// Gibt die ID des aktuell anzuzeigenden Benutzers zurück (entweder der eingeloggte oder der vom Admin betrachtete)
function get_current_view_user_id() {
    if (is_admin() && isset($_SESSION['viewing_user_id'])) {
        return $_SESSION['viewing_user_id'];
    }
    return $_SESSION['user_id'] ?? null;
}

// Formatiert Bytes in lesbare Einheiten
function format_bytes($bytes, $precision = 2) {
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= pow(1024, $pow);
    return round($bytes, $precision) . ' ' . $units[$pow];
}

// Holt sich den aktuellen Ordnernamen (sauber)
function get_folder_name($folder_param) {
    $allowed_folders = ['inbox', 'sent', 'trash'];
    return in_array(strtolower($folder_param), $allowed_folders) ? strtoupper($folder_param) : 'INBOX';
}
?>