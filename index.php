<?php

// --- THIS IS AN OPEN SOURCE VIRTUAL MAIL SYSTEM CREATED BY GOOGLE GEMINI
// --- IF SOMEONE SOLD THIS TO YOU, YOU'VE BEEN SCAMMED https://github.com/mzl-alex/virtual-mail

require_once 'config.php'; // Konfiguration und DB-Verbindung laden

// --- Routing und Aktionsbehandlung ---
$page = $_GET['page'] ?? (is_logged_in() ? (is_admin() ? 'admin_dashboard' : 'inbox') : 'login');
$action = $_POST['action'] ?? $_GET['action'] ?? null;
$folder = $_GET['folder'] ?? 'inbox'; // Für Mailbox-Ansichten
$email_id = isset($_GET['email_id']) ? (int)$_GET['email_id'] : null;
$user_id_param = isset($_GET['user_id']) ? (int)$_GET['user_id'] : null; // Für Admin-Aktionen
$domain_id_param = isset($_GET['domain_id']) ? (int)$_GET['domain_id'] : null; // Für Admin-Aktionen

// --- Nachrichten-Handling (z.B. nach Aktionen) ---
$success_message = $_SESSION['success_message'] ?? null;
$error_message = $_SESSION['error_message'] ?? null;
unset($_SESSION['success_message'], $_SESSION['error_message']); // Nachrichten nach Anzeige löschen

// --- Aktions-Handler (POST-Requests meistens) ---
try {
    if ($action) {
        switch ($action) {
            // --- AUTHENTICATION ACTIONS ---
            case 'login':
                if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                    $email = trim($_POST['email'] ?? '');
                    $password = $_POST['password'] ?? '';
                    list($username, $domain_name) = explode('@', $email, 2) + [null, null];

                    if ($username && $domain_name) {
                        $stmt = $pdo->prepare("SELECT u.*, d.domain_name FROM users u JOIN domains d ON u.domain_id = d.id WHERE u.username = ? AND d.domain_name = ?");
                        $stmt->execute([$username, $domain_name]);
                        $user = $stmt->fetch();

                        if ($user && password_verify($password, $user['password_hash'])) {
                            // Login erfolgreich
                            session_regenerate_id(true); // Wichtig zur Vermeidung von Session Fixation
                            $_SESSION['user_id'] = $user['id'];
                            $_SESSION['username'] = $user['username'];
                            $_SESSION['user_email'] = get_user_email($user);
                            $_SESSION['is_admin'] = (bool)$user['is_admin'];

                            // Letzten Login aktualisieren
                            $stmt = $pdo->prepare("UPDATE users SET last_login = NOW() WHERE id = ?");
                            $stmt->execute([$user['id']]);

                            clear_admin_view_session(); // Sicherstellen, dass keine alte Admin-Ansicht aktiv ist

                            redirect('index.php?page=' . (is_admin() ? 'admin_dashboard' : 'inbox'));
                        }
                    }
                    $_SESSION['error_message'] = "Ungültige E-Mail-Adresse oder Passwort.";
                    redirect('index.php?page=login');
                }
                break;

            case 'register':
                if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                    $username = trim($_POST['username'] ?? '');
                    $domain_id = (int)($_POST['domain_id'] ?? 0);
                    $password = $_POST['password'] ?? '';
                    $password_confirm = $_POST['password_confirm'] ?? '';

                    // Validierung
                    if (empty($username) || $domain_id <= 0 || empty($password) || $password !== $password_confirm) {
                         $_SESSION['error_message'] = "Bitte alle Felder korrekt ausfüllen. Passwörter müssen übereinstimmen.";
                         redirect('index.php?page=register');
                    }
                    if (strlen($password) < 6) { // Beispiel: Mindestlänge
                         $_SESSION['error_message'] = "Passwort muss mindestens 6 Zeichen lang sein.";
                         redirect('index.php?page=register');
                    }

                    // Prüfen, ob Domain öffentlich registrierbar ist
                    $stmt = $pdo->prepare("SELECT id, domain_name FROM domains WHERE id = ? AND is_public_registrable = 1");
                    $stmt->execute([$domain_id]);
                    $domain = $stmt->fetch();

                    if (!$domain) {
                        $_SESSION['error_message'] = "Ausgewählte Domain ist nicht für die öffentliche Registrierung freigegeben.";
                        redirect('index.php?page=register');
                    }

                    // Prüfen, ob Benutzername@Domain bereits existiert
                    $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ? AND domain_id = ?");
                    $stmt->execute([$username, $domain_id]);
                    if ($stmt->fetch()) {
                         $_SESSION['error_message'] = "Die E-Mail-Adresse " . htmlspecialchars($username) . "@" . htmlspecialchars($domain['domain_name']) . " ist bereits vergeben.";
                         redirect('index.php?page=register');
                    }

                    // Benutzer erstellen
                    $password_hash = password_hash($password, PASSWORD_DEFAULT);
                    $stmt = $pdo->prepare("INSERT INTO users (username, domain_id, password_hash, is_admin, created_at) VALUES (?, ?, ?, 0, NOW())");
                    $stmt->execute([$username, $domain_id, $password_hash]);

                    $_SESSION['success_message'] = "Registrierung erfolgreich! Du kannst dich jetzt anmelden.";
                    redirect('index.php?page=login');
                }
                break;

            case 'logout':
                session_destroy();
                redirect('index.php?page=login');
                break;

            // --- WEBMAIL ACTIONS ---
             case 'send_email':
                require_login();
                if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                    $recipients_str = trim($_POST['recipients'] ?? '');
                    $subject = trim($_POST['subject'] ?? '');
                    $body = trim($_POST['body'] ?? '');
                    $sender_id = $_SESSION['user_id'];
                    $valid_recipient_ids = [];

                    if (empty($recipients_str) || empty($body)) {
                        $_SESSION['error_message'] = "Empfänger und Nachrichtentext dürfen nicht leer sein.";
                        redirect('index.php?page=compose');
                    }

                    // Empfänger parsen und validieren
                    $recipient_emails = array_map('trim', explode(',', $recipients_str));
                    foreach ($recipient_emails as $email) {
                        list($r_user, $r_domain) = explode('@', $email, 2) + [null, null];
                        if ($r_user && $r_domain) {
                            $stmt = $pdo->prepare("SELECT u.id FROM users u JOIN domains d ON u.domain_id = d.id WHERE u.username = ? AND d.domain_name = ?");
                            $stmt->execute([$r_user, $r_domain]);
                            $recipient = $stmt->fetch();
                            if ($recipient) {
                                $valid_recipient_ids[] = $recipient['id'];
                            } else {
                                // Optional: Fehlermeldung über ungültige Empfänger
                                $_SESSION['error_message'] = "Empfänger nicht gefunden: " . htmlspecialchars($email);
                                // Entscheide, ob Senden abgebrochen wird oder nur ungültige ignoriert werden
                                // redirect('index.php?page=compose'); // Abbruch
                            }
                        }
                    }
                    $valid_recipient_ids = array_unique($valid_recipient_ids); // Duplikate entfernen

                    if (empty($valid_recipient_ids)) {
                        $_SESSION['error_message'] = "Keine gültigen Empfänger gefunden.";
                        redirect('index.php?page=compose');
                    }

                    // E-Mail in `emails` speichern
                    $stmt = $pdo->prepare("INSERT INTO emails (sender_user_id, subject, body, sent_at) VALUES (?, ?, ?, NOW())");
                    $stmt->execute([$sender_id, $subject, $body]);
                    $new_email_id = $pdo->lastInsertId();

                    // Einträge für Empfänger in `email_recipients` (INBOX)
                    $stmt_recipient = $pdo->prepare("INSERT INTO email_recipients (email_id, recipient_user_id, folder, is_read, received_at) VALUES (?, ?, 'INBOX', 0, NOW())");
                    foreach ($valid_recipient_ids as $recipient_id) {
                        $stmt_recipient->execute([$new_email_id, $recipient_id]);
                    }

                    // Eintrag für Absender in `email_recipients` (SENT)
                    $stmt_sender = $pdo->prepare("INSERT INTO email_recipients (email_id, recipient_user_id, folder, is_read, received_at) VALUES (?, ?, 'SENT', 1, NOW())");
                    $stmt_sender->execute([$new_email_id, $sender_id]);

                     // Speicherplatz aktualisieren (sehr einfache Schätzung!)
                     $email_size = strlen($subject) + strlen($body);
                     $stmt_update_storage = $pdo->prepare("UPDATE users SET storage_used_bytes = storage_used_bytes + ? WHERE id = ?");
                     $stmt_update_storage->execute([$email_size, $sender_id]); // Speicher nur dem Sender anrechnen
                     foreach ($valid_recipient_ids as $recipient_id) {
                         $stmt_update_storage->execute([$email_size, $recipient_id]); // oder auch den Empfängern
                     }


                    $_SESSION['success_message'] = "E-Mail erfolgreich gesendet!";
                    redirect('index.php?page=inbox');
                }
                break;

            case 'move_to_trash':
            case 'delete_permanently':
            case 'mark_unread': // Eigentlich braucht man hier die email_recipient ID, nicht email_id
                 require_login();
                 $recipient_email_id = isset($_GET['re_id']) ? (int)$_GET['re_id'] : 0; // ID aus email_recipients
                 $current_user_id = get_current_view_user_id(); // Kann Admin oder User sein

                 if ($recipient_email_id > 0 && $current_user_id) {
                     // Sicherstellen, dass die Mail dem User gehört (oder Admin zugreift)
                     $stmt = $pdo->prepare("SELECT id, folder FROM email_recipients WHERE id = ? AND recipient_user_id = ?");
                     $stmt->execute([$recipient_email_id, $current_user_id]);
                     $recipient_entry = $stmt->fetch();

                     if($recipient_entry) {
                         if ($action === 'move_to_trash' && $recipient_entry['folder'] !== 'TRASH') {
                             $stmt = $pdo->prepare("UPDATE email_recipients SET folder = 'TRASH' WHERE id = ?");
                             $stmt->execute([$recipient_email_id]);
                             $_SESSION['success_message'] = "E-Mail in den Papierkorb verschoben.";
                         } elseif ($action === 'delete_permanently' && $recipient_entry['folder'] === 'TRASH') {
                             // Optional: Speicherplatz anpassen (komplexer, da Mail evtl. noch bei anderen liegt)
                             $stmt = $pdo->prepare("DELETE FROM email_recipients WHERE id = ?");
                             $stmt->execute([$recipient_email_id]);
                             // Optional: Prüfen, ob die email in emails gelöscht werden kann (wenn keine recipients mehr)
                             $_SESSION['success_message'] = "E-Mail endgültig gelöscht.";
                         } elseif ($action === 'mark_unread') {
                             $stmt = $pdo->prepare("UPDATE email_recipients SET is_read = 0 WHERE id = ?");
                             $stmt->execute([$recipient_email_id]);
                             $_SESSION['success_message'] = "E-Mail als ungelesen markiert.";
                         }
                     } else {
                         $_SESSION['error_message'] = "E-Mail nicht gefunden oder Zugriff verweigert.";
                     }
                 } else {
                      $_SESSION['error_message'] = "Ungültige Anfrage.";
                 }
                 $redirect_page = (is_admin() && isset($_SESSION['viewing_user_id'])) ? 'admin_mailbox_view' : 'inbox';
                 redirect("index.php?page={$redirect_page}&folder=" . urlencode(strtolower($folder)));
                 break;

            // --- ADMIN ACTIONS ---
            case 'add_domain':
            case 'edit_domain':
                 require_admin();
                 if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                     $domain_name = trim($_POST['domain_name'] ?? '');
                     $is_public = isset($_POST['is_public_registrable']) ? 1 : 0;

                     if (empty($domain_name)) {
                         $_SESSION['error_message'] = "Domainname darf nicht leer sein.";
                     } else {
                         if ($action === 'add_domain') {
                             // Prüfen ob Domain schon existiert
                             $stmt_check = $pdo->prepare("SELECT id FROM domains WHERE domain_name = ?");
                             $stmt_check->execute([$domain_name]);
                             if ($stmt_check->fetch()) {
                                 $_SESSION['error_message'] = "Domain '$domain_name' existiert bereits.";
                             } else {
                                 $stmt = $pdo->prepare("INSERT INTO domains (domain_name, is_public_registrable) VALUES (?, ?)");
                                 $stmt->execute([$domain_name, $is_public]);
                                 $_SESSION['success_message'] = "Domain '$domain_name' erfolgreich hinzugefügt.";
                             }
                         } elseif ($action === 'edit_domain' && $domain_id_param) {
                             // Prüfen ob Domain (außer sich selbst) schon existiert
                             $stmt_check = $pdo->prepare("SELECT id FROM domains WHERE domain_name = ? AND id != ?");
                             $stmt_check->execute([$domain_name, $domain_id_param]);
                             if ($stmt_check->fetch()) {
                                  $_SESSION['error_message'] = "Domain '$domain_name' existiert bereits.";
                             } else {
                                 $stmt = $pdo->prepare("UPDATE domains SET domain_name = ?, is_public_registrable = ? WHERE id = ?");
                                 $stmt->execute([$domain_name, $is_public, $domain_id_param]);
                                 $_SESSION['success_message'] = "Domain erfolgreich aktualisiert.";
                             }
                         }
                     }
                 }
                 redirect('index.php?page=admin_domains');
                 break;

            case 'delete_domain':
                 require_admin();
                 if ($domain_id_param) {
                     // Optional: Prüfen, ob noch Benutzer die Domain verwenden
                     $stmt_check = $pdo->prepare("SELECT COUNT(*) as user_count FROM users WHERE domain_id = ?");
                     $stmt_check->execute([$domain_id_param]);
                     if($stmt_check->fetch()['user_count'] > 0) {
                          $_SESSION['error_message'] = "Domain kann nicht gelöscht werden, da ihr noch Benutzer zugewiesen sind.";
                     } else {
                         $stmt = $pdo->prepare("DELETE FROM domains WHERE id = ?");
                         $stmt->execute([$domain_id_param]);
                         $_SESSION['success_message'] = "Domain erfolgreich gelöscht.";
                     }
                 }
                 redirect('index.php?page=admin_domains');
                 break;

            case 'add_user':
            case 'edit_user':
                require_admin();
                 if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                     $username = trim($_POST['username'] ?? '');
                     $domain_id = (int)($_POST['domain_id'] ?? 0);
                     $full_name = trim($_POST['full_name'] ?? '');
                     $is_admin_flag = isset($_POST['is_admin']) ? 1 : 0;
                     $password = $_POST['password'] ?? ''; // Nur bei Add oder wenn geändert

                     if (empty($username) || $domain_id <= 0) {
                          $_SESSION['error_message'] = "Benutzername und Domain sind erforderlich.";
                     } else {
                         // Prüfen ob Domain existiert
                         $stmt_dcheck = $pdo->prepare("SELECT domain_name FROM domains WHERE id = ?");
                         $stmt_dcheck->execute([$domain_id]);
                         $domain = $stmt_dcheck->fetch();
                         if (!$domain) {
                            $_SESSION['error_message'] = "Ausgewählte Domain existiert nicht.";
                         } else {
                             // Prüfen ob User@Domain bereits existiert (außer sich selbst bei Edit)
                             $sql_check = "SELECT id FROM users WHERE username = ? AND domain_id = ?";
                             $params_check = [$username, $domain_id];
                             if ($action === 'edit_user' && $user_id_param) {
                                 $sql_check .= " AND id != ?";
                                 $params_check[] = $user_id_param;
                             }
                             $stmt_check = $pdo->prepare($sql_check);
                             $stmt_check->execute($params_check);

                             if ($stmt_check->fetch()) {
                                 $_SESSION['error_message'] = "Die E-Mail-Adresse " . htmlspecialchars($username) . "@" . htmlspecialchars($domain['domain_name']) . " ist bereits vergeben.";
                             } else {
                                 // Aktionen durchführen
                                 if ($action === 'add_user') {
                                     if (empty($password)) {
                                         $_SESSION['error_message'] = "Passwort ist für neue Benutzer erforderlich.";
                                     } elseif (strlen($password) < 6) {
                                          $_SESSION['error_message'] = "Passwort muss mindestens 6 Zeichen haben.";
                                     } else {
                                         $password_hash = password_hash($password, PASSWORD_DEFAULT);
                                         $stmt = $pdo->prepare("INSERT INTO users (username, domain_id, password_hash, full_name, is_admin, created_at) VALUES (?, ?, ?, ?, ?, NOW())");
                                         $stmt->execute([$username, $domain_id, $password_hash, $full_name, $is_admin_flag]);
                                         $_SESSION['success_message'] = "Benutzer erfolgreich hinzugefügt.";
                                     }
                                 } elseif ($action === 'edit_user' && $user_id_param) {
                                     $sql_update = "UPDATE users SET username = ?, domain_id = ?, full_name = ?, is_admin = ?";
                                     $params_update = [$username, $domain_id, $full_name, $is_admin_flag];
                                     if (!empty($password)) {
                                         if(strlen($password) < 6) {
                                             $_SESSION['error_message'] = "Neues Passwort muss mindestens 6 Zeichen haben.";
                                             redirect('index.php?page=admin_users'); // Bleibe auf der Seite
                                         }
                                         $password_hash = password_hash($password, PASSWORD_DEFAULT);
                                         $sql_update .= ", password_hash = ?";
                                         $params_update[] = $password_hash;
                                     }
                                     $sql_update .= " WHERE id = ?";
                                     $params_update[] = $user_id_param;

                                     $stmt = $pdo->prepare($sql_update);
                                     $stmt->execute($params_update);
                                     $_SESSION['success_message'] = "Benutzer erfolgreich aktualisiert.";
                                 }
                             }
                         }
                     }
                 }
                 redirect('index.php?page=admin_users');
                 break;

            case 'delete_user':
                 require_admin();
                 if ($user_id_param) {
                     // Verhindere Selbstlöschung
                     if ($user_id_param == $_SESSION['user_id']) {
                         $_SESSION['error_message'] = "Du kannst dich nicht selbst löschen.";
                     } else {
                         $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
                         $stmt->execute([$user_id_param]);
                         $_SESSION['success_message'] = "Benutzer erfolgreich gelöscht.";
                     }
                 }
                 redirect('index.php?page=admin_users');
                 break;

            case 'access_mailbox': // Admin greift auf Postfach zu
                 require_admin();
                 if ($_SERVER['REQUEST_METHOD'] === 'POST' && $user_id_param) {
                     $justification = trim($_POST['justification_reason'] ?? '');
                     $acknowledged = isset($_POST['legitimate_interest']);

                     if (empty($justification) || !$acknowledged) {
                         $_SESSION['error_message'] = "Grund für den Zugriff und Bestätigung des berechtigten Interesses sind erforderlich.";
                         // Bleibe auf der User-Liste oder leite zurück zum Justification-Formular (wenn separat)
                         redirect('index.php?page=admin_users');
                     } else {
                         // Zielbenutzer holen zum Anzeigen
                         $target_user = fetch_user($user_id_param);
                         if ($target_user) {
                             // Zugriff loggen
                             $stmt_log = $pdo->prepare("INSERT INTO admin_mailbox_access_log (admin_user_id, target_user_id, justification_reason, acknowledged_legitimate_interest, access_timestamp) VALUES (?, ?, ?, 1, NOW())");
                             $stmt_log->execute([$_SESSION['user_id'], $user_id_param, $justification]);

                             // Session-Variablen für die Ansicht setzen
                             $_SESSION['viewing_user_id'] = $user_id_param;
                             $_SESSION['viewing_user_email'] = get_user_email($target_user);

                             // Umleiten zur Mailbox-Ansicht im Admin-Kontext
                             redirect('index.php?page=admin_mailbox_view&folder=inbox');
                         } else {
                             $_SESSION['error_message'] = "Zielbenutzer nicht gefunden.";
                             redirect('index.php?page=admin_users');
                         }
                     }
                 }
                 break;

             case 'exit_mailbox_view':
                 require_admin();
                 clear_admin_view_session();
                 redirect('index.php?page=admin_users'); // Oder zum Dashboard
                 break;

            default:
                 // Unbekannte Aktion - Optional: Loggen oder Fehlermeldung
                 break;
        }
    }
} catch (PDOException $e) {
    // Generische Fehlermeldung für den Benutzer
    $_SESSION['error_message'] = "Ein Datenbankfehler ist aufgetreten. Bitte versuche es später erneut.";
    // Logge den detaillierten Fehler für den Admin/Entwickler
    error_log("PDO Error in action '{$action}': " . $e->getMessage());
    // Leite zu einer sicheren Seite um
    redirect('index.php?page=' . (is_logged_in() ? 'inbox' : 'login'));
} catch (Exception $e) {
     $_SESSION['error_message'] = "Ein unerwarteter Fehler ist aufgetreten.";
     error_log("General Error in action '{$action}': " . $e->getMessage());
     redirect('index.php?page=' . (is_logged_in() ? 'inbox' : 'login'));
}


// --- HTML Output Start ---
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars(SITE_TITLE) ?> - <?= htmlspecialchars(ucfirst(str_replace('_', ' ', $page))) ?></title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous">
    <!-- Optional: Font Awesome für Icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" integrity="sha512-DTOQO9RWCH3ppGqcWaEA1BIZOC6xxalwEsw9c2QQeAIftl+Vegovlnee1c9QX4TctnWMn13TZye+giMm8e2LwA==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    <style>
        body { padding-top: 56px; /* Platz für fixe Navbar */ }
        .email-item.unread { font-weight: bold; background-color: #f8f9fa; }
        .email-body { white-space: pre-wrap; word-wrap: break-word; font-family: monospace; border: 1px solid #ddd; padding: 15px; margin-top: 15px; background: #fdfdfd; }
        .nav-pills .nav-link.active { background-color: #0d6efd; }
        /* Admin Mailbox View Indicator */
        .admin-view-indicator { background-color: #ffc107; color: #000; padding: 5px 10px; font-weight: bold; }
    </style>
</head>
<body>

<nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">
    <div class="container-fluid">
        <a class="navbar-brand" href="index.php"><?= htmlspecialchars(SITE_TITLE) ?></a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav me-auto mb-2 mb-lg-0">
                <?php if (is_logged_in()): ?>
                    <?php if (is_admin() && isset($_SESSION['viewing_user_id'])): // Admin im Inspektionsmodus ?>
                        <li class="nav-item">
                             <span class="navbar-text admin-view-indicator me-3">
                                 <i class="fas fa-user-secret"></i> Postfach von: <?= htmlspecialchars($_SESSION['viewing_user_email']) ?>
                             </span>
                        </li>
                         <li class="nav-item">
                             <a class="nav-link" href="index.php?action=exit_mailbox_view"><i class="fas fa-sign-out-alt"></i> Inspektion beenden</a>
                        </li>
                    <?php elseif (is_admin()): // Normaler Admin-Modus ?>
                         <li class="nav-item">
                            <a class="nav-link <?= ($page === 'admin_dashboard') ? 'active' : '' ?>" href="index.php?page=admin_dashboard"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link <?= ($page === 'admin_domains') ? 'active' : '' ?>" href="index.php?page=admin_domains"><i class="fas fa-globe"></i> Domains</a>
                        </li>
                         <li class="nav-item">
                            <a class="nav-link <?= ($page === 'admin_users') ? 'active' : '' ?>" href="index.php?page=admin_users"><i class="fas fa-users"></i> Benutzer</a>
                        </li>
                         <li class="nav-item">
                            <a class="nav-link <?= ($page === 'admin_logs') ? 'active' : '' ?>" href="index.php?page=admin_logs"><i class="fas fa-clipboard-list"></i> Zugriffsprotokoll</a>
                        </li>
                         <li class="nav-item">
                            <a class="nav-link <?= ($page === 'inbox' || $page === 'sent' || $page === 'trash' || $page === 'compose' || $page === 'view_email') ? 'active' : '' ?>" href="index.php?page=inbox"><i class="fas fa-envelope"></i> Mein Postfach</a>
                        </li>
                    <?php else: // Normaler User-Modus ?>
                        <li class="nav-item">
                             <a class="nav-link <?= ($page === 'inbox') ? 'active' : '' ?>" href="index.php?page=inbox"><i class="fas fa-inbox"></i> Posteingang</a>
                         </li>
                         <li class="nav-item">
                            <a class="nav-link <?= ($page === 'compose') ? 'active' : '' ?>" href="index.php?page=compose"><i class="fas fa-pencil-alt"></i> Verfassen</a>
                        </li>
                    <?php endif; ?>
                 <?php endif; ?>
            </ul>
             <ul class="navbar-nav ms-auto mb-2 mb-lg-0">
                <?php if (is_logged_in()): ?>
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                           <i class="fas fa-user"></i> <?= htmlspecialchars($_SESSION['user_email'] ?? 'Benutzer') ?>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="navbarDropdown">
                           <!-- <li><a class="dropdown-item" href="#">Einstellungen</a></li> -->
                           <!-- <li><hr class="dropdown-divider"></li> -->
                            <li><a class="dropdown-item" href="index.php?action=logout"><i class="fas fa-sign-out-alt"></i> Abmelden</a></li>
                        </ul>
                    </li>
                <?php else: ?>
                    <li class="nav-item">
                        <a class="nav-link <?= ($page === 'login') ? 'active' : '' ?>" href="index.php?page=login">Anmelden</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link <?= ($page === 'register') ? 'active' : '' ?>" href="index.php?page=register">Registrieren</a>
                    </li>
                <?php endif; ?>
            </ul>
        </div>
    </div>
</nav>

<div class="container mt-4">

    <?php // --- Nachrichten anzeigen --- ?>
    <?php if ($success_message): ?>
        <div class="alert alert-success alert-dismissible fade show" role="alert">
            <?= htmlspecialchars($success_message) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    <?php endif; ?>
    <?php if ($error_message): ?>
        <div class="alert alert-danger alert-dismissible fade show" role="alert">
            <?= htmlspecialchars($error_message) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    <?php endif; ?>


    <?php // --- Seiteninhalte basierend auf $page ---

    switch ($page) {

        // --- Öffentliche Seiten ---
        case 'login':
            if (is_logged_in()) redirect(); // Bereits eingeloggt -> weiterleiten
            ?>
            <div class="row justify-content-center">
                <div class="col-md-6 col-lg-4">
                    <h2 class="text-center mb-4">Anmelden</h2>
                    <div class="card">
                        <div class="card-body">
                            <form method="POST" action="index.php?action=login">
                                <input type="hidden" name="action" value="login">
                                <div class="mb-3">
                                    <label for="email" class="form-label">E-Mail-Adresse</label>
                                    <input type="email" class="form-control" id="email" name="email" placeholder="user@internal.local" required>
                                </div>
                                <div class="mb-3">
                                    <label for="password" class="form-label">Passwort</label>
                                    <input type="password" class="form-control" id="password" name="password" required>
                                </div>
                                <button type="submit" class="btn btn-primary w-100">Anmelden</button>
                            </form>
                        </div>
                         <div class="card-footer text-center">
                             Noch kein Konto? <a href="index.php?page=register">Registrieren</a>
                         </div>
                    </div>
                </div>
            </div>
            <?php
            break; // Ende Login

        case 'register':
             if (is_logged_in()) redirect();
             // Öffentlich registrierbare Domains holen
             $stmt_dom = $pdo->query("SELECT id, domain_name FROM domains WHERE is_public_registrable = 1 ORDER BY domain_name");
             $public_domains = $stmt_dom->fetchAll();
            ?>
             <div class="row justify-content-center">
                <div class="col-md-6 col-lg-5">
                    <h2 class="text-center mb-4">Registrieren</h2>
                     <div class="card">
                         <div class="card-body">
                             <?php if (empty($public_domains)): ?>
                                 <div class="alert alert-warning">Aktuell sind keine Domains für die öffentliche Registrierung freigegeben.</div>
                             <?php else: ?>
                                 <form method="POST" action="index.php?action=register">
                                     <input type="hidden" name="action" value="register">
                                     <div class="mb-3">
                                         <label for="username" class="form-label">Benutzername</label>
                                         <input type="text" class="form-control" id="username" name="username" pattern="[a-zA-Z0-9._-]+" title="Nur Buchstaben, Zahlen, Punkt, Unterstrich, Bindestrich" required>
                                     </div>
                                      <div class="mb-3">
                                        <label for="domain_id" class="form-label">@ Domain auswählen</label>
                                        <select class="form-select" id="domain_id" name="domain_id" required>
                                            <option value="" selected disabled>Bitte wählen...</option>
                                            <?php foreach ($public_domains as $domain): ?>
                                                <option value="<?= $domain['id'] ?>"><?= htmlspecialchars($domain['domain_name']) ?></option>
                                            <?php endforeach; ?>
                                        </select>
                                     </div>
                                     <div class="mb-3">
                                         <label for="password" class="form-label">Passwort (min. 6 Zeichen)</label>
                                         <input type="password" class="form-control" id="password" name="password" required minlength="6">
                                     </div>
                                     <div class="mb-3">
                                         <label for="password_confirm" class="form-label">Passwort bestätigen</label>
                                         <input type="password" class="form-control" id="password_confirm" name="password_confirm" required>
                                     </div>
                                     <button type="submit" class="btn btn-success w-100">Registrieren</button>
                                 </form>
                             <?php endif; ?>
                         </div>
                          <div class="card-footer text-center">
                             Bereits registriert? <a href="index.php?page=login">Anmelden</a>
                         </div>
                     </div>
                </div>
            </div>
            <?php
            break; // Ende Register


        // --- Webmail-Seiten (auch für Admin-Inspektion nutzbar) ---
        case 'inbox':
        case 'sent':
        case 'trash':
        case 'admin_mailbox_view': // Diese Seite dient als Container für die Mailbox-Ansicht des Admins
             require_login(); // Grundlegende Anmeldung erforderlich

             // Sicherstellen, dass bei 'admin_mailbox_view' der Admin auch Admin ist und ein Ziel ausgewählt hat
             if ($page === 'admin_mailbox_view' && !(is_admin() && isset($_SESSION['viewing_user_id']))) {
                 $_SESSION['error_message'] = "Ungültiger Zugriff auf Admin-Mailbox-Ansicht.";
                 clear_admin_view_session();
                 redirect('index.php?page=admin_users');
             }

             $current_user_id_for_view = get_current_view_user_id();
             $current_folder = get_folder_name($folder);
             $is_admin_view = ($page === 'admin_mailbox_view');

             // Mails für den aktuellen Ordner holen
             $stmt_emails = $pdo->prepare("
                 SELECT
                     er.id as recipient_email_id, er.is_read, er.folder,
                     e.id as email_id, e.subject, e.sent_at,
                     sender.username as sender_username, sender_domain.domain_name as sender_domain,
                     GROUP_CONCAT(DISTINCT CONCAT(rcp_user.username, '@', rcp_domain.domain_name) SEPARATOR ', ') as recipient_list
                 FROM email_recipients er
                 JOIN emails e ON er.email_id = e.id
                 JOIN users sender ON e.sender_user_id = sender.id
                 JOIN domains sender_domain ON sender.domain_id = sender_domain.id
                 -- Join, um Empfängerlisten zu bekommen (kann performance-intensiv sein)
                 LEFT JOIN email_recipients er_list ON e.id = er_list.email_id AND er_list.folder = 'INBOX' -- Nur echte Empfänger
                 LEFT JOIN users rcp_user ON er_list.recipient_user_id = rcp_user.id
                 LEFT JOIN domains rcp_domain ON rcp_user.domain_id = rcp_domain.id
                 WHERE er.recipient_user_id = ? AND er.folder = ?
                 GROUP BY er.id, e.id, sender.id, sender_domain.id -- Gruppieren, um Empfänger zu aggregieren
                 ORDER BY e.sent_at DESC
             ");
             $stmt_emails->execute([$current_user_id_for_view, $current_folder]);
             $emails = $stmt_emails->fetchAll();

             // URL-Präfix für Links (abhängig vom Modus)
             $base_link_page = $is_admin_view ? 'admin_mailbox_view' : ''; // Normale Links gehen ohne Page-Präfix
             $view_page_link = $is_admin_view ? 'admin_mailbox_view_email' : 'view_email';

            ?>
            <div class="row">
                <div class="col-md-3 col-lg-2">
                    <?php if (!$is_admin_view): // Nur für normale User ?>
                        <div class="d-grid gap-2 mb-3">
                            <a href="index.php?page=compose" class="btn btn-primary"><i class="fas fa-pencil-alt"></i> Verfassen</a>
                        </div>
                    <?php endif; ?>
                    <ul class="nav nav-pills flex-column">
                        <li class="nav-item">
                            <a class="nav-link <?= ($current_folder === 'INBOX') ? 'active' : '' ?>" href="index.php?page=<?= $base_link_page ?>&folder=inbox">
                                <i class="fas fa-inbox fa-fw me-2"></i> Posteingang
                                <?php /* Optional: Ungelesene Zählen (Performance!)
                                $stmt_unread = $pdo->prepare("SELECT COUNT(*) as count FROM email_recipients WHERE recipient_user_id = ? AND folder='INBOX' AND is_read = 0");
                                $stmt_unread->execute([$current_user_id_for_view]);
                                $unread_count = $stmt_unread->fetch()['count'];
                                if ($unread_count > 0) echo '<span class="badge bg-danger float-end">'.$unread_count.'</span>';
                                */ ?>
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link <?= ($current_folder === 'SENT') ? 'active' : '' ?>" href="index.php?page=<?= $base_link_page ?>&folder=sent">
                                <i class="fas fa-paper-plane fa-fw me-2"></i> Gesendet
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link <?= ($current_folder === 'TRASH') ? 'active' : '' ?>" href="index.php?page=<?= $base_link_page ?>&folder=trash">
                                <i class="fas fa-trash fa-fw me-2"></i> Papierkorb
                            </a>
                        </li>
                    </ul>
                </div>
                <div class="col-md-9 col-lg-10">
                    <h4><?= htmlspecialchars(ucfirst(strtolower($current_folder))) ?></h4>
                    <hr>
                    <?php if (empty($emails)): ?>
                        <p class="text-muted">Dieser Ordner ist leer.</p>
                    <?php else: ?>
                        <div class="list-group">
                            <?php foreach ($emails as $email):
                                $sender_full = $email['sender_username'] . '@' . $email['sender_domain'];
                                $subject_display = !empty($email['subject']) ? $email['subject'] : '(Kein Betreff)';
                                $read_class = $email['is_read'] ? '' : 'unread';
                                $view_link = "index.php?page={$view_page_link}&re_id={$email['recipient_email_id']}";
                            ?>
                            <div class="list-group-item list-group-item-action email-item <?= $read_class ?>">
                                <div class="d-flex w-100 justify-content-between">
                                     <h5 class="mb-1 flex-grow-1">
                                         <a href="<?= $view_link ?>" class="text-decoration-none text-dark stretched-link">
                                             <?php if ($current_folder === 'SENT'): ?>
                                                <span class="text-muted me-2">An:</span><?= htmlspecialchars($email['recipient_list'] ?: 'Unbekannt') ?>
                                             <?php else: ?>
                                                 <span class="text-muted me-2">Von:</span><?= htmlspecialchars($sender_full) ?>
                                             <?php endif; ?>
                                             - <?= htmlspecialchars($subject_display) ?>
                                         </a>
                                     </h5>
                                    <small class="text-muted flex-shrink-0 ms-3" title="<?= date('d.m.Y H:i', strtotime($email['sent_at'])) ?>">
                                        <?= date('d.m.y H:i', strtotime($email['sent_at'])) ?>
                                    </small>
                                </div>
                                <!-- Aktionen direkt hier einfügen? Oder erst in der Detailansicht -->
                                 <div class="mt-1">
                                     <?php if ($current_folder !== 'TRASH'): ?>
                                        <a href="index.php?action=move_to_trash&re_id=<?= $email['recipient_email_id'] ?>&folder=<?= $folder ?>" class="btn btn-sm btn-outline-secondary me-2" title="In Papierkorb verschieben"><i class="fas fa-trash"></i></a>
                                     <?php else: ?>
                                         <a href="index.php?action=delete_permanently&re_id=<?= $email['recipient_email_id'] ?>&folder=<?= $folder ?>" class="btn btn-sm btn-outline-danger me-2" onclick="return confirm('Diese E-Mail wirklich endgültig löschen?')" title="Endgültig löschen"><i class="fas fa-times-circle"></i></a>
                                     <?php endif; ?>
                                      <?php if ($email['is_read']): ?>
                                        <a href="index.php?action=mark_unread&re_id=<?= $email['recipient_email_id'] ?>&folder=<?= $folder ?>" class="btn btn-sm btn-outline-secondary" title="Als ungelesen markieren"><i class="fas fa-envelope"></i></a>
                                      <?php endif; ?>
                                 </div>
                            </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
            <?php
            break; // Ende Mailbox-Listenansicht

        case 'compose':
            require_login();
             // Sicherstellen, dass Admin nicht aus Versehen aus fremdem Postfach sendet
            if (isset($_SESSION['viewing_user_id'])) {
                $_SESSION['error_message'] = "Senden ist im Inspektionsmodus nicht möglich.";
                redirect("index.php?page=admin_mailbox_view&folder=inbox");
            }
            ?>
            <h3>Neue E-Mail verfassen</h3>
            <hr>
            <form method="POST" action="index.php?action=send_email">
                <input type="hidden" name="action" value="send_email">
                 <div class="mb-3">
                    <label for="recipients" class="form-label">An (mehrere durch Komma trennen):</label>
                    <input type="text" class="form-control" id="recipients" name="recipients" placeholder="user1@internal.local, user2@projekt-secret.local" required>
                 </div>
                 <div class="mb-3">
                    <label for="subject" class="form-label">Betreff:</label>
                    <input type="text" class="form-control" id="subject" name="subject">
                 </div>
                 <div class="mb-3">
                    <label for="body" class="form-label">Nachricht:</label>
                    <textarea class="form-control" id="body" name="body" rows="10" required></textarea>
                 </div>
                 <button type="submit" class="btn btn-primary"><i class="fas fa-paper-plane"></i> Senden</button>
                 <a href="index.php?page=inbox" class="btn btn-secondary">Abbrechen</a>
            </form>
            <?php
            break; // Ende Compose

        case 'view_email':
        case 'admin_mailbox_view_email':
            require_login();
            $re_id = isset($_GET['re_id']) ? (int)$_GET['re_id'] : 0;
            $current_user_id_for_view = get_current_view_user_id();
            $is_admin_view = ($page === 'admin_mailbox_view_email');
            $back_link_page = $is_admin_view ? 'admin_mailbox_view' : 'inbox'; // Wohin zurück?

             if ($re_id <= 0 || !$current_user_id_for_view) {
                $_SESSION['error_message'] = "Ungültige E-Mail-Anfrage.";
                redirect("index.php?page={$back_link_page}");
             }

             // E-Mail Daten holen und sicherstellen, dass sie dem User gehört (oder Admin sie anschaut)
             $stmt = $pdo->prepare("
                SELECT
                    er.id as recipient_email_id, er.folder, er.is_read,
                    e.*,
                    sender.username as sender_username, sender_domain.domain_name as sender_domain,
                    GROUP_CONCAT(DISTINCT CONCAT(rcp_user.username, '@', rcp_domain.domain_name) SEPARATOR ', ') as recipient_list
                FROM email_recipients er
                JOIN emails e ON er.email_id = e.id
                JOIN users sender ON e.sender_user_id = sender.id
                JOIN domains sender_domain ON sender.domain_id = sender_domain.id
                LEFT JOIN email_recipients er_list ON e.id = er_list.email_id AND er_list.folder = 'INBOX'
                LEFT JOIN users rcp_user ON er_list.recipient_user_id = rcp_user.id
                LEFT JOIN domains rcp_domain ON rcp_user.domain_id = rcp_domain.id
                WHERE er.id = ? AND er.recipient_user_id = ?
                GROUP BY er.id, e.id, sender.id, sender_domain.id
             ");
             $stmt->execute([$re_id, $current_user_id_for_view]);
             $email = $stmt->fetch();

             if (!$email) {
                  $_SESSION['error_message'] = "E-Mail nicht gefunden oder Zugriff verweigert.";
                  redirect("index.php?page={$back_link_page}");
             }

             // Als gelesen markieren (wenn im Posteingang und noch ungelesen)
             if ($email['folder'] === 'INBOX' && !$email['is_read']) {
                 $stmt_mark_read = $pdo->prepare("UPDATE email_recipients SET is_read = 1 WHERE id = ?");
                 $stmt_mark_read->execute([$re_id]);
             }

             $sender_full = htmlspecialchars($email['sender_username'] . '@' . $email['sender_domain']);
             $recipients_display = htmlspecialchars($email['recipient_list'] ?: 'Unbekannt');
             $folder_display = ucfirst(strtolower($email['folder']));

            ?>
            <div class="d-flex justify-content-between align-items-center mb-3">
                 <a href="index.php?page=<?= $back_link_page ?>&folder=<?= strtolower($email['folder']) ?>" class="btn btn-outline-secondary"><i class="fas fa-arrow-left"></i> Zurück zu <?= $folder_display ?></a>
                 <div>
                      <?php if ($email['folder'] !== 'TRASH'): ?>
                        <a href="index.php?action=move_to_trash&re_id=<?= $email['recipient_email_id'] ?>&folder=<?= strtolower($email['folder']) ?>" class="btn btn-outline-secondary" title="In Papierkorb verschieben"><i class="fas fa-trash"></i></a>
                      <?php else: ?>
                          <a href="index.php?action=delete_permanently&re_id=<?= $email['recipient_email_id'] ?>&folder=<?= strtolower($email['folder']) ?>" class="btn btn-outline-danger" onclick="return confirm('Diese E-Mail wirklich endgültig löschen?')" title="Endgültig löschen"><i class="fas fa-times-circle"></i></a>
                      <?php endif; ?>
                       <?php if (!$is_admin_view && $email['folder'] !== 'SENT'): // Antworten etc. nur für normale User und nicht aus Gesendet ?>
                            <a href="index.php?page=compose&reply_to=<?= $re_id ?>" class="btn btn-outline-primary ms-2 disabled"><i class="fas fa-reply"></i> Antworten</a> <!-- Antworten-Logik nicht implementiert -->
                       <?php endif; ?>
                 </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h4 class="mb-0"><?= htmlspecialchars($email['subject'] ?: '(Kein Betreff)') ?></h4>
                </div>
                <div class="card-body">
                    <p><strong>Von:</strong> <?= $sender_full ?></p>
                    <p><strong>An:</strong> <?= $recipients_display ?></p>
                    <p><strong>Datum:</strong> <?= date('d.m.Y H:i:s', strtotime($email['sent_at'])) ?></p>
                    <hr>
                    <div class="email-body">
                        <?= nl2br(htmlspecialchars($email['body'])) // Einfache Textanzeige, nl2br für Zeilenumbrüche ?>
                        <?php /* Alternativ für HTML-Mails (VORSICHT: XSS-Gefahr! Sanitization nötig!): echo $email['body']; */ ?>
                    </div>
                </div>
            </div>
            <?php
            break; // Ende View Email

        // --- Admin Seiten ---
        case 'admin_dashboard':
            require_admin();
            clear_admin_view_session(); // Sicherstellen, dass keine Inspektions-Session aktiv ist

            // --- THIS IS AN OPEN SOURCE VIRTUAL MAIL SYSTEM CREATED BY GOOGLE GEMINI
            // --- IF SOMEONE SOLD THIS TO YOU, YOU'VE BEEN SCAMMED https://github.com/mzl-alex/virtual-mail


            // Statistiken holen
            $stats = [];
            $stats['domains'] = $pdo->query("SELECT COUNT(*) FROM domains")->fetchColumn();
            $stats['users'] = $pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
            $stats['total_emails'] = $pdo->query("SELECT COUNT(*) FROM emails")->fetchColumn();
            $stats['total_storage'] = $pdo->query("SELECT SUM(storage_used_bytes) FROM users")->fetchColumn();
            $stats['access_logs'] = $pdo->query("SELECT COUNT(*) FROM admin_mailbox_access_log")->fetchColumn();

            ?>
            <h2>Admin Dashboard</h2>
            <hr>
            <div class="row">
                 <div class="col-md-4 mb-3">
                    <div class="card text-white bg-primary">
                        <div class="card-body">
                            <h5 class="card-title"><i class="fas fa-globe"></i> Domains</h5>
                            <p class="card-text fs-4"><?= $stats['domains'] ?></p>
                            <a href="index.php?page=admin_domains" class="text-white stretched-link">Verwalten</a>
                        </div>
                    </div>
                </div>
                 <div class="col-md-4 mb-3">
                    <div class="card text-white bg-success">
                        <div class="card-body">
                            <h5 class="card-title"><i class="fas fa-users"></i> Benutzerkonten</h5>
                            <p class="card-text fs-4"><?= $stats['users'] ?></p>
                             <a href="index.php?page=admin_users" class="text-white stretched-link">Verwalten</a>
                        </div>
                    </div>
                </div>
                <div class="col-md-4 mb-3">
                    <div class="card text-dark bg-light">
                         <div class="card-body">
                            <h5 class="card-title"><i class="fas fa-envelope"></i> Gesendete E-Mails (gesamt)</h5>
                            <p class="card-text fs-4"><?= $stats['total_emails'] ?></p>
                            <span class="text-muted">Einblick über Postfächer</span>
                        </div>
                    </div>
                </div>
                 <div class="col-md-4 mb-3">
                    <div class="card text-dark bg-warning">
                         <div class="card-body">
                            <h5 class="card-title"><i class="fas fa-database"></i> Geschätzter Speicher</h5>
                            <p class="card-text fs-4"><?= format_bytes($stats['total_storage']) ?></p>
                            <span class="text-muted">Summe der Benutzerwerte</span>
                        </div>
                    </div>
                </div>
                 <div class="col-md-4 mb-3">
                    <div class="card text-white bg-danger">
                        <div class="card-body">
                            <h5 class="card-title"><i class="fas fa-clipboard-list"></i> Postfach-Zugriffe (Admin)</h5>
                            <p class="card-text fs-4"><?= $stats['access_logs'] ?></p>
                             <a href="index.php?page=admin_logs" class="text-white stretched-link">Protokoll anzeigen</a>
                        </div>
                    </div>
                </div>
            </div>
            <?php
            break; // Ende Admin Dashboard

        case 'admin_domains':
            require_admin();
            clear_admin_view_session();
            $domains = $pdo->query("SELECT * FROM domains ORDER BY domain_name")->fetchAll();
            ?>
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h2>Domain Verwaltung</h2>
                <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addDomainModal">
                   <i class="fas fa-plus"></i> Neue Domain hinzufügen
                </button>
            </div>
            <table class="table table-striped table-hover">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Domainname</th>
                        <th>Öffentlich registrierbar?</th>
                        <th>Erstellt am</th>
                        <th>Aktionen</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($domains as $domain): ?>
                    <tr>
                        <td><?= $domain['id'] ?></td>
                        <td><?= htmlspecialchars($domain['domain_name']) ?></td>
                        <td><?= $domain['is_public_registrable'] ? '<span class="badge bg-success">Ja</span>' : '<span class="badge bg-secondary">Nein</span>' ?></td>
                        <td><?= date('d.m.Y H:i', strtotime($domain['created_at'])) ?></td>
                        <td>
                           <button type="button" class="btn btn-sm btn-warning" data-bs-toggle="modal" data-bs-target="#editDomainModal<?= $domain['id'] ?>" title="Bearbeiten"><i class="fas fa-edit"></i></button>
                           <a href="index.php?action=delete_domain&domain_id=<?= $domain['id'] ?>" class="btn btn-sm btn-danger" onclick="return confirm('Domain <?= htmlspecialchars($domain['domain_name']) ?> wirklich löschen? Dies geht nur, wenn keine Benutzer mehr zugewiesen sind.')" title="Löschen"><i class="fas fa-trash"></i></a>

                           <!-- Edit Modal -->
                            <div class="modal fade" id="editDomainModal<?= $domain['id'] ?>" tabindex="-1" aria-labelledby="editDomainModalLabel<?= $domain['id'] ?>" aria-hidden="true">
                              <div class="modal-dialog">
                                <div class="modal-content">
                                  <div class="modal-header">
                                    <h5 class="modal-title" id="editDomainModalLabel<?= $domain['id'] ?>">Domain bearbeiten: <?= htmlspecialchars($domain['domain_name']) ?></h5>
                                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                  </div>
                                  <form method="POST" action="index.php?action=edit_domain&domain_id=<?= $domain['id'] ?>">
                                      <input type="hidden" name="action" value="edit_domain">
                                      <div class="modal-body">
                                            <div class="mb-3">
                                                <label for="edit_domain_name<?= $domain['id'] ?>" class="form-label">Domainname</label>
                                                <input type="text" class="form-control" id="edit_domain_name<?= $domain['id'] ?>" name="domain_name" value="<?= htmlspecialchars($domain['domain_name']) ?>" required>
                                            </div>
                                            <div class="form-check">
                                              <input class="form-check-input" type="checkbox" value="1" id="edit_is_public<?= $domain['id'] ?>" name="is_public_registrable" <?= $domain['is_public_registrable'] ? 'checked' : '' ?>>
                                              <label class="form-check-label" for="edit_is_public<?= $domain['id'] ?>">
                                                Öffentliche Registrierung erlauben
                                              </label>
                                            </div>
                                      </div>
                                      <div class="modal-footer">
                                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Abbrechen</button>
                                        <button type="submit" class="btn btn-primary">Speichern</button>
                                      </div>
                                  </form>
                                </div>
                              </div>
                            </div>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                     <?php if (empty($domains)): ?>
                        <tr><td colspan="5" class="text-center text-muted">Keine Domains gefunden.</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>

            <!-- Add Modal -->
            <div class="modal fade" id="addDomainModal" tabindex="-1" aria-labelledby="addDomainModalLabel" aria-hidden="true">
              <div class="modal-dialog">
                <div class="modal-content">
                  <div class="modal-header">
                    <h5 class="modal-title" id="addDomainModalLabel">Neue Domain hinzufügen</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                  </div>
                   <form method="POST" action="index.php?action=add_domain">
                      <input type="hidden" name="action" value="add_domain">
                      <div class="modal-body">
                            <div class="mb-3">
                                <label for="add_domain_name" class="form-label">Domainname</label>
                                <input type="text" class="form-control" id="add_domain_name" name="domain_name" placeholder="z.B. firma.local" required>
                            </div>
                            <div class="form-check">
                              <input class="form-check-input" type="checkbox" value="1" id="add_is_public" name="is_public_registrable" checked>
                              <label class="form-check-label" for="add_is_public">
                                Öffentliche Registrierung erlauben
                              </label>
                            </div>
                      </div>
                      <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Abbrechen</button>
                        <button type="submit" class="btn btn-primary">Hinzufügen</button>
                      </div>
                   </form>
                </div>
              </div>
            </div>
            <?php
            break; // Ende Admin Domains

        case 'admin_users':
            require_admin();
            clear_admin_view_session();
            $users = $pdo->query("
                SELECT u.*, d.domain_name
                FROM users u
                JOIN domains d ON u.domain_id = d.id
                ORDER BY d.domain_name, u.username
            ")->fetchAll();
            $all_domains = $pdo->query("SELECT id, domain_name FROM domains ORDER BY domain_name")->fetchAll(); // Für Formulare
            ?>
             <div class="d-flex justify-content-between align-items-center mb-3">
                <h2>Benutzer Verwaltung</h2>
                <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addUserModal">
                   <i class="fas fa-user-plus"></i> Neuen Benutzer hinzufügen
                </button>
            </div>
             <table class="table table-striped table-hover table-sm">
                 <thead>
                    <tr>
                        <th>ID</th>
                        <th>E-Mail</th>
                        <th>Voller Name</th>
                        <th>Admin?</th>
                        <th>Speicher</th>
                        <th>Letzter Login</th>
                        <th>Erstellt</th>
                        <th>Aktionen</th>
                    </tr>
                 </thead>
                 <tbody>
                    <?php foreach ($users as $user):
                        $user_email = get_user_email($user);
                    ?>
                    <tr>
                        <td><?= $user['id'] ?></td>
                        <td><?= $user_email ?></td>
                        <td><?= htmlspecialchars($user['full_name'] ?: '-') ?></td>
                        <td><?= $user['is_admin'] ? '<span class="badge bg-danger">Ja</span>' : '<span class="badge bg-secondary">Nein</span>' ?></td>
                        <td title="<?= $user['storage_used_bytes'] ?> Bytes"><?= format_bytes($user['storage_used_bytes']) ?></td>
                        <td><?= $user['last_login'] ? date('d.m.Y H:i', strtotime($user['last_login'])) : '-' ?></td>
                        <td><?= date('d.m.Y', strtotime($user['created_at'])) ?></td>
                        <td>
                            <button type="button" class="btn btn-sm btn-info" data-bs-toggle="modal" data-bs-target="#viewMailboxModal<?= $user['id'] ?>" title="Postfach einsehen"><i class="fas fa-eye"></i></button>
                            <button type="button" class="btn btn-sm btn-warning" data-bs-toggle="modal" data-bs-target="#editUserModal<?= $user['id'] ?>" title="Bearbeiten"><i class="fas fa-edit"></i></button>
                            <?php if ($user['id'] != $_SESSION['user_id']): // Selbstlöschung verhindern ?>
                            <a href="index.php?action=delete_user&user_id=<?= $user['id'] ?>" class="btn btn-sm btn-danger" onclick="return confirm('Benutzer <?= $user_email ?> wirklich löschen? Alle seine E-Mails werden ebenfalls gelöscht!')" title="Löschen"><i class="fas fa-trash"></i></a>
                            <?php endif; ?>

                           <!-- View Mailbox Justification Modal -->
                            <div class="modal fade" id="viewMailboxModal<?= $user['id'] ?>" tabindex="-1" aria-labelledby="viewMailboxModalLabel<?= $user['id'] ?>" aria-hidden="true">
                              <div class="modal-dialog">
                                <div class="modal-content">
                                  <div class="modal-header">
                                    <h5 class="modal-title" id="viewMailboxModalLabel<?= $user['id'] ?>">Zugriff auf Postfach: <?= $user_email ?></h5>
                                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                  </div>
                                  <form method="POST" action="index.php?action=access_mailbox&user_id=<?= $user['id'] ?>">
                                      <input type="hidden" name="action" value="access_mailbox">
                                      <div class="modal-body">
                                            <p class="text-danger fw-bold">Achtung: Sie sind dabei, auf das Postfach eines anderen Benutzers zuzugreifen.</p>
                                            <div class="mb-3">
                                                <label for="justification_reason<?= $user['id'] ?>" class="form-label">Grund für den Zugriff (Pflichtfeld):</label>
                                                <textarea class="form-control" id="justification_reason<?= $user['id'] ?>" name="justification_reason" rows="3" placeholder="z.B. Durchsuchungsbeschluss AZ 123/45, Technische Analyse wegen Fehlermeldung XYZ" required></textarea>
                                            </div>
                                            <div class="form-check">
                                              <input class="form-check-input" type="checkbox" value="1" id="legitimate_interest<?= $user['id'] ?>" name="legitimate_interest" required>
                                              <label class="form-check-label" for="legitimate_interest<?= $user['id'] ?>">
                                                Ich bestätige ein berechtigtes Interesse für diesen Zugriff und dass der Grund korrekt dokumentiert wurde.
                                              </label>
                                            </div>
                                      </div>
                                      <div class="modal-footer">
                                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Abbrechen</button>
                                        <button type="submit" class="btn btn-danger"><i class="fas fa-user-secret"></i> Zugriff bestätigen & Postfach öffnen</button>
                                      </div>
                                  </form>
                                </div>
                              </div>
                            </div>

                            <!-- Edit User Modal -->
                            <div class="modal fade" id="editUserModal<?= $user['id'] ?>" tabindex="-1" aria-labelledby="editUserModalLabel<?= $user['id'] ?>" aria-hidden="true">
                              <div class="modal-dialog modal-lg">
                                <div class="modal-content">
                                  <div class="modal-header">
                                    <h5 class="modal-title" id="editUserModalLabel<?= $user['id'] ?>">Benutzer bearbeiten: <?= $user_email ?></h5>
                                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                  </div>
                                  <form method="POST" action="index.php?action=edit_user&user_id=<?= $user['id'] ?>">
                                      <input type="hidden" name="action" value="edit_user">
                                      <div class="modal-body">
                                          <div class="row">
                                              <div class="col-md-6 mb-3">
                                                  <label for="edit_username<?= $user['id'] ?>" class="form-label">Benutzername</label>
                                                  <input type="text" class="form-control" id="edit_username<?= $user['id'] ?>" name="username" value="<?= htmlspecialchars($user['username']) ?>" required>
                                              </div>
                                              <div class="col-md-6 mb-3">
                                                  <label for="edit_domain_id<?= $user['id'] ?>" class="form-label">@ Domain</label>
                                                  <select class="form-select" id="edit_domain_id<?= $user['id'] ?>" name="domain_id" required>
                                                      <?php foreach ($all_domains as $domain): ?>
                                                          <option value="<?= $domain['id'] ?>" <?= ($user['domain_id'] == $domain['id']) ? 'selected' : '' ?>><?= htmlspecialchars($domain['domain_name']) ?></option>
                                                      <?php endforeach; ?>
                                                  </select>
                                              </div>
                                          </div>
                                          <div class="mb-3">
                                             <label for="edit_full_name<?= $user['id'] ?>" class="form-label">Voller Name (Optional)</label>
                                             <input type="text" class="form-control" id="edit_full_name<?= $user['id'] ?>" name="full_name" value="<?= htmlspecialchars($user['full_name']) ?>">
                                          </div>
                                           <div class="mb-3">
                                             <label for="edit_password<?= $user['id'] ?>" class="form-label">Neues Passwort (leer lassen, um nicht zu ändern)</label>
                                             <input type="password" class="form-control" id="edit_password<?= $user['id'] ?>" name="password" minlength="6" aria-describedby="passwordHelpBlock<?= $user['id'] ?>">
                                             <div id="passwordHelpBlock<?= $user['id'] ?>" class="form-text">
                                               Mindestens 6 Zeichen.
                                             </div>
                                          </div>
                                          <div class="form-check">
                                              <input class="form-check-input" type="checkbox" value="1" id="edit_is_admin<?= $user['id'] ?>" name="is_admin" <?= $user['is_admin'] ? 'checked' : '' ?> <?= ($user['id'] == $_SESSION['user_id']) ? 'disabled' : '' /* Admin kann sich nicht selbst degradieren */ ?>>
                                              <label class="form-check-label" for="edit_is_admin<?= $user['id'] ?>">
                                                Ist Administrator?
                                              </label>
                                              <?php if($user['id'] == $_SESSION['user_id']): ?>
                                                  <small class="text-muted d-block">Du kannst deine eigenen Adminrechte nicht entfernen.</small>
                                              <?php endif; ?>
                                          </div>
                                      </div>
                                      <div class="modal-footer">
                                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Abbrechen</button>
                                        <button type="submit" class="btn btn-primary">Speichern</button>
                                      </div>
                                  </form>
                                </div>
                              </div>
                            </div>

                        </td>
                    </tr>
                    <?php endforeach; ?>
                     <?php if (empty($users)): ?>
                        <tr><td colspan="8" class="text-center text-muted">Keine Benutzer gefunden.</td></tr>
                    <?php endif; ?>
                 </tbody>
            </table>

            <!-- Add User Modal -->
             <div class="modal fade" id="addUserModal" tabindex="-1" aria-labelledby="addUserModalLabel" aria-hidden="true">
               <div class="modal-dialog modal-lg">
                 <div class="modal-content">
                   <div class="modal-header">
                     <h5 class="modal-title" id="addUserModalLabel">Neuen Benutzer hinzufügen</h5>
                     <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                   </div>
                   <form method="POST" action="index.php?action=add_user">
                       <input type="hidden" name="action" value="add_user">
                       <div class="modal-body">
                           <div class="row">
                               <div class="col-md-6 mb-3">
                                   <label for="add_username" class="form-label">Benutzername</label>
                                   <input type="text" class="form-control" id="add_username" name="username" required>
                               </div>
                               <div class="col-md-6 mb-3">
                                   <label for="add_domain_id" class="form-label">@ Domain</label>
                                   <select class="form-select" id="add_domain_id" name="domain_id" required>
                                       <option value="" selected disabled>Bitte wählen...</option>
                                       <?php foreach ($all_domains as $domain): ?>
                                           <option value="<?= $domain['id'] ?>"><?= htmlspecialchars($domain['domain_name']) ?></option>
                                       <?php endforeach; ?>
                                   </select>
                               </div>
                           </div>
                           <div class="mb-3">
                              <label for="add_full_name" class="form-label">Voller Name (Optional)</label>
                              <input type="text" class="form-control" id="add_full_name" name="full_name">
                           </div>
                            <div class="mb-3">
                              <label for="add_password" class="form-label">Passwort</label>
                              <input type="password" class="form-control" id="add_password" name="password" required minlength="6">
                           </div>
                           <div class="form-check">
                               <input class="form-check-input" type="checkbox" value="1" id="add_is_admin" name="is_admin">
                               <label class="form-check-label" for="add_is_admin">
                                 Ist Administrator?
                               </label>
                           </div>
                       </div>
                       <div class="modal-footer">
                         <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Abbrechen</button>
                         <button type="submit" class="btn btn-primary">Hinzufügen</button>
                       </div>
                   </form>
                 </div>
               </div>
             </div>
            <?php
            break; // Ende Admin Users

        case 'admin_logs':
             require_admin();
             clear_admin_view_session();
             $logs = $pdo->query("
                SELECT
                    al.*,
                    admin_user.username as admin_username, admin_domain.domain_name as admin_domain,
                    target_user.username as target_username, target_domain.domain_name as target_domain
                FROM admin_mailbox_access_log al
                JOIN users admin_user ON al.admin_user_id = admin_user.id
                JOIN domains admin_domain ON admin_user.domain_id = admin_domain.id
                JOIN users target_user ON al.target_user_id = target_user.id
                JOIN domains target_domain ON target_user.domain_id = target_domain.id
                ORDER BY al.access_timestamp DESC
             ")->fetchAll();
            ?>
             <h2>Admin Zugriffsprotokoll auf Postfächer</h2>
             <hr>
             <table class="table table-striped table-hover table-sm">
                <thead>
                    <tr>
                        <th>Zeitstempel</th>
                        <th>Admin</th>
                        <th>Ziel-Postfach</th>
                        <th>Grund / Rechtfertigung</th>
                    </tr>
                </thead>
                <tbody>
                     <?php foreach ($logs as $log):
                        $admin_email = htmlspecialchars($log['admin_username'] . '@' . $log['admin_domain']);
                        $target_email = htmlspecialchars($log['target_username'] . '@' . $log['target_domain']);
                    ?>
                    <tr>
                        <td><?= date('d.m.Y H:i:s', strtotime($log['access_timestamp'])) ?></td>
                        <td><?= $admin_email ?></td>
                        <td><?= $target_email ?></td>
                        <td><?= nl2br(htmlspecialchars($log['justification_reason'])) ?></td>
                    </tr>
                    <?php endforeach; ?>
                    <?php if (empty($logs)): ?>
                        <tr><td colspan="4" class="text-center text-muted">Keine Protokolleinträge gefunden.</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
            <?php
            break; // Ende Admin Logs


        // --- Fallback / Unbekannte Seite ---
        default:
            require_login(); // Wenn nicht öffentlich und unbekannt -> Login erforderlich
            // Zeige eine 404-Seite oder leite zum Dashboard/Inbox um
            ?>
            <h2>Seite nicht gefunden</h2>
            <p>Die angeforderte Seite '<?= htmlspecialchars($page) ?>' existiert nicht.</p>
            <a href="index.php" class="btn btn-primary">Zur Startseite</a>
            <?php
            break;
    } // Ende switch($page)

    // --- THIS IS AN OPEN SOURCE VIRTUAL MAIL SYSTEM CREATED BY GOOGLE GEMINI
    // --- IF SOMEONE SOLD THIS TO YOU, YOU'VE BEEN SCAMMED https://github.com/mzl-alex/virtual-mail


    ?>

</div><!-- /.container -->

<!-- Bootstrap JS Bundle (Popper included) -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" crossorigin="anonymous"></script>
<!-- Optional: Eigene JS-Datei für zusätzliche Interaktivität -->
<!-- <script src="script.js"></script> -->
</body>
</html>
<?php // --- HTML Output Ende --- ?>