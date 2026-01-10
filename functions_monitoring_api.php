<?php
// This library provides helper functions for the monitoring API.
// It is designed to work with the WAMP stack and the monitoring database.
//
// Key differences from the original version:
// - It prefers search_observations_view (when available) for filtering
//   and date_obs support, with fallback to the `birds` table.
// - When date_obs is missing, dates are parsed from the `date` column
//   (dd/mm/YYYY) using STR_TO_DATE.
// - Geo lookups join to `sites` and `points` tables to obtain
//   latitude/longitude.  If birds.x_num/y_num are ever populated in
//   future, they will be used; otherwise the fallback coordinates come
//   from the site or point.

// Database credentials.  Adjust these constants to match your WAMP
// environment.  By default, WAMP uses 'root' with an empty password.
define('DB_HOST', '127.0.0.1');
define('DB_NAME', 'monitoring');
define('DB_USER', 'root');
define('DB_PASS', '');

/**
 * Return a PDO connection to the monitoring database.
 *
 * @return PDO
 */
function db()
{
    static $pdo;
    if ($pdo instanceof PDO) {
        return $pdo;
    }
    $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';
    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ];
    try {
        $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
    } catch (PDOException $e) {
        http_response_code(500);
        echo json_encode([
            'error'   => 'DB connection failed',
            'message' => $e->getMessage(),
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }
    return $pdo;
}

class ApiException extends Exception
{
    public int $status;

    public function __construct(string $message, int $status = 400)
    {
        parent::__construct($message);
        $this->status = $status;
    }
}

function api_error(string $message, int $status = 400): void
{
    throw new ApiException($message, $status);
}

function read_body_params(): array
{
    if (!empty($_POST)) {
        return $_POST;
    }
    $raw = file_get_contents('php://input');
    if (!$raw) {
        return [];
    }
    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}

function now_ts(): string
{
    return date('Y-m-d H:i:s');
}

function messages_upload_dir(): string
{
    $dir = __DIR__ . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . 'messages';
    if (!is_dir($dir)) {
        mkdir($dir, 0775, true);
    }
    return $dir;
}

function has_messages_table(): bool
{
    static $has;
    if (is_bool($has)) {
        return $has;
    }
    try {
        $pdo = db();
        $st = $pdo->prepare('SELECT table_name FROM information_schema.tables WHERE table_schema = :schema AND table_name IN ("messagerie","message","messages")');
        $st->execute([':schema' => DB_NAME]);
        $has = (bool)$st->fetchColumn();
    } catch (Throwable $e) {
        $has = false;
    }
    if (!$has) {
        try {
            $pdo = db();
            $st = $pdo->query("SHOW TABLES LIKE 'messagerie'");
            if ($st && $st->fetchColumn()) {
                $has = true;
            } else {
                $st = $pdo->query("SHOW TABLES LIKE 'message'");
                if ($st && $st->fetchColumn()) {
                    $has = true;
                } else {
                    $st = $pdo->query("SHOW TABLES LIKE 'messages'");
                    $has = (bool)($st && $st->fetchColumn());
                }
            }
        } catch (Throwable $e) {
            $has = false;
        }
    }
    return $has;
}

function message_table_name(): string
{
    static $name;
    if (is_string($name) && $name !== '') {
        return $name;
    }
    if (!has_messages_table()) {
        $name = 'messagerie';
        return $name;
    }
    $candidates = ['messagerie', 'message', 'messages'];
    try {
        $pdo = db();
        $st = $pdo->prepare('SELECT table_name FROM information_schema.tables WHERE table_schema = :schema AND table_name = :table');
        foreach ($candidates as $candidate) {
            $st->execute([
                ':schema' => DB_NAME,
                ':table' => $candidate,
            ]);
            if ($st->fetchColumn()) {
                $name = $candidate;
                return $name;
            }
        }
        $name = 'messagerie';
    } catch (Throwable $e) {
        try {
            $pdo = db();
            foreach ($candidates as $candidate) {
                $st = $pdo->query("SHOW TABLES LIKE '{$candidate}'");
                if ($st && $st->fetchColumn()) {
                    $name = $candidate;
                    return $name;
                }
            }
            $name = 'messagerie';
        } catch (Throwable $e2) {
            $name = 'messagerie';
        }
    }
    return $name;
}

function message_column_map(): array
{
    static $map;
    if (is_array($map)) {
        return $map;
    }
    $map = [];
    if (!has_messages_table()) {
        return $map;
    }
    $pdo = db();
    $table = message_table_name();
    $cols = [];
    try {
        $st = $pdo->prepare('SELECT COLUMN_NAME FROM information_schema.columns WHERE table_schema = :schema AND table_name = :table');
        $st->execute([
            ':schema' => DB_NAME,
            ':table' => $table,
        ]);
        $cols = $st->fetchAll(PDO::FETCH_COLUMN);
    } catch (Throwable $e) {
        try {
            $st = $pdo->query('DESCRIBE `' . $table . '`');
            $cols = $st ? $st->fetchAll(PDO::FETCH_COLUMN) : [];
        } catch (Throwable $e2) {
            $cols = [];
        }
    }
    $set = array_flip($cols);
    $pick = function (array $candidates) use ($set): ?string {
        foreach ($candidates as $name) {
            if (isset($set[$name])) {
                return $name;
            }
        }
        return null;
    };
    $map = [
        'sender' => $pick(['sender_id', 'sender', 'from_id', 'from_user_id', 'expediteur_id', 'id_expediteur', 'id_sender']),
        'recipient' => $pick(['recipient_id', 'recipient', 'to_id', 'to_user_id', 'destinataire_id', 'id_destinataire', 'receiver_id', 'id_receiver']),
        'body' => $pick(['body', 'message', 'contenu', 'content', 'text', 'texte', 'msg']),
        'created' => $pick(['created_at', 'created', 'sent_at', 'date', 'date_envoi', 'created_on']),
        'id' => $pick(['id', 'message_id', 'id_message', 'id_messagerie']),
        'file_path' => $pick(['file_path', 'file', 'fichier', 'piece_jointe', 'attachment', 'file_url', 'path']),
        'file_name' => $pick(['file_name', 'nom_fichier', 'fichier_nom', 'attachment_name']),
        'file_size' => $pick(['file_size', 'taille', 'size']),
        'mime_type' => $pick(['mime_type', 'type_mime', 'format']),
    ];
    return $map;
}

function sanitize_filename(string $name): string
{
    $name = basename($name);
    $name = preg_replace('/[^A-Za-z0-9._-]/', '_', $name);
    $name = trim($name, '._-');
    return $name !== '' ? $name : 'piece_jointe';
}

function parse_int($value): ?int
{
    if ($value === null || $value === '') {
        return null;
    }
    if (is_numeric($value)) {
        return (int)$value;
    }
    return null;
}

function parse_float($value): ?float
{
    if ($value === null || $value === '') {
        return null;
    }
    if (is_numeric($value)) {
        return (float)$value;
    }
    return null;
}

/**
 * Normalize a key for comparisons (trim, ASCII fold, uppercase).
 *
 * @param string|null $value
 * @return string
 */
function normalize_key(?string $value): string
{
    $value = trim((string)$value);
    if ($value === '') {
        return '';
    }
    $fallbackMap = [
        'Á' => 'A', 'À' => 'A', 'Â' => 'A', 'Ä' => 'A', 'Ã' => 'A', 'Å' => 'A', 'Æ' => 'AE',
        'Ç' => 'C',
        'É' => 'E', 'È' => 'E', 'Ê' => 'E', 'Ë' => 'E',
        'Í' => 'I', 'Ì' => 'I', 'Î' => 'I', 'Ï' => 'I',
        'Ñ' => 'N',
        'Ó' => 'O', 'Ò' => 'O', 'Ô' => 'O', 'Ö' => 'O', 'Õ' => 'O', 'Ø' => 'O', 'Œ' => 'OE',
        'Ú' => 'U', 'Ù' => 'U', 'Û' => 'U', 'Ü' => 'U',
        'Ý' => 'Y', 'Ÿ' => 'Y',
        'á' => 'a', 'à' => 'a', 'â' => 'a', 'ä' => 'a', 'ã' => 'a', 'å' => 'a', 'æ' => 'ae',
        'ç' => 'c',
        'é' => 'e', 'è' => 'e', 'ê' => 'e', 'ë' => 'e',
        'í' => 'i', 'ì' => 'i', 'î' => 'i', 'ï' => 'i',
        'ñ' => 'n',
        'ó' => 'o', 'ò' => 'o', 'ô' => 'o', 'ö' => 'o', 'õ' => 'o', 'ø' => 'o', 'œ' => 'oe',
        'ú' => 'u', 'ù' => 'u', 'û' => 'u', 'ü' => 'u',
        'ý' => 'y', 'ÿ' => 'y',
    ];
    if (function_exists('iconv')) {
        $ascii = iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $value);
        if ($ascii !== false) {
            $value = $ascii;
        } else {
            $value = strtr($value, $fallbackMap);
        }
    } else {
        $value = strtr($value, $fallbackMap);
    }
    $value = strtoupper($value);
    $value = preg_replace('/\s+/', ' ', $value);
    return $value;
}

/**
 * Normalize zone/site keys.
 *
 * @param string|null $value
 * @return string
 */
function normalize_zone_key(?string $value): string
{
    return normalize_key($value);
}

/**
 * Load zone coordinate mapping from data/zone_coords.json.
 *
 * @return array<string,array{lat:float,lon:float}>
 */
function zone_coords(): array
{
    static $coords;
    if (is_array($coords)) {
        return $coords;
    }
    $coords = [];
    $path = __DIR__ . '/data/zone_coords.json';
    if (!is_file($path)) {
        return $coords;
    }
    $raw = file_get_contents($path);
    if ($raw === false) {
        return $coords;
    }
    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        return $coords;
    }
    foreach ($decoded as $key => $value) {
        $norm = normalize_zone_key((string)$key);
        if ($norm === '' || !is_array($value)) {
            continue;
        }
        if (!array_key_exists('lat', $value) || !array_key_exists('lon', $value)) {
            continue;
        }
        $lat = is_numeric($value['lat']) ? (float)$value['lat'] : null;
        $lon = is_numeric($value['lon']) ? (float)$value['lon'] : null;
        if ($lat === null || $lon === null) {
            continue;
        }
        $coords[$norm] = ['lat' => $lat, 'lon' => $lon];
    }
    return $coords;
}

/**
 * Lookup fallback coordinates by zone name.
 *
 * @param string|null $zone
 * @return array{lat:float,lon:float}|null
 */
function lookup_zone_coords(?string $zone): ?array
{
    $key = normalize_zone_key($zone);
    if ($key === '') {
        return null;
    }
    $coords = zone_coords();
    return $coords[$key] ?? null;
}

/**
 * Lookup fallback coordinates by site (first) or zone name.
 *
 * @param string|null $site
 * @param string|null $zone
 * @return array{lat:float,lon:float}|null
 */
function lookup_site_coords(?string $site, ?string $zone = null): ?array
{
    $coords = zone_coords();
    $siteKey = normalize_zone_key($site);
    if ($siteKey === '') {
        return null;
    }
    $specials = [
        'TECHNOPOLE' => ['TECHNOPOLE', 'TECHNOPOLE DAKAR', 'TECHNOPOLE DE DAKAR'],
        'MBEUBEUSS' => ['MBEUBEUSS', 'LAC MBEUBEUSS'],
    ];
    foreach ($specials as $needle => $keys) {
        if (strpos($siteKey, $needle) !== false) {
            foreach ($keys as $key) {
                $normKey = normalize_zone_key($key);
                if (isset($coords[$normKey])) {
                    return $coords[$normKey];
                }
            }
        }
    }
    if (isset($coords[$siteKey])) {
        return $coords[$siteKey];
    }
    $candidates = [];
    $zoneKey = normalize_zone_key($zone);
    if ($zoneKey !== '' && strpos($siteKey, $zoneKey) !== false) {
        $candidates[] = trim(str_replace($zoneKey, '', $siteKey));
    }
    $candidates[] = preg_replace('/\s*\([^)]*\)\s*/', ' ', $siteKey);
    $candidates[] = preg_replace('/\s*[-\/].*$/', '', $siteKey);

    foreach ($candidates as $candidate) {
        $candidate = normalize_zone_key($candidate);
        if ($candidate === '') {
            continue;
        }
        if (isset($coords[$candidate])) {
            return $coords[$candidate];
        }
    }
    return null;
}

function is_special_site(?string $site): bool
{
    $siteKey = normalize_zone_key($site);
    if ($siteKey === '') {
        return false;
    }
    foreach (['TECHNOPOLE', 'MBEUBEUSS'] as $needle) {
        if (strpos($siteKey, $needle) !== false) {
            return true;
        }
    }
    return false;
}

function lookup_place_coords(?string $site, ?string $zone): ?array
{
    $fromSite = lookup_site_coords($site, $zone);
    if (is_array($fromSite)) {
        return $fromSite;
    }
    return lookup_zone_coords($zone);
}

/**
 * Check if the search_observations_view exists.
 *
 * @return bool
 */
function has_search_view(): bool
{
    static $hasView;
    if (is_bool($hasView)) {
        return $hasView;
    }
    $pdo = db();
    $sql = 'SELECT 1 FROM information_schema.VIEWS WHERE TABLE_SCHEMA = :schema AND TABLE_NAME = :view';
    $st = $pdo->prepare($sql);
    $st->execute([
        ':schema' => DB_NAME,
        ':view'   => 'search_observations_view',
    ]);
    $hasView = (bool)$st->fetchColumn();
    return $hasView;
}

function fetch_user_by_id(int $id): ?array
{
    $pdo = db();
    $st = $pdo->prepare('SELECT * FROM users WHERE id = :id LIMIT 1');
    $st->execute([':id' => $id]);
    $row = $st->fetch();
    return $row ?: null;
}

function fetch_user_by_email(string $email): ?array
{
    $pdo = db();
    $st = $pdo->prepare('SELECT * FROM users WHERE email = :email LIMIT 1');
    $st->execute([':email' => $email]);
    $row = $st->fetch();
    return $row ?: null;
}

function sanitize_user(array $user): array
{
    unset($user['password_hash']);
    return $user;
}

function require_session_user(array $roles = []): array
{
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    $userId = $_SESSION['user_id'] ?? null;
    if (!$userId) {
        api_error('Unauthorized', 401);
    }
    $user = fetch_user_by_id((int)$userId);
    if (!$user || ($user['status'] ?? '') !== 'active') {
        api_error('Unauthorized', 401);
    }
    if ($roles && !in_array($user['role'], $roles, true)) {
        api_error('Forbidden', 403);
    }
    return $user;
}

function set_session_user(array $user): void
{
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    $_SESSION['user_id'] = (int)$user['id'];
}

function clear_session_user(): void
{
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }
    session_destroy();
}

function register_user(array $data, ?array $actor = null): array
{
    $email = trim((string)($data['email'] ?? ''));
    $password = (string)($data['password'] ?? '');
    $fullName = trim((string)($data['full_name'] ?? ''));
    $phone = trim((string)($data['phone'] ?? ''));
    $pole = null;
    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        api_error('Invalid email', 422);
    }
    if (strlen($password) < 6) {
        api_error('Password too short', 422);
    }
    if ($fullName === '') {
        api_error('Full name required', 422);
    }
    if (fetch_user_by_email($email)) {
        api_error('Email already used', 409);
    }
    $role = 'charge_suivi';
    $allowed = ['charge_suivi', 'controleur', 'controle_qualite', 'admin'];
    if ($actor && ($actor['role'] ?? '') === 'admin' && in_array(($data['role'] ?? ''), $allowed, true)) {
        $role = (string)$data['role'];
    } elseif (!$actor && in_array(($data['role'] ?? ''), ['charge_suivi', 'controle_qualite'], true)) {
        $role = (string)$data['role'];
    }
    if ($actor && ($actor['role'] ?? '') === 'controle_qualite') {
        $role = 'charge_suivi';
        $poleValue = trim((string)($actor['pole'] ?? ''));
        $poleValue = $poleValue !== '' ? normalize_zone_key($poleValue) : '';
        $pole = $poleValue !== '' ? $poleValue : null;
    } elseif ($actor && ($actor['role'] ?? '') === 'admin') {
        $poleValue = trim((string)($data['pole'] ?? ''));
        $poleValue = $poleValue !== '' ? normalize_zone_key($poleValue) : '';
        $pole = $poleValue !== '' ? $poleValue : null;
    } elseif ($role === 'controle_qualite') {
        $poleValue = trim((string)($data['pole'] ?? ''));
        $poleValue = $poleValue !== '' ? normalize_zone_key($poleValue) : '';
        if ($poleValue === '') {
            api_error('Pole required', 422);
        }
        $pole = $poleValue;
    }
    $pdo = db();
    $st = $pdo->prepare('INSERT INTO users (full_name, email, phone, pole, role, password_hash, status, created_at, updated_at) VALUES (:full_name, :email, :phone, :pole, :role, :password_hash, :status, :created_at, :updated_at)');
    $hash = password_hash($password, PASSWORD_DEFAULT);
    $now = now_ts();
    $st->execute([
        ':full_name' => $fullName,
        ':email' => $email,
        ':phone' => $phone !== '' ? $phone : null,
        ':pole' => $pole,
        ':role' => $role,
        ':password_hash' => $hash,
        ':status' => 'active',
        ':created_at' => $now,
        ':updated_at' => $now,
    ]);
    $user = fetch_user_by_id((int)$pdo->lastInsertId());
    return sanitize_user($user ?? []);
}

function login_user(array $data): array
{
    $email = trim((string)($data['email'] ?? ''));
    $password = (string)($data['password'] ?? '');
    if ($email === '' || $password === '') {
        api_error('Missing credentials', 422);
    }
    $user = fetch_user_by_email($email);
    if (!$user || !password_verify($password, (string)$user['password_hash'])) {
        api_error('Invalid credentials', 401);
    }
    if (($user['status'] ?? '') !== 'active') {
        api_error('Account disabled', 403);
    }
    $pdo = db();
    $st = $pdo->prepare('UPDATE users SET last_login_at = :ts WHERE id = :id');
    $st->execute([':ts' => now_ts(), ':id' => $user['id']]);
    set_session_user($user);
    return sanitize_user($user);
}

function update_user_profile(array $data, array $user): array
{
    $fields = [];
    $bind = [':id' => $user['id']];

    if (isset($data['full_name']) && trim((string)$data['full_name']) !== '') {
        $fields[] = 'full_name = :full_name';
        $bind[':full_name'] = trim((string)$data['full_name']);
    }
    if (isset($data['phone'])) {
        $phone = trim((string)$data['phone']);
        $fields[] = 'phone = :phone';
        $bind[':phone'] = $phone !== '' ? $phone : null;
    }
    if (isset($data['email']) && trim((string)$data['email']) !== '') {
        $email = trim((string)$data['email']);
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            api_error('Invalid email', 422);
        }
        $existing = fetch_user_by_email($email);
        if ($existing && (int)$existing['id'] !== (int)$user['id']) {
            api_error('Email already used', 409);
        }
        $fields[] = 'email = :email';
        $bind[':email'] = $email;
    }
    if (isset($data['password']) && $data['password'] !== '') {
        if (strlen((string)$data['password']) < 6) {
            api_error('Password too short', 422);
        }
        $fields[] = 'password_hash = :password_hash';
        $bind[':password_hash'] = password_hash((string)$data['password'], PASSWORD_DEFAULT);
    }
    if (isset($data['pole']) && in_array(($user['role'] ?? ''), ['admin', 'controle_qualite'], true)) {
        $pole = trim((string)$data['pole']);
        $pole = $pole !== '' ? normalize_zone_key($pole) : '';
        $fields[] = 'pole = :pole';
        $bind[':pole'] = $pole !== '' ? $pole : null;
    }

    if (!$fields) {
        return sanitize_user($user);
    }

    $fields[] = 'updated_at = :updated_at';
    $bind[':updated_at'] = now_ts();
    $sql = 'UPDATE users SET ' . implode(', ', $fields) . ' WHERE id = :id';
    $pdo = db();
    $st = $pdo->prepare($sql);
    $st->execute($bind);

    $fresh = fetch_user_by_id((int)$user['id']);
    return sanitize_user($fresh ?? []);
}

function list_users_basic(array $currentUser): array
{
    $pdo = db();
    $st = $pdo->prepare('SELECT id, full_name, email, phone, role FROM users WHERE status = :status ORDER BY full_name');
    $st->execute([':status' => 'active']);
    $rows = $st->fetchAll();
    foreach ($rows as &$row) {
        $row['is_self'] = ((int)$row['id'] === (int)$currentUser['id']);
    }
    return $rows;
}

function list_users_admin(array $params, array $actor): array
{
    $roleFilter = trim((string)($params['role'] ?? ''));
    $statusFilter = trim((string)($params['status'] ?? ''));
    $limit = isset($params['limit']) ? (int)$params['limit'] : 200;
    $limit = max(1, min($limit, 500));

    $actorRole = $actor['role'] ?? '';
    if (!in_array($actorRole, ['admin', 'controle_qualite'], true)) {
        api_error('Forbidden', 403);
    }
    if ($actorRole === 'controle_qualite') {
        $roleFilter = 'charge_suivi';
    }

    $sql = 'SELECT id, full_name, email, phone, role, status, pole, created_at
            FROM users WHERE 1=1';
    $bind = [];
    if ($roleFilter !== '') {
        $sql .= ' AND role = :role';
        $bind[':role'] = $roleFilter;
    }
    if ($statusFilter !== '') {
        $sql .= ' AND status = :status';
        $bind[':status'] = $statusFilter;
    }
    if ($actorRole === 'controle_qualite') {
        $pole = trim((string)($actor['pole'] ?? ''));
        if ($pole === '') {
            api_error('Pole missing', 422);
        }
        $sql .= ' AND UPPER(TRIM(pole)) = :pole';
        $bind[':pole'] = normalize_zone_key($pole);
    }
    $sql .= ' ORDER BY full_name LIMIT :limit';

    $pdo = db();
    $st = $pdo->prepare($sql);
    foreach ($bind as $key => $value) {
        $st->bindValue($key, $value);
    }
    $st->bindValue(':limit', $limit, PDO::PARAM_INT);
    $st->execute();
    return $st->fetchAll();
}

function create_user_admin(array $data, array $actor): array
{
    $actorRole = $actor['role'] ?? '';
    if (!in_array($actorRole, ['admin', 'controle_qualite'], true)) {
        api_error('Forbidden', 403);
    }
    if ($actorRole === 'controle_qualite') {
        $data['role'] = 'charge_suivi';
        $pole = trim((string)($actor['pole'] ?? ''));
        if ($pole === '') {
            api_error('Pole missing', 422);
        }
        $data['pole'] = $pole;
    }
    return register_user($data, $actor);
}

function update_user_status(array $params, array $actor): array
{
    $actorRole = $actor['role'] ?? '';
    if (!in_array($actorRole, ['admin', 'controle_qualite'], true)) {
        api_error('Forbidden', 403);
    }
    $id = isset($params['id']) ? (int)$params['id'] : 0;
    if ($id <= 0) {
        api_error('Missing id', 422);
    }
    $status = trim((string)($params['status'] ?? ''));
    if (!in_array($status, ['active', 'disabled'], true)) {
        api_error('Invalid status', 422);
    }
    $target = fetch_user_by_id($id);
    if (!$target) {
        api_error('User not found', 404);
    }
    if ($actorRole === 'controle_qualite') {
        if (($target['role'] ?? '') !== 'charge_suivi') {
            api_error('Forbidden', 403);
        }
        $pole = trim((string)($actor['pole'] ?? ''));
        if ($pole === '') {
            api_error('Pole missing', 422);
        }
        if (normalize_zone_key($target['pole'] ?? '') !== normalize_zone_key($pole)) {
            api_error('Forbidden', 403);
        }
    }
    if ((int)$target['id'] === (int)$actor['id']) {
        api_error('Forbidden', 403);
    }
    $pdo = db();
    $st = $pdo->prepare('UPDATE users SET status = :status, updated_at = :updated_at WHERE id = :id');
    $st->execute([
        ':status' => $status,
        ':updated_at' => now_ts(),
        ':id' => $id,
    ]);
    $fresh = fetch_user_by_id($id);
    return sanitize_user($fresh ?? []);
}

/**
 * Build a date expression for view queries.
 *
 * @param string $viewAlias
 * @param string $birdsAlias
 * @return string
 */
function view_date_expr(string $viewAlias = 'v', string $birdsAlias = 'b'): string
{
    return "COALESCE({$viewAlias}.date_obs, STR_TO_DATE({$birdsAlias}.date, '%d/%m/%Y'))";
}

/**
 * Build the SQL WHERE clause for search_observations_view.
 *
 * @param array $params
 * @param string $alias
 * @param string|null $dateExpr
 * @return array [string $whereSql, array $bind]
 */
function build_where_view(array $params, string $alias = 'v', ?string $dateExpr = null): array
{
    $where = 'WHERE 1=1';
    $bind = [];
    $dateCol = $dateExpr ?: "{$alias}.date_obs";
    $dateCol = '(' . $dateCol . ')';

    if (!empty($params['q'])) {
        $query = trim((string)$params['q']);
        if ($query !== '') {
            $where .= " AND ({$alias}.title LIKE :q0 OR {$alias}.content LIKE :q1)";
            $q = '%' . $query . '%';
            $bind[':q0'] = $q;
            $bind[':q1'] = $q;
        }
    }
    if (!empty($params['zone'])) {
        $zone = strtoupper(trim((string)$params['zone']));
        if ($zone !== '') {
            $where .= " AND {$alias}.zone_norm = :zone";
            $bind[':zone'] = $zone;
        }
    }
    if (!empty($params['site'])) {
        $site = strtoupper(trim((string)$params['site']));
        if ($site !== '') {
            $where .= " AND {$alias}.site_norm = :site";
            $bind[':site'] = $site;
        }
    }
    if (!empty($params['qc_pole'])) {
        $pole = normalize_zone_key((string)$params['qc_pole']);
        if ($pole !== '') {
            $where .= " AND {$alias}.site_norm IN (
                SELECT scoped.site_norm FROM (
                    SELECT s.name_norm AS site_norm
                    FROM sites s
                    INNER JOIN zone z ON z.id = s.zone_id
                    WHERE z.name_norm = :qc_pole
                    UNION
                    SELECT DISTINCT b2.site_norm AS site_norm
                    FROM birds b2
                    WHERE b2.site_norm IS NOT NULL
                      AND b2.zone_norm = :qc_pole2
                ) scoped
            )";
            $bind[':qc_pole'] = $pole;
            $bind[':qc_pole2'] = $pole;
        }
    }
    if (!empty($params['famille'])) {
        $famille = trim((string)$params['famille']);
        if ($famille !== '') {
            $where .= " AND {$alias}.famille = :famille";
            $bind[':famille'] = $famille;
        }
    }
    if (!empty($params['wicode'])) {
        $wicode = trim((string)$params['wicode']);
        if ($wicode !== '') {
            $where .= " AND {$alias}.wiCode = :wicode";
            $bind[':wicode'] = $wicode;
        }
    }
    if (!empty($params['code_fr'])) {
        $codeFr = trim((string)$params['code_fr']);
        if ($codeFr !== '') {
            $where .= " AND {$alias}.code_fr = :code_fr";
            $bind[':code_fr'] = $codeFr;
        }
    }

    if (!empty($params['date_from'])) {
        $where .= " AND {$dateCol} >= :date_from";
        $bind[':date_from'] = $params['date_from'];
    }
    if (!empty($params['date_to'])) {
        $where .= " AND {$dateCol} <= :date_to";
        $bind[':date_to'] = $params['date_to'];
    }

    if (isset($params['count_min']) && $params['count_min'] !== '' && is_numeric($params['count_min'])) {
        $where .= " AND IFNULL({$alias}.effectif_int, 0) >= :count_min";
        $bind[':count_min'] = (int)$params['count_min'];
    }
    if (isset($params['count_max']) && $params['count_max'] !== '' && is_numeric($params['count_max'])) {
        $where .= " AND IFNULL({$alias}.effectif_int, 0) <= :count_max";
        $bind[':count_max'] = (int)$params['count_max'];
    }

    return [$where, $bind];
}

/**
 * Build the SQL WHERE clause and bind array based on request parameters.
 *
 * The monitoring schema stores dates as dd/mm/YYYY in the `date` column.
 * Because the `date_obs` column is null across the dataset, we parse
 * `date` on the fly using STR_TO_DATE for filtering.  We build a
 * where-clause beginning with "WHERE 1=1" to simplify appending
 * conditions.  Bindings for the prepared statement are returned in
 * associative array format.
 *
 * Supported parameters:
 *   q            - free text search across species codes, names, zone,
 *                  site and observation notes
 *   zone         - exact match on zone_norm (case-insensitive)
 *   site         - exact match on site_norm (case-insensitive)
 *   famille      - exact match on famille
 *   wicode       - exact match on wiCode
 *   code_fr      - exact match on code_fr
 *   date_from    - lower bound (YYYY-MM-DD) inclusive
 *   date_to      - upper bound (YYYY-MM-DD) inclusive
 *   count_min    - minimum effectif_int
 *   count_max    - maximum effectif_int
 *
 * @param array $params
 * @param bool  $for_count   whether we are building a COUNT query (omit limit/offset)
 * @return array [string $whereSql, array $bind]
 */
function build_where(array $params, bool $for_count = false): array
{
    $where = 'WHERE 1=1';
    $bind = [];

    // Free text search: match against several fields using LIKE.
    if (!empty($params['q'])) {
        $where .= ' AND (
            b.wiCode LIKE :q OR
            b.codeFran├ºais LIKE :q OR
            b.nomFran├ºais LIKE :q OR
            b.nomScientifique LIKE :q OR
            b.englishName LIKE :q OR
            b.famille LIKE :q OR
            b.zone LIKE :q OR
            b.site LIKE :q OR
            b.observateurs LIKE :q OR
            b.observations LIKE :q
        )';
        // Surround search term with wildcards
        $bind[':q'] = '%' . $params['q'] . '%';
    }

    // Exact match filters
    if (!empty($params['zone'])) {
        $where .= ' AND b.zone_norm = :zone';
        $bind[':zone'] = strtoupper(trim($params['zone']));
    }
    if (!empty($params['site'])) {
        $where .= ' AND b.site_norm = :site';
        $bind[':site'] = strtoupper(trim($params['site']));
    }
    if (!empty($params['qc_pole'])) {
        $pole = normalize_zone_key((string)$params['qc_pole']);
        if ($pole !== '') {
            $where .= ' AND b.site_norm IN (
                SELECT scoped.site_norm FROM (
                    SELECT s.name_norm AS site_norm
                    FROM sites s
                    INNER JOIN zone z ON z.id = s.zone_id
                    WHERE z.name_norm = :qc_pole
                    UNION
                    SELECT DISTINCT b2.site_norm AS site_norm
                    FROM birds b2
                    WHERE b2.site_norm IS NOT NULL
                      AND b2.zone_norm = :qc_pole2
                ) scoped
            )';
            $bind[':qc_pole'] = $pole;
            $bind[':qc_pole2'] = $pole;
        }
    }
    if (!empty($params['famille'])) {
        $where .= ' AND b.famille = :famille';
        $bind[':famille'] = $params['famille'];
    }
    if (!empty($params['wicode'])) {
        $where .= ' AND b.wiCode = :wicode';
        $bind[':wicode'] = $params['wicode'];
    }
    if (!empty($params['code_fr'])) {
        $where .= ' AND b.codeFran├ºais = :code_fr';
        $bind[':code_fr'] = $params['code_fr'];
    }

    // Date range: parse `date` string into DATE using STR_TO_DATE.
    // We only apply date filters if provided.  The input is expected in
    // ISO format (YYYY-MM-DD).  MySQL will compare DATEs correctly.
    if (!empty($params['date_from'])) {
        $where .= ' AND STR_TO_DATE(b.date, "%d/%m/%Y") >= :date_from';
        $bind[':date_from'] = $params['date_from'];
    }
    if (!empty($params['date_to'])) {
        $where .= ' AND STR_TO_DATE(b.date, "%d/%m/%Y") <= :date_to';
        $bind[':date_to'] = $params['date_to'];
    }

    // Effectif range
    if (isset($params['count_min']) && $params['count_min'] !== '') {
        $where .= ' AND IFNULL(b.effectif_int, 0) >= :count_min';
        $bind[':count_min'] = (int)$params['count_min'];
    }
    if (isset($params['count_max']) && $params['count_max'] !== '') {
        $where .= ' AND IFNULL(b.effectif_int, 0) <= :count_max';
        $bind[':count_max'] = (int)$params['count_max'];
    }

    return [$where, $bind];
}

/**
 * Query a list of zones with the number of observations in each zone.
 * Returns an array of strings for zone_norm.
 *
 * @param array $params (not used for now)
 * @return array
 */
function q_zones(array $params = []): array
{
    if (!empty($params['qc_pole'])) {
        $pole = normalize_zone_key((string)$params['qc_pole']);
        return $pole !== '' ? [$pole] : [];
    }
    $pdo = db();
    $sql = 'SELECT DISTINCT b.zone_norm AS zone FROM birds b WHERE b.zone_norm IS NOT NULL ORDER BY b.zone_norm';
    $st = $pdo->query($sql);
    $rows = $st->fetchAll(PDO::FETCH_COLUMN);
    return $rows;
}

/**
 * Query a list of sites given an optional zone.
 * Returns an array of strings for site_norm.
 *
 * @param array $params expects 'zone' optionally
 * @return array
 */
function q_sites(array $params = []): array
{
    $pdo = db();
    if (!empty($params['qc_pole'])) {
        $pole = normalize_zone_key((string)$params['qc_pole']);
        if ($pole === '') {
            return [];
        }
        if (!empty($params['zone']) && normalize_zone_key((string)$params['zone']) !== $pole) {
            return [];
        }
        $sql = 'SELECT DISTINCT site_norm AS site FROM (
                    SELECT s.name_norm AS site_norm
                    FROM sites s
                    INNER JOIN zone z ON z.id = s.zone_id
                    WHERE z.name_norm = :pole
                    UNION
                    SELECT DISTINCT b.site_norm AS site_norm
                    FROM birds b
                    WHERE b.site_norm IS NOT NULL
                      AND b.zone_norm = :pole2
                ) scoped
                ORDER BY site_norm';
        $st = $pdo->prepare($sql);
        $st->execute([':pole' => $pole, ':pole2' => $pole]);
        return $st->fetchAll(PDO::FETCH_COLUMN);
    }
    $sql = 'SELECT DISTINCT b.site_norm AS site FROM birds b WHERE b.site_norm IS NOT NULL';
    $bind = [];
    if (!empty($params['zone'])) {
        $sql .= ' AND b.zone_norm = :zone';
        $bind[':zone'] = strtoupper(trim($params['zone']));
    }
    $sql .= ' ORDER BY b.site_norm';
    $st = $pdo->prepare($sql);
    $st->execute($bind);
    return $st->fetchAll(PDO::FETCH_COLUMN);
}

/**
 * Return distinct species metadata for dropdowns.
 *
 * @return array<int,array<string,string>>
 */
function list_species_options(): array
{
    $pdo = db();
    $sql = 'SELECT DISTINCT
                NULLIF(TRIM(b.wiCode), "") AS wicode,
                NULLIF(TRIM(b.codeFrançais), "") AS code_fr,
                NULLIF(TRIM(b.nomFrançais), "") AS nom_fr,
                NULLIF(TRIM(b.nomScientifique), "") AS nom_sc,
                NULLIF(TRIM(b.englishName), "") AS english,
                NULLIF(TRIM(b.famille), "") AS famille
            FROM birds b
            WHERE b.wiCode <> ""
               OR b.codeFrançais <> ""
               OR b.nomFrançais <> ""
               OR b.nomScientifique <> ""
               OR b.englishName <> ""
            ORDER BY b.wiCode, b.nomScientifique';
    $st = $pdo->query($sql);
    $rows = $st->fetchAll();
    $items = [];
    foreach ($rows as $row) {
        $item = [
            'wicode' => (string)($row['wicode'] ?? ''),
            'code_fr' => (string)($row['code_fr'] ?? ''),
            'nom_fr' => (string)($row['nom_fr'] ?? ''),
            'nom_sc' => (string)($row['nom_sc'] ?? ''),
            'english' => (string)($row['english'] ?? ''),
            'famille' => (string)($row['famille'] ?? ''),
        ];
        if (implode('', $item) === '') {
            continue;
        }
        $items[] = $item;
    }
    return $items;
}

/**
 * Return a list of members for the landing page.
 *
 * @param array $params supports optional: limit
 * @return array<int,array<string,string>>
 */
function list_members(array $params = []): array
{
    $limit = isset($params['limit']) && (int)$params['limit'] > 0 ? (int)$params['limit'] : 12;
    $limit = max(1, min($limit, 1000));
    $pdo = db();
    $sql = 'SELECT id, prenom, nom, pole, poste, telephone, email, photo, profession, slug
            FROM members';
    if (members_has_column('adhesion_status')) {
        $sql .= " WHERE adhesion_status IS NULL OR adhesion_status = 'active'";
    }
    $sql .= ' ORDER BY id ASC
            LIMIT :limit';
    $st = $pdo->prepare($sql);
    $st->bindValue(':limit', $limit, PDO::PARAM_INT);
    $st->execute();
    return $st->fetchAll();
}

function members_has_column(string $column): bool
{
    static $cache = [];
    if (array_key_exists($column, $cache)) {
        return $cache[$column];
    }
    try {
        $pdo = db();
        $st = $pdo->prepare('SELECT 1 FROM information_schema.columns WHERE table_schema = :schema AND table_name = :table AND column_name = :col');
        $st->execute([
            ':schema' => DB_NAME,
            ':table' => 'members',
            ':col' => $column,
        ]);
        $cache[$column] = (bool)$st->fetchColumn();
    } catch (Throwable $e) {
        $cache[$column] = false;
    }
    return $cache[$column];
}

function next_member_id(): int
{
    $pdo = db();
    $id = (int)$pdo->query('SELECT COALESCE(MAX(id), 0) + 1 FROM members')->fetchColumn();
    return max(1, $id);
}

function membership_amount(string $type): int
{
    return $type === 'student' ? 5000 : 10000;
}

function fetch_member_by_email(string $email): ?array
{
    $pdo = db();
    $st = $pdo->prepare('SELECT * FROM members WHERE email = :email ORDER BY id DESC LIMIT 1');
    $st->execute([':email' => $email]);
    $row = $st->fetch();
    return $row ?: null;
}

function generate_temp_password(int $length = 8): string
{
    $pool = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    $max = strlen($pool) - 1;
    $password = '';
    for ($i = 0; $i < $length; $i++) {
        $password .= $pool[random_int(0, $max)];
    }
    return $password;
}

function ensure_member_user_account(array $member, array $actor): array
{
    $email = trim((string)($member['email'] ?? ''));
    if ($email === '') {
        api_error('Member email missing', 422);
    }
    $pdo = db();
    $existing = fetch_user_by_email($email);
    $now = now_ts();
    $tempPassword = null;
    if ($existing) {
        if (($existing['role'] ?? '') !== 'member') {
            api_error('Email already used', 409);
        }
        $st = $pdo->prepare('UPDATE users SET pole = :pole, status = :status, updated_at = :updated_at WHERE id = :id');
        $st->execute([
            ':pole' => normalize_zone_key((string)($member['pole'] ?? '')) ?: null,
            ':status' => 'active',
            ':updated_at' => $now,
            ':id' => (int)$existing['id'],
        ]);
        return ['user_id' => (int)$existing['id'], 'temp_password' => null];
    }

    $passwordHash = (string)($member['password_hash'] ?? '');
    if ($passwordHash === '') {
        $tempPassword = generate_temp_password();
        $passwordHash = password_hash($tempPassword, PASSWORD_DEFAULT);
    }
    $fullName = trim((string)($member['prenom'] ?? '') . ' ' . (string)($member['nom'] ?? ''));
    $st = $pdo->prepare('INSERT INTO users (full_name, email, phone, pole, role, password_hash, status, created_at, updated_at) VALUES (:full_name, :email, :phone, :pole, :role, :password_hash, :status, :created_at, :updated_at)');
    $st->execute([
        ':full_name' => $fullName !== '' ? $fullName : $email,
        ':email' => $email,
        ':phone' => (string)($member['telephone'] ?? '') ?: null,
        ':pole' => normalize_zone_key((string)($member['pole'] ?? '')) ?: null,
        ':role' => 'member',
        ':password_hash' => $passwordHash,
        ':status' => 'active',
        ':created_at' => $now,
        ':updated_at' => $now,
    ]);
    return ['user_id' => (int)$pdo->lastInsertId(), 'temp_password' => $tempPassword];
}

function create_membership_request(array $data): array
{
    $prenom = trim((string)($data['prenom'] ?? ''));
    $nom = trim((string)($data['nom'] ?? ''));
    $email = trim((string)($data['email'] ?? ''));
    $telephone = trim((string)($data['telephone'] ?? ''));
    $pole = trim((string)($data['pole'] ?? ''));
    $fonction = trim((string)($data['fonction'] ?? ''));
    $organisation = trim((string)($data['organisation'] ?? ''));
    $password = (string)($data['password'] ?? '');
    $type = trim((string)($data['adhesion_type'] ?? ''));
    if ($prenom === '' || $nom === '' || $email === '' || $telephone === '' || $pole === '' || $fonction === '' || $organisation === '' || $type === '' || $password === '') {
        api_error('Missing required fields', 422);
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        api_error('Invalid email', 422);
    }
    if (strlen($password) < 6) {
        api_error('Password too short', 422);
    }
    $type = strtolower($type);
    if (!in_array($type, ['student', 'professional'], true)) {
        api_error('Invalid adhesion_type', 422);
    }
    if (fetch_user_by_email($email)) {
        api_error('Email already used', 409);
    }
    $existing = fetch_member_by_email($email);
    if ($existing && in_array(($existing['adhesion_status'] ?? ''), ['pending_payment', 'paid', 'pending_activation', 'active'], true)) {
        api_error('Member already exists', 409);
    }
    $memberId = next_member_id();
    $amount = membership_amount($type);
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);
    $now = now_ts();
    $pdo = db();
    $stmt = $pdo->prepare('INSERT INTO members (id, prenom, nom, pole, poste, telephone, email, photo, profession, slug, fonction, organisation, adhesion_type, adhesion_amount, adhesion_currency, adhesion_status, paid_at, activated_by, activated_at, expires_at, password_hash, user_id, created_at, updated_at) VALUES (:id, :prenom, :nom, :pole, :poste, :telephone, :email, :photo, :profession, :slug, :fonction, :organisation, :adhesion_type, :adhesion_amount, :adhesion_currency, :adhesion_status, :paid_at, :activated_by, :activated_at, :expires_at, :password_hash, :user_id, :created_at, :updated_at)');
    $stmt->execute([
        ':id' => $memberId,
        ':prenom' => $prenom,
        ':nom' => $nom,
        ':pole' => normalize_zone_key($pole),
        ':poste' => $fonction,
        ':telephone' => $telephone,
        ':email' => $email,
        ':photo' => '',
        ':profession' => $organisation,
        ':slug' => (string)$memberId,
        ':fonction' => $fonction,
        ':organisation' => $organisation,
        ':adhesion_type' => $type,
        ':adhesion_amount' => $amount,
        ':adhesion_currency' => 'XOF',
        ':adhesion_status' => 'pending_payment',
        ':paid_at' => null,
        ':activated_by' => null,
        ':activated_at' => null,
        ':expires_at' => null,
        ':password_hash' => $passwordHash,
        ':user_id' => null,
        ':created_at' => $now,
        ':updated_at' => $now,
    ]);
    return [
        'id' => $memberId,
        'prenom' => $prenom,
        'nom' => $nom,
        'email' => $email,
        'pole' => normalize_zone_key($pole),
        'adhesion_type' => $type,
        'adhesion_amount' => $amount,
        'adhesion_currency' => 'XOF',
        'adhesion_status' => 'pending_payment'
    ];
}

function list_membership_requests(array $params, array $actor): array
{
    $role = $actor['role'] ?? '';
    if (!in_array($role, ['controle_qualite', 'admin'], true)) {
        api_error('Forbidden', 403);
    }
    $statuses = [];
    $rawStatus = trim((string)($params['status'] ?? ''));
    $allowed = ['pending_payment', 'paid', 'pending_activation', 'active', 'rejected'];
    if ($rawStatus !== '') {
        foreach (explode(',', $rawStatus) as $item) {
            $item = trim($item);
            if ($item !== '' && in_array($item, $allowed, true)) {
                $statuses[] = $item;
            }
        }
    } else {
        $statuses = ['pending_payment', 'paid', 'pending_activation'];
    }

    $limit = isset($params['limit']) ? (int)$params['limit'] : 200;
    $limit = max(1, min($limit, 500));

    $sql = 'SELECT id, prenom, nom, pole, telephone, email, fonction, organisation, adhesion_type, adhesion_amount, adhesion_currency, adhesion_status, paid_at, created_at
            FROM members WHERE 1=1';
    $bind = [];
    if ($statuses) {
        $placeholders = implode(',', array_fill(0, count($statuses), '?'));
        $sql .= " AND adhesion_status IN ($placeholders)";
        $bind = array_merge($bind, $statuses);
    }
    if ($role === 'controle_qualite') {
        $pole = trim((string)($actor['pole'] ?? ''));
        if ($pole === '') {
            api_error('Pole missing', 422);
        }
        $sql .= ' AND UPPER(TRIM(pole)) = ?';
        $bind[] = normalize_zone_key($pole);
    } elseif (!empty($params['pole'])) {
        $sql .= ' AND UPPER(TRIM(pole)) = ?';
        $bind[] = normalize_zone_key((string)$params['pole']);
    }
    $sql .= ' ORDER BY created_at DESC, id DESC LIMIT ' . $limit;

    $pdo = db();
    $st = $pdo->prepare($sql);
    $st->execute($bind);
    return $st->fetchAll();
}

function approve_membership(int $id, array $actor, bool $markPaid = true): array
{
    $role = $actor['role'] ?? '';
    if (!in_array($role, ['controle_qualite', 'admin'], true)) {
        api_error('Forbidden', 403);
    }
    $pdo = db();
    $st = $pdo->prepare('SELECT * FROM members WHERE id = :id');
    $st->execute([':id' => $id]);
    $member = $st->fetch();
    if (!$member) {
        api_error('Member not found', 404);
    }
    if ($role === 'controle_qualite') {
        $pole = trim((string)($actor['pole'] ?? ''));
        if ($pole === '') {
            api_error('Pole missing', 422);
        }
        if (normalize_zone_key((string)$member['pole']) !== normalize_zone_key($pole)) {
            api_error('Forbidden', 403);
        }
    }
    $now = now_ts();
    $paidAt = $markPaid && empty($member['paid_at']) ? $now : $member['paid_at'];
    $pdo->beginTransaction();
    try {
        $userInfo = ensure_member_user_account($member, $actor);
        $userId = $userInfo['user_id'] ?? null;
        $sql = 'UPDATE members SET adhesion_status = :status, paid_at = :paid_at, activated_by = :activated_by, activated_at = :activated_at, updated_at = :updated_at';
        if (members_has_column('user_id')) {
            $sql .= ', user_id = :user_id';
        }
        $sql .= ' WHERE id = :id';
        $update = $pdo->prepare($sql);
        $bind = [
            ':status' => 'active',
            ':paid_at' => $paidAt,
            ':activated_by' => (int)$actor['id'],
            ':activated_at' => $now,
            ':updated_at' => $now,
            ':id' => $id,
        ];
        if (members_has_column('user_id')) {
            $bind[':user_id'] = $userId;
        }
        $update->execute($bind);
        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }
    $response = ['id' => $id, 'status' => 'active', 'user_id' => $userId];
    if (!empty($userInfo['temp_password'])) {
        $response['temp_password'] = $userInfo['temp_password'];
    }
    return $response;
}

function reject_membership(int $id, array $actor, string $reason): array
{
    $role = $actor['role'] ?? '';
    if (!in_array($role, ['controle_qualite', 'admin'], true)) {
        api_error('Forbidden', 403);
    }
    $pdo = db();
    $st = $pdo->prepare('SELECT * FROM members WHERE id = :id');
    $st->execute([':id' => $id]);
    $member = $st->fetch();
    if (!$member) {
        api_error('Member not found', 404);
    }
    if ($role === 'controle_qualite') {
        $pole = trim((string)($actor['pole'] ?? ''));
        if ($pole === '') {
            api_error('Pole missing', 422);
        }
        if (normalize_zone_key((string)$member['pole']) !== normalize_zone_key($pole)) {
            api_error('Forbidden', 403);
        }
    }
    $now = now_ts();
    $update = $pdo->prepare('UPDATE members SET adhesion_status = :status, rejection_reason = :reason, updated_at = :updated_at WHERE id = :id');
    $update->execute([
        ':status' => 'rejected',
        ':reason' => $reason !== '' ? $reason : null,
        ':updated_at' => $now,
        ':id' => $id,
    ]);
    return ['id' => $id, 'status' => 'rejected'];
}

/**
 * Return species catalog with optional photo from birds table.
 *
 * @param array $params supports optional: limit
 * @return array<int,array<string,string>>
 */
function list_especes(array $params = []): array
{
    $limit = isset($params['limit']) && (int)$params['limit'] > 0 ? (int)$params['limit'] : 200;
    $limit = max(1, min($limit, 2000));
    $pdo = db();
    $sql = 'SELECT
                e.id,
                e.codeFrançais AS code_fr,
                e.wiCode AS wicode,
                e.nomFrançais AS nom_fr,
                e.nomScientifique AS nom_sc,
                e.englishName AS english,
                e.famille,
                e.statutDeConservationUICN AS statut,
                p.photo
            FROM especes e
            LEFT JOIN (
                SELECT wiCode, MIN(photo) AS photo
                FROM birds
                WHERE photo IS NOT NULL AND photo <> ""
                GROUP BY wiCode
            ) p ON p.wiCode = e.wiCode
            ORDER BY e.nomFrançais, e.wiCode
            LIMIT :limit';
    $st = $pdo->prepare($sql);
    $st->bindValue(':limit', $limit, PDO::PARAM_INT);
    $st->execute();
    return $st->fetchAll();
}

/**
 * Query observations with pagination.
 * Returns an array with keys: total, page, page_size, items.
 * Each item contains fields: doc_id, date, title, zone, site,
 * famille, wicode, code_fr, effectif, effectif_int.
 *
 * @param array $params
 * @return array
 */
function q_observations(array $params): array
{
    $pdo = db();
    $useView = has_search_view();

    // Determine page and page_size
    $page = isset($params['page']) && (int)$params['page'] > 0 ? (int)$params['page'] : 1;
    $pageSize = isset($params['page_size']) && (int)$params['page_size'] > 0 ? (int)$params['page_size'] : 25;
    $pageSize = min($pageSize, 200); // limit to avoid huge loads
    $offset = ($page - 1) * $pageSize;

    if ($useView) {
        $dateExpr = view_date_expr('v', 'b');
        [$whereSql, $bindWhere] = build_where_view($params, 'v', $dateExpr);

        // Total count
        $sqlTotal = 'SELECT COUNT(*) FROM search_observations_view v LEFT JOIN birds b ON b.id = v.doc_id ' . $whereSql;
        $st = $pdo->prepare($sqlTotal);
        $st->execute($bindWhere);
        $total = (int)$st->fetchColumn();

        $sql = "SELECT
    v.doc_id AS doc_id,
    {$dateExpr} AS date_parsed,
    v.title AS title,
    v.zone_norm AS zone,
    v.site_norm AS site,
    v.famille,
    v.wiCode,
    v.code_fr,
    b.effectif,
    v.effectif_int
FROM search_observations_view v
LEFT JOIN birds b ON b.id = v.doc_id
{$whereSql}
ORDER BY date_parsed DESC, v.updated_at DESC, v.doc_id DESC
LIMIT :limit OFFSET :offset";
    } else {
        [$whereSql, $bindWhere] = build_where($params, true);

        // Total count
        $sqlTotal = 'SELECT COUNT(*) FROM birds b ' . $whereSql;
        $st = $pdo->prepare($sqlTotal);
        $st->execute($bindWhere);
        $total = (int)$st->fetchColumn();

        // Items query.  Parse date string to DATE for ordering and display.
        $sql = 'SELECT
                    b.id AS doc_id,
                    STR_TO_DATE(b.date, "%d/%m/%Y") AS date_parsed,
                    concat_ws(" - ",
                        NULLIF(b.wiCode, ""),
                        NULLIF(b.codeFrançais, ""),
                        NULLIF(b.site, ""),
                        NULLIF(b.zone, "")
                    ) AS title,
                    b.zone_norm AS zone,
                    b.site_norm AS site,
                    b.famille,
                    b.wiCode,
                    b.codeFrançais AS code_fr,
                    b.effectif,
                    b.effectif_int
                FROM birds b
                ' . $whereSql . '
                ORDER BY date_parsed DESC, b.updated_at DESC, b.id DESC
                LIMIT :limit OFFSET :offset';
    }

    $st = $pdo->prepare($sql);
    foreach ($bindWhere as $k => $v) {
        $st->bindValue($k, $v);
    }
    $st->bindValue(':limit', $pageSize, PDO::PARAM_INT);
    $st->bindValue(':offset', $offset, PDO::PARAM_INT);
    $st->execute();
    $items = $st->fetchAll();

    // Convert date_parsed to ISO string for JSON
    foreach ($items as &$item) {
        $item['date'] = $item['date_parsed'];
        unset($item['date_parsed']);
    }

    return [
        'total'     => $total,
        'page'      => $page,
        'page_size' => $pageSize,
        'items'     => $items,
    ];
}

/**
 * Query GeoJSON features limited by optional bbox and filters.
 * This function attempts to obtain coordinates from points or sites
 * tables if birds.x_num/y_num are null.  It returns a GeoJSON
 * FeatureCollection with minimal properties for the map.
 *
 * @param array $params expects optional: bbox, q, zone, site, etc., limit
 * @return array GeoJSON
 */
function q_geo(array $params): array
{
    $pdo = db();
    $useView = has_search_view();

    if ($useView) {
        $dateExpr = view_date_expr('v', 'b');
        [$whereSql, $bindWhere] = build_where_view($params, 'v', $dateExpr);
    } else {
        [$whereSql, $bindWhere] = build_where($params, true);
    }

    // Determine limit.  Default 10000 to avoid overloading the map.
    $limit = isset($params['limit']) && (int)$params['limit'] > 0 ? (int)$params['limit'] : 10000;
    $limit = min($limit, 20000);

    // Bbox filter: expects 'minLon,minLat,maxLon,maxLat'
    $bboxClause = '';
    $bbox = null;
    if (!empty($params['bbox'])) {
        $bboxParts = explode(',', $params['bbox']);
        if (count($bboxParts) === 4) {
            list($minLon, $minLat, $maxLon, $maxLat) = array_map('floatval', $bboxParts);
            $bbox = ['minLon' => $minLon, 'minLat' => $minLat, 'maxLon' => $maxLon, 'maxLat' => $maxLat];
            $xCol = $useView ? 'v.x_num' : 'b.x_num';
            $yCol = $useView ? 'v.y_num' : 'b.y_num';
            // Use birds/view x_num/y_num first; fallback to site/point later
            $bboxClause = ' AND (
                (
                    ' . $xCol . ' IS NOT NULL AND ' . $yCol . ' IS NOT NULL
                    AND ' . $xCol . ' BETWEEN :minLon AND :maxLon
                    AND ' . $yCol . ' BETWEEN :minLat AND :maxLat
                ) OR (
                    ' . $xCol . ' IS NULL OR ' . $yCol . ' IS NULL
                )
            )';
            $bindWhere[':minLon'] = $minLon;
            $bindWhere[':maxLon'] = $maxLon;
            $bindWhere[':minLat'] = $minLat;
            $bindWhere[':maxLat'] = $maxLat;
        }
    }

    if ($useView) {
        $sql = "SELECT
                v.doc_id AS doc_id,
                COALESCE(p.lon, s.lon, v.x_num) AS lon,
                COALESCE(p.lat, s.lat, v.y_num) AS lat,
                {$dateExpr} AS date_parsed,
                v.zone_norm AS zone,
                v.site_norm AS site,
                v.famille,
                v.wiCode,
                v.code_fr,
                v.title AS title,
                v.effectif_int AS effectif
            FROM search_observations_view v
            LEFT JOIN birds b ON b.id = v.doc_id
            LEFT JOIN sites s ON s.name_norm = v.site_norm
            LEFT JOIN points p ON p.site_id = s.id AND p.name = b.point
            {$whereSql}{$bboxClause}
            ORDER BY v.updated_at DESC, v.doc_id DESC
            LIMIT :limit";
    } else {
        // Query: join birds -> points -> sites to obtain coordinates
        $sql = 'SELECT
                b.id AS doc_id,
                COALESCE(p.lon, s.lon, b.x_num) AS lon,
                COALESCE(p.lat, s.lat, b.y_num) AS lat,
                STR_TO_DATE(b.date, "%d/%m/%Y") AS date_parsed,
                b.zone_norm AS zone,
                b.site_norm AS site,
                b.famille,
                b.wiCode,
                b.codeFrançais AS code_fr,
                b.effectif_int AS effectif
            FROM birds b
            LEFT JOIN sites s ON s.name_norm = b.site_norm
            LEFT JOIN points p ON p.site_id = s.id AND p.name = b.point
            ' . $whereSql . $bboxClause . '
            ORDER BY b.updated_at DESC, b.id DESC
            LIMIT :limit';
    }

    $st = $pdo->prepare($sql);
    foreach ($bindWhere as $k => $v) {
        // Determine parameter type
        if (is_int($v)) {
            $st->bindValue($k, $v, PDO::PARAM_INT);
        } elseif (is_float($v)) {
            $st->bindValue($k, $v);
        } else {
            $st->bindValue($k, $v);
        }
    }
    $st->bindValue(':limit', $limit, PDO::PARAM_INT);
    $st->execute();
    $rows = $st->fetchAll();

    $features = [];
    foreach ($rows as $r) {
        $lon = is_numeric($r['lon']) ? (float)$r['lon'] : null;
        $lat = is_numeric($r['lat']) ? (float)$r['lat'] : null;
        $siteCoords = lookup_site_coords($r['site'] ?? null, $r['zone'] ?? null);
        $zoneCoords = lookup_zone_coords($r['zone'] ?? null);
        if (is_array($siteCoords) && is_special_site($r['site'] ?? null)) {
            $lon = $siteCoords['lon'];
            $lat = $siteCoords['lat'];
        }
        if (is_array($siteCoords)) {
            if ($lon === null || $lat === null) {
                $lon = $siteCoords['lon'];
                $lat = $siteCoords['lat'];
            } elseif (is_array($zoneCoords)) {
                $tol = 0.0001;
                if (abs($lon - $zoneCoords['lon']) < $tol && abs($lat - $zoneCoords['lat']) < $tol) {
                    $lon = $siteCoords['lon'];
                    $lat = $siteCoords['lat'];
                }
            }
        }
        if ($lon === null || $lat === null) {
            if (is_array($zoneCoords)) {
                $lon = $zoneCoords['lon'];
                $lat = $zoneCoords['lat'];
            }
        }
        if ($lon === null || $lat === null) {
            continue;
        }
        if ($bbox && (
            $lon < $bbox['minLon'] || $lon > $bbox['maxLon'] ||
            $lat < $bbox['minLat'] || $lat > $bbox['maxLat']
        )) {
            continue;
        }
        $features[] = [
            'type' => 'Feature',
            'geometry' => [
                'type' => 'Point',
                'coordinates' => [$lon, $lat],
            ],
            'properties' => [
                'doc_id'   => $r['doc_id'],
                'title'    => $r['title'] ?? null,
                'date'     => $r['date_parsed'],
                'zone'     => $r['zone'],
                'site'     => $r['site'],
                'famille'  => $r['famille'],
                'wiCode'   => $r['wiCode'],
                'code_fr'  => $r['code_fr'],
                'effectif' => $r['effectif'],
            ],
        ];
    }

    return [
        'type'     => 'FeatureCollection',
        'features' => $features,
    ];
}

/**
 * Compute summary statistics for the dashboard.
 * Returns an array with keys:
 *   kpis        - counts (observations, species, sites, zones)
 *   time        - observations by YYYY-MM (label,value)
 *   top_species - top 10 species by count
 *   top_sites   - top 10 sites by count
 *   zones       - top 10 zones by count
 *   families    - distribution by family (top 10)
 *
 * @param array $params
 * @return array
 */
function q_stats(array $params): array
{
    $pdo = db();
    $useView = has_search_view();

    if ($useView) {
        $dateExpr = view_date_expr('v', 'b');
        $fromView = 'FROM search_observations_view v LEFT JOIN birds b ON b.id = v.doc_id ';
        [$whereSql, $bindWhere] = build_where_view($params, 'v', $dateExpr);

        // KPI counts
        $sqlObs = 'SELECT COUNT(*) ' . $fromView . $whereSql;
        $stObs = $pdo->prepare($sqlObs);
        $stObs->execute($bindWhere);
        $countObs = (int)$stObs->fetchColumn();

        $sqlSpecies = 'SELECT COUNT(DISTINCT v.wiCode) ' . $fromView . $whereSql;
        $stSpecies = $pdo->prepare($sqlSpecies);
        $stSpecies->execute($bindWhere);
        $countSpecies = (int)$stSpecies->fetchColumn();

        $sqlSites = 'SELECT COUNT(DISTINCT v.site_norm) ' . $fromView . $whereSql;
        $stSites = $pdo->prepare($sqlSites);
        $stSites->execute($bindWhere);
        $countSites = (int)$stSites->fetchColumn();

        $sqlZones = 'SELECT COUNT(DISTINCT v.zone_norm) ' . $fromView . $whereSql;
        $stZones = $pdo->prepare($sqlZones);
        $stZones->execute($bindWhere);
        $countZones = (int)$stZones->fetchColumn();

        $kpis = [
            'observations' => $countObs,
            'species'      => $countSpecies,
            'sites'        => $countSites,
            'zones'        => $countZones,
        ];

        $sqlTime = 'SELECT
                        DATE_FORMAT(' . $dateExpr . ', "%Y-%m") AS label,
                        COUNT(*) AS value
                    ' . $fromView .
                    $whereSql . '
                    AND ' . $dateExpr . ' IS NOT NULL
                    GROUP BY label
                    ORDER BY label';
        $stTime = $pdo->prepare($sqlTime);
        $stTime->execute($bindWhere);
        $timeSeries = $stTime->fetchAll();

        $sqlTopSpecies = 'SELECT v.wiCode AS label, COUNT(*) AS value
                          ' . $fromView . $whereSql . '
                          GROUP BY label
                          ORDER BY value DESC
                          LIMIT 10';
        $stTopSpecies = $pdo->prepare($sqlTopSpecies);
        $stTopSpecies->execute($bindWhere);
        $topSpecies = $stTopSpecies->fetchAll();

        $sqlTopSites = 'SELECT v.site_norm AS label, COUNT(*) AS value
                        ' . $fromView . $whereSql . '
                        GROUP BY label
                        ORDER BY value DESC
                        LIMIT 10';
        $stTopSites = $pdo->prepare($sqlTopSites);
        $stTopSites->execute($bindWhere);
        $topSites = $stTopSites->fetchAll();

        $sqlZones = 'SELECT v.zone_norm AS label, COUNT(*) AS value
                     ' . $fromView . $whereSql . '
                     GROUP BY label
                     ORDER BY value DESC
                     LIMIT 10';
        $stZones = $pdo->prepare($sqlZones);
        $stZones->execute($bindWhere);
        $zones = $stZones->fetchAll();

        $sqlFamilies = 'SELECT v.famille AS label, COUNT(*) AS value
                        ' . $fromView . $whereSql . '
                        GROUP BY label
                        ORDER BY value DESC
                        LIMIT 10';
        $stFamilies = $pdo->prepare($sqlFamilies);
        $stFamilies->execute($bindWhere);
        $families = $stFamilies->fetchAll();
    } else {
        [$whereSql, $bindWhere] = build_where($params, true);

        // KPI counts
        $sqlObs = 'SELECT COUNT(*) FROM birds b ' . $whereSql;
        $stObs = $pdo->prepare($sqlObs);
        $stObs->execute($bindWhere);
        $countObs = (int)$stObs->fetchColumn();

        $sqlSpecies = 'SELECT COUNT(DISTINCT b.wiCode) FROM birds b ' . $whereSql;
        $stSpecies = $pdo->prepare($sqlSpecies);
        $stSpecies->execute($bindWhere);
        $countSpecies = (int)$stSpecies->fetchColumn();

        $sqlSites = 'SELECT COUNT(DISTINCT b.site_norm) FROM birds b ' . $whereSql;
        $stSites = $pdo->prepare($sqlSites);
        $stSites->execute($bindWhere);
        $countSites = (int)$stSites->fetchColumn();

        $sqlZones = 'SELECT COUNT(DISTINCT b.zone_norm) FROM birds b ' . $whereSql;
        $stZones = $pdo->prepare($sqlZones);
        $stZones->execute($bindWhere);
        $countZones = (int)$stZones->fetchColumn();

        $kpis = [
            'observations' => $countObs,
            'species'      => $countSpecies,
            'sites'        => $countSites,
            'zones'        => $countZones,
        ];

        $sqlTime = 'SELECT
                        DATE_FORMAT(STR_TO_DATE(b.date, "%d/%m/%Y"), "%Y-%m") AS label,
                        COUNT(*) AS value
                    FROM birds b
                    ' . $whereSql . '
                    GROUP BY label
                    ORDER BY label';
        $stTime = $pdo->prepare($sqlTime);
        $stTime->execute($bindWhere);
        $timeSeries = $stTime->fetchAll();

        $sqlTopSpecies = 'SELECT b.wiCode AS label, COUNT(*) AS value
                          FROM birds b
                          ' . $whereSql . '
                          GROUP BY label
                          ORDER BY value DESC
                          LIMIT 10';
        $stTopSpecies = $pdo->prepare($sqlTopSpecies);
        $stTopSpecies->execute($bindWhere);
        $topSpecies = $stTopSpecies->fetchAll();

        $sqlTopSites = 'SELECT b.site_norm AS label, COUNT(*) AS value
                        FROM birds b
                        ' . $whereSql . '
                        GROUP BY label
                        ORDER BY value DESC
                        LIMIT 10';
        $stTopSites = $pdo->prepare($sqlTopSites);
        $stTopSites->execute($bindWhere);
        $topSites = $stTopSites->fetchAll();

        $sqlZones = 'SELECT b.zone_norm AS label, COUNT(*) AS value
                     FROM birds b
                     ' . $whereSql . '
                     GROUP BY label
                     ORDER BY value DESC
                     LIMIT 10';
        $stZones = $pdo->prepare($sqlZones);
        $stZones->execute($bindWhere);
        $zones = $stZones->fetchAll();

        $sqlFamilies = 'SELECT b.famille AS label, COUNT(*) AS value
                        FROM birds b
                        ' . $whereSql . '
                        GROUP BY label
                        ORDER BY value DESC
                        LIMIT 10';
        $stFamilies = $pdo->prepare($sqlFamilies);
        $stFamilies->execute($bindWhere);
        $families = $stFamilies->fetchAll();
    }

    return [
        'kpis'       => $kpis,
        'time'       => $timeSeries,
        'top_species'=> $topSpecies,
        'top_sites'  => $topSites,
        'zones'      => $zones ?? [],
        'families'   => $families,
    ];
}

function parse_observation_date(string $input): array
{
    $input = trim($input);
    if ($input === '') {
        return [
            'date_text' => '',
            'date_obs' => null,
            'jour' => '',
            'mois' => '',
            'annee' => '',
            'semaine' => '',
        ];
    }
    $dt = DateTime::createFromFormat('Y-m-d', $input);
    if (!$dt) {
        $dt = DateTime::createFromFormat('d/m/Y', $input);
    }
    if (!$dt) {
        return [
            'date_text' => $input,
            'date_obs' => null,
            'jour' => '',
            'mois' => '',
            'annee' => '',
            'semaine' => '',
        ];
    }
    $months = ['janvier','fevrier','mars','avril','mai','juin','juillet','aout','septembre','octobre','novembre','decembre'];
    $monthIndex = (int)$dt->format('n') - 1;
    return [
        'date_text' => $dt->format('d/m/Y'),
        'date_obs' => $dt->format('Y-m-d'),
        'jour' => $dt->format('d'),
        'mois' => $months[$monthIndex] ?? '',
        'annee' => $dt->format('Y'),
        'semaine' => $dt->format('W'),
    ];
}

function create_pending_observation(array $data, array $user): array
{
    $zone = trim((string)($data['zone'] ?? ''));
    $site = trim((string)($data['site'] ?? ''));
    if ($zone === '' || $site === '') {
        api_error('Zone and site required', 422);
    }
    $dateInfo = parse_observation_date((string)($data['date'] ?? ''));
    $lon = parse_float($data['lon'] ?? $data['x_num'] ?? null);
    $lat = parse_float($data['lat'] ?? $data['y_num'] ?? null);
    $xText = trim((string)($data['x'] ?? ($lon !== null ? (string)$lon : '')));
    $yText = trim((string)($data['y'] ?? ($lat !== null ? (string)$lat : '')));
    $effectifInt = parse_int($data['effectif_int'] ?? $data['effectif'] ?? null);
    $observateurs = trim((string)($data['observateurs'] ?? ''));
    if ($observateurs === '') {
        $observateurs = (string)($user['full_name'] ?? '');
    }

    $values = [
        'user_id' => (int)$user['id'],
        'zone' => $zone,
        'site' => $site,
        'transect' => trim((string)($data['transect'] ?? '')),
        'point' => trim((string)($data['point'] ?? '')),
        'utm' => trim((string)($data['utm'] ?? '')),
        'x' => $xText,
        'x_num' => $lon,
        'y' => $yText,
        'y_num' => $lat,
        'date' => $dateInfo['date_text'] !== '' ? $dateInfo['date_text'] : trim((string)($data['date'] ?? '')),
        'date_obs' => $dateInfo['date_obs'],
        'jour' => $dateInfo['jour'],
        'mois' => $dateInfo['mois'],
        'annee' => $dateInfo['annee'],
        'semaine' => $dateInfo['semaine'],
        'codeFrançais' => trim((string)($data['codeFrançais'] ?? $data['code_fr'] ?? '')),
        'wiCode' => trim((string)($data['wiCode'] ?? $data['wicode'] ?? '')),
        'nomFrançais' => trim((string)($data['nomFrançais'] ?? $data['nom_fr'] ?? '')),
        'nomScientifique' => trim((string)($data['nomScientifique'] ?? '')),
        'englishName' => trim((string)($data['englishName'] ?? '')),
        'famille' => trim((string)($data['famille'] ?? '')),
        'effectif' => trim((string)($data['effectif'] ?? '')),
        'effectif_int' => $effectifInt,
        'statutDeConservation' => trim((string)($data['statutDeConservation'] ?? '')),
        'observateurs' => $observateurs,
        'observations' => trim((string)($data['observations'] ?? '')),
        'photo' => trim((string)($data['photo'] ?? '')),
        'status' => 'pending',
        'created_at' => now_ts(),
        'updated_at' => now_ts(),
    ];

    $columns = [
        'user_id' => 'user_id',
        'zone' => 'zone',
        'site' => 'site',
        'transect' => 'transect',
        'point' => 'point',
        'utm' => 'utm',
        'x' => 'x',
        'x_num' => 'x_num',
        'y' => 'y',
        'y_num' => 'y_num',
        'date' => 'date',
        'date_obs' => 'date_obs',
        'jour' => 'jour',
        'mois' => 'mois',
        'annee' => 'annee',
        'semaine' => 'semaine',
        'codeFrançais' => 'code_fr',
        'wiCode' => 'wicode',
        'nomFrançais' => 'nom_fr',
        'nomScientifique' => 'nom_sc',
        'englishName' => 'english',
        'famille' => 'famille',
        'effectif' => 'effectif',
        'effectif_int' => 'effectif_int',
        'statutDeConservation' => 'statut',
        'observateurs' => 'observateurs',
        'observations' => 'observations',
        'photo' => 'photo',
        'status' => 'status',
        'created_at' => 'created_at',
        'updated_at' => 'updated_at',
    ];
    $sqlCols = implode(', ', array_map(fn($c) => "`{$c}`", array_keys($columns)));
    $sqlVals = implode(', ', array_map(fn($p) => ':' . $p, $columns));
    $sql = 'INSERT INTO observation_pending (' . $sqlCols . ') VALUES (' . $sqlVals . ')';
    $pdo = db();
    $st = $pdo->prepare($sql);
    foreach ($columns as $col => $param) {
        $st->bindValue(':' . $param, $values[$col]);
    }
    $st->execute();
    return ['id' => (int)$pdo->lastInsertId()];
}

function list_pending_observations(array $params, array $user): array
{
    $status = trim((string)($params['status'] ?? ''));
    $limit = (int)($params['limit'] ?? 200);
    $limit = max(1, min($limit, 500));
    $sql = 'SELECT * FROM observation_pending WHERE user_id = :user_id';
    $bind = [':user_id' => (int)$user['id']];
    if ($status !== '') {
        $sql .= ' AND status = :status';
        $bind[':status'] = $status;
    }
    $sql .= ' ORDER BY created_at DESC, id DESC LIMIT :limit';
    $pdo = db();
    $st = $pdo->prepare($sql);
    foreach ($bind as $k => $v) {
        $st->bindValue($k, $v);
    }
    $st->bindValue(':limit', $limit, PDO::PARAM_INT);
    $st->execute();
    return $st->fetchAll();
}

function list_pending_review(array $params, array $actor): array
{
    $status = trim((string)($params['status'] ?? 'pending'));
    $limit = (int)($params['limit'] ?? 200);
    $limit = max(1, min($limit, 500));
    $poleKey = null;
    if (($actor['role'] ?? '') === 'controle_qualite') {
        $pole = trim((string)($actor['pole'] ?? ''));
        if ($pole === '') {
            api_error('Pole missing', 422);
        }
        $poleKey = normalize_zone_key($pole);
    }
    $sql = 'SELECT p.*, u.full_name AS user_name, u.email AS user_email
            FROM observation_pending p
            LEFT JOIN users u ON u.id = p.user_id
            WHERE p.status = :status';
    if ($poleKey !== null) {
        $sql .= ' AND UPPER(TRIM(p.site)) IN (
                SELECT scoped.site_norm FROM (
                    SELECT s.name_norm AS site_norm
                    FROM sites s
                    INNER JOIN zone z ON z.id = s.zone_id
                    WHERE z.name_norm = :pole
                    UNION
                    SELECT DISTINCT b2.site_norm AS site_norm
                    FROM birds b2
                    WHERE b2.site_norm IS NOT NULL
                      AND b2.zone_norm = :pole2
                ) scoped
            )';
    }
    $sql .= '
            ORDER BY p.created_at DESC, p.id DESC
            LIMIT :limit';
    $pdo = db();
    $st = $pdo->prepare($sql);
    $st->bindValue(':status', $status);
    if ($poleKey !== null) {
        $st->bindValue(':pole', $poleKey);
        $st->bindValue(':pole2', $poleKey);
    }
    $st->bindValue(':limit', $limit, PDO::PARAM_INT);
    $st->execute();
    return $st->fetchAll();
}

function assert_qc_site_access(?string $site, array $actor): void
{
    if (($actor['role'] ?? '') !== 'controle_qualite') {
        return;
    }
    $pole = trim((string)($actor['pole'] ?? ''));
    if ($pole === '') {
        api_error('Pole missing', 422);
    }
    $site = trim((string)$site);
    if ($site === '') {
        api_error('Forbidden', 403);
    }
    $pdo = db();
    $st = $pdo->prepare('SELECT 1 FROM (
            SELECT s.name_norm AS site_norm
            FROM sites s
            INNER JOIN zone z ON z.id = s.zone_id
            WHERE z.name_norm = :pole
            UNION
            SELECT DISTINCT b.site_norm AS site_norm
            FROM birds b
            WHERE b.site_norm IS NOT NULL
              AND b.zone_norm = :pole2
        ) scoped
        WHERE scoped.site_norm = UPPER(TRIM(:site))
        LIMIT 1');
    $st->execute([
        ':pole' => normalize_zone_key($pole),
        ':pole2' => normalize_zone_key($pole),
        ':site' => $site,
    ]);
    if (!$st->fetchColumn()) {
        api_error('Forbidden', 403);
    }
}

function approve_pending_observation(int $id, array $actor): array
{
    $pdo = db();
    $pdo->beginTransaction();
    try {
        $st = $pdo->prepare('SELECT * FROM observation_pending WHERE id = :id FOR UPDATE');
        $st->execute([':id' => $id]);
        $row = $st->fetch();
        if (!$row) {
            api_error('Pending observation not found', 404);
        }
        assert_qc_site_access($row['site'] ?? null, $actor);
        if (($row['status'] ?? '') !== 'pending') {
            api_error('Observation already processed', 409);
        }
        $now = now_ts();
        $columns = [
            'zone' => 'zone',
            'site' => 'site',
            'transect' => 'transect',
            'point' => 'point',
            'utm' => 'utm',
            'x' => 'x',
            'x_num' => 'x_num',
            'y' => 'y',
            'y_num' => 'y_num',
            'date' => 'date',
            'date_obs' => 'date_obs',
            'jour' => 'jour',
            'mois' => 'mois',
            'annee' => 'annee',
            'semaine' => 'semaine',
            'codeFrançais' => 'code_fr',
            'wiCode' => 'wicode',
            'nomFrançais' => 'nom_fr',
            'nomScientifique' => 'nom_sc',
            'englishName' => 'english',
            'famille' => 'famille',
            'effectif' => 'effectif',
            'effectif_int' => 'effectif_int',
            'statutDeConservation' => 'statut',
            'observateurs' => 'observateurs',
            'observations' => 'observations',
            'photo' => 'photo',
            'slug' => 'slug',
            'created_at' => 'created_at',
            'updated_at' => 'updated_at',
        ];
        $values = [
            'zone' => (string)($row['zone'] ?? ''),
            'site' => (string)($row['site'] ?? ''),
            'transect' => (string)($row['transect'] ?? ''),
            'point' => (string)($row['point'] ?? ''),
            'utm' => (string)($row['utm'] ?? ''),
            'x' => (string)($row['x'] ?? ''),
            'x_num' => $row['x_num'] ?? null,
            'y' => (string)($row['y'] ?? ''),
            'y_num' => $row['y_num'] ?? null,
            'date' => (string)($row['date'] ?? ''),
            'date_obs' => $row['date_obs'] ?? null,
            'jour' => (string)($row['jour'] ?? ''),
            'mois' => (string)($row['mois'] ?? ''),
            'annee' => (string)($row['annee'] ?? ''),
            'semaine' => (string)($row['semaine'] ?? ''),
            'codeFrançais' => (string)($row['codeFrançais'] ?? ''),
            'wiCode' => (string)($row['wiCode'] ?? ''),
            'nomFrançais' => (string)($row['nomFrançais'] ?? ''),
            'nomScientifique' => (string)($row['nomScientifique'] ?? ''),
            'englishName' => (string)($row['englishName'] ?? ''),
            'famille' => (string)($row['famille'] ?? ''),
            'effectif' => (string)($row['effectif'] ?? ''),
            'effectif_int' => $row['effectif_int'] ?? null,
            'statutDeConservation' => (string)($row['statutDeConservation'] ?? ''),
            'observateurs' => (string)($row['observateurs'] ?? ''),
            'observations' => (string)($row['observations'] ?? ''),
            'photo' => (string)($row['photo'] ?? ''),
            'slug' => '',
            'created_at' => $now,
            'updated_at' => $now,
        ];
        $sqlCols = implode(', ', array_map(fn($c) => "`{$c}`", array_keys($columns)));
        $sqlVals = implode(', ', array_map(fn($p) => ':' . $p, $columns));
        $sql = 'INSERT INTO birds (' . $sqlCols . ') VALUES (' . $sqlVals . ')';
        $stInsert = $pdo->prepare($sql);
        foreach ($columns as $col => $param) {
            $stInsert->bindValue(':' . $param, $values[$col]);
        }
        $stInsert->execute();
        $birdId = (int)$pdo->lastInsertId();
        $stUpdate = $pdo->prepare('UPDATE observation_pending SET status = :status, reviewed_by = :reviewed_by, reviewed_at = :reviewed_at, updated_at = :updated_at WHERE id = :id');
        $stUpdate->execute([
            ':status' => 'approved',
            ':reviewed_by' => (int)$actor['id'],
            ':reviewed_at' => $now,
            ':updated_at' => $now,
            ':id' => $id,
        ]);
        $pdo->commit();
        return ['bird_id' => $birdId];
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }
}

function reject_pending_observation(int $id, array $actor, string $note = ''): array
{
    $pdo = db();
    $stFetch = $pdo->prepare('SELECT zone, site, status FROM observation_pending WHERE id = :id LIMIT 1');
    $stFetch->execute([':id' => $id]);
    $row = $stFetch->fetch();
    if (!$row) {
        api_error('Pending observation not found', 404);
    }
    assert_qc_site_access($row['site'] ?? null, $actor);
    if (($row['status'] ?? '') !== 'pending') {
        api_error('Observation already processed', 409);
    }
    $st = $pdo->prepare('UPDATE observation_pending SET status = :status, review_note = :note, reviewed_by = :reviewed_by, reviewed_at = :reviewed_at, updated_at = :updated_at WHERE id = :id AND status = :pending');
    $now = now_ts();
    $st->execute([
        ':status' => 'rejected',
        ':note' => $note !== '' ? $note : null,
        ':reviewed_by' => (int)$actor['id'],
        ':reviewed_at' => $now,
        ':updated_at' => $now,
        ':id' => $id,
        ':pending' => 'pending',
    ]);
    if ($st->rowCount() === 0) {
        api_error('Pending observation not found', 404);
    }
    return ['id' => $id, 'status' => 'rejected'];
}

function q_observations_export(array $params): array
{
    $pdo = db();
    $useView = has_search_view();
    $limit = isset($params['limit']) ? (int)$params['limit'] : 2000;
    $limit = max(1, min($limit, 5000));

    if ($useView) {
        $dateExpr = view_date_expr('v', 'b');
        [$whereSql, $bindWhere] = build_where_view($params, 'v', $dateExpr);
        $sql = "SELECT
    v.doc_id AS doc_id,
    {$dateExpr} AS date_parsed,
    v.title AS title,
    v.zone_norm AS zone,
    v.site_norm AS site,
    v.famille,
    v.wiCode,
    v.code_fr,
    b.effectif,
    v.effectif_int
FROM search_observations_view v
LEFT JOIN birds b ON b.id = v.doc_id
{$whereSql}
ORDER BY date_parsed DESC, v.updated_at DESC, v.doc_id DESC
LIMIT :limit";
    } else {
        [$whereSql, $bindWhere] = build_where($params, true);
        $sql = 'SELECT
                    b.id AS doc_id,
                    STR_TO_DATE(b.date, "%d/%m/%Y") AS date_parsed,
                    concat_ws(" - ",
                        NULLIF(b.wiCode, ""),
                        NULLIF(b.codeFrançais, ""),
                        NULLIF(b.site, ""),
                        NULLIF(b.zone, "")
                    ) AS title,
                    b.zone_norm AS zone,
                    b.site_norm AS site,
                    b.famille,
                    b.wiCode,
                    b.codeFrançais AS code_fr,
                    b.effectif,
                    b.effectif_int
                FROM birds b
                ' . $whereSql . '
                ORDER BY date_parsed DESC, b.updated_at DESC, b.id DESC
                LIMIT :limit';
    }

    $st = $pdo->prepare($sql);
    foreach ($bindWhere as $k => $v) {
        $st->bindValue($k, $v);
    }
    $st->bindValue(':limit', $limit, PDO::PARAM_INT);
    $st->execute();
    $items = $st->fetchAll();
    foreach ($items as &$item) {
        $item['date'] = $item['date_parsed'];
        unset($item['date_parsed']);
    }
    return $items;
}

function render_export_html(array $items, array $params): string
{
    $escape = fn($v) => htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8');
    $filters = [];
    foreach (['q','zone','site','famille','date_from','date_to','count_min','count_max'] as $key) {
        if (!empty($params[$key])) {
            $filters[] = strtoupper($key) . ': ' . $escape($params[$key]);
        }
    }
    $filterText = $filters ? implode(' | ', $filters) : 'Aucun filtre';
    $rows = '';
    foreach ($items as $row) {
        $rows .= '<tr>'
            . '<td>' . $escape($row['date'] ?? '') . '</td>'
            . '<td>' . $escape($row['title'] ?? '') . '</td>'
            . '<td>' . $escape($row['famille'] ?? '') . '</td>'
            . '<td>' . $escape($row['zone'] ?? '') . '</td>'
            . '<td>' . $escape($row['site'] ?? '') . '</td>'
            . '<td>' . $escape($row['effectif'] ?? '') . '</td>'
            . '</tr>';
    }
    $html = '<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>Export observations</title>'
        . '<link rel="stylesheet" href="styles/app.css"/></head><body class="page-export">'
        . '<h1>Export observations</h1>'
        . '<p>' . $escape($filterText) . '</p>'
        . '<table><thead><tr>'
        . '<th>Date</th><th>Titre</th><th>Famille</th><th>Zone</th><th>Site</th><th>Effectif</th>'
        . '</tr></thead><tbody>'
        . ($rows !== '' ? $rows : '<tr><td colspan="6">Aucun resultat</td></tr>')
        . '</tbody></table>'
        . '<script>window.onload=function(){window.print();};</script>'
        . '</body></html>';
    return $html;
}

function count_observations(array $params): int
{
    $pdo = db();
    $useView = has_search_view();
    if ($useView) {
        $dateExpr = view_date_expr('v', 'b');
        [$whereSql, $bindWhere] = build_where_view($params, 'v', $dateExpr);
        $sql = 'SELECT COUNT(*) FROM search_observations_view v LEFT JOIN birds b ON b.id = v.doc_id ' . $whereSql;
    } else {
        [$whereSql, $bindWhere] = build_where($params, true);
        $sql = 'SELECT COUNT(*) FROM birds b ' . $whereSql;
    }
    $st = $pdo->prepare($sql);
    $st->execute($bindWhere);
    return (int)$st->fetchColumn();
}

function series_by_month(array $params): array
{
    $pdo = db();
    $useView = has_search_view();
    if ($useView) {
        $dateExpr = view_date_expr('v', 'b');
        [$whereSql, $bindWhere] = build_where_view($params, 'v', $dateExpr);
        $sql = 'SELECT DATE_FORMAT(' . $dateExpr . ', "%Y-%m") AS label, COUNT(*) AS value
                FROM search_observations_view v
                LEFT JOIN birds b ON b.id = v.doc_id
                ' . $whereSql . '
                AND ' . $dateExpr . ' IS NOT NULL
                GROUP BY label
                ORDER BY label';
    } else {
        [$whereSql, $bindWhere] = build_where($params, true);
        $sql = 'SELECT DATE_FORMAT(STR_TO_DATE(b.date, "%d/%m/%Y"), "%Y-%m") AS label, COUNT(*) AS value
                FROM birds b
                ' . $whereSql . '
                GROUP BY label
                ORDER BY label';
    }
    $st = $pdo->prepare($sql);
    $st->execute($bindWhere);
    return $st->fetchAll();
}

function q_evolution(array $params): array
{
    $now = new DateTime();
    $to = DateTime::createFromFormat('Y-m-d', (string)($params['date_to'] ?? '')) ?: $now;
    $from = DateTime::createFromFormat('Y-m-d', (string)($params['date_from'] ?? '')) ?: (clone $to)->modify('-365 days');
    if ($from > $to) {
        $tmp = $from;
        $from = $to;
        $to = $tmp;
    }
    $days = (int)$to->diff($from)->format('%a') + 1;
    $prevTo = (clone $from)->modify('-1 day');
    $prevFrom = (clone $prevTo)->modify('-' . max(1, $days - 1) . ' days');

    $currentParams = $params;
    $currentParams['date_from'] = $from->format('Y-m-d');
    $currentParams['date_to'] = $to->format('Y-m-d');
    $prevParams = $params;
    $prevParams['date_from'] = $prevFrom->format('Y-m-d');
    $prevParams['date_to'] = $prevTo->format('Y-m-d');

    $currentCount = count_observations($currentParams);
    $prevCount = count_observations($prevParams);
    $delta = $currentCount - $prevCount;
    $pct = $prevCount > 0 ? round(($delta / $prevCount) * 100, 2) : null;

    return [
        'current' => [
            'from' => $currentParams['date_from'],
            'to' => $currentParams['date_to'],
            'total' => $currentCount,
        ],
        'previous' => [
            'from' => $prevParams['date_from'],
            'to' => $prevParams['date_to'],
            'total' => $prevCount,
        ],
        'change' => [
            'delta' => $delta,
            'pct' => $pct,
        ],
        'series' => series_by_month($currentParams),
        'series_prev' => series_by_month($prevParams),
    ];
}

function fetch_messages(array $params, array $user): array
{
    $withId = (int)($params['with_user_id'] ?? 0);
    if ($withId <= 0) {
        api_error('with_user_id required', 422);
    }
    if (!has_messages_table()) {
        return [];
    }
    $table = message_table_name();
    $columns = message_column_map();
    $senderCol = $columns['sender'] ?? null;
    $recipientCol = $columns['recipient'] ?? null;
    $bodyCol = $columns['body'] ?? null;
    $createdCol = $columns['created'] ?? null;
    $idCol = $columns['id'] ?? null;
    $filePathCol = $columns['file_path'] ?? null;
    $fileNameCol = $columns['file_name'] ?? null;
    $fileSizeCol = $columns['file_size'] ?? null;
    $mimeTypeCol = $columns['mime_type'] ?? null;
    if (!$senderCol || !$recipientCol || !$bodyCol || !$idCol) {
        return [];
    }
    $sinceId = (int)($params['since_id'] ?? 0);
    $limit = (int)($params['limit'] ?? 200);
    $limit = max(1, min($limit, 500));
    $pdo = db();
    $createdExpr = $createdCol ? "m.`{$createdCol}`" : 'NULL';
    $attachmentSelect = '';
    if ($filePathCol) {
        $attachmentSelect .= ", m.`{$filePathCol}` AS attachment_path";
    }
    if ($fileNameCol) {
        $attachmentSelect .= ", m.`{$fileNameCol}` AS attachment_name";
    }
    if ($fileSizeCol) {
        $attachmentSelect .= ", m.`{$fileSizeCol}` AS attachment_size";
    }
    if ($mimeTypeCol) {
        $attachmentSelect .= ", m.`{$mimeTypeCol}` AS attachment_mime";
    }
    $selectBase = "SELECT
                m.`{$idCol}` AS id,
                m.`{$senderCol}` AS sender_id,
                m.`{$recipientCol}` AS recipient_id,
                m.`{$bodyCol}` AS body,
                {$createdExpr} AS created_at{$attachmentSelect}";
    $sql = $selectBase . ",
                u.full_name AS sender_name
            FROM `{$table}` m
            LEFT JOIN users u ON u.id = m.`{$senderCol}`
            WHERE ((m.`{$senderCol}` = :me AND m.`{$recipientCol}` = :with_id)
                OR (m.`{$senderCol}` = :with_id AND m.`{$recipientCol}` = :me))";
    $bind = [
        ':me' => (int)$user['id'],
        ':with_id' => $withId,
    ];
    if ($sinceId > 0) {
        $sql .= " AND m.`{$idCol}` > :since_id";
        $bind[':since_id'] = $sinceId;
    }
    $sql .= " ORDER BY m.`{$idCol}` ASC LIMIT :limit";
    try {
        $st = $pdo->prepare($sql);
        foreach ($bind as $k => $v) {
            $st->bindValue($k, $v);
        }
        $st->bindValue(':limit', $limit, PDO::PARAM_INT);
        $st->execute();
        $rows = $st->fetchAll();
    } catch (PDOException $e) {
        $fallback = $selectBase . ",
                NULL AS sender_name
            FROM `{$table}` m
            WHERE ((m.`{$senderCol}` = :me AND m.`{$recipientCol}` = :with_id)
                OR (m.`{$senderCol}` = :with_id AND m.`{$recipientCol}` = :me))";
        if ($sinceId > 0) {
            $fallback .= " AND m.`{$idCol}` > :since_id";
        }
        $fallback .= " ORDER BY m.`{$idCol}` ASC LIMIT :limit";
        try {
            $st = $pdo->prepare($fallback);
            foreach ($bind as $k => $v) {
                $st->bindValue($k, $v);
            }
            $st->bindValue(':limit', $limit, PDO::PARAM_INT);
            $st->execute();
            $rows = $st->fetchAll();
        } catch (PDOException $e2) {
            $me = (int)$user['id'];
            $withId = (int)$withId;
            $sinceSql = $sinceId > 0 ? " AND m.`{$idCol}` > {$sinceId}" : '';
            $fallbackRaw = $selectBase . ",
                    NULL AS sender_name
                FROM `{$table}` m
                WHERE ((m.`{$senderCol}` = {$me} AND m.`{$recipientCol}` = {$withId})
                    OR (m.`{$senderCol}` = {$withId} AND m.`{$recipientCol}` = {$me})){$sinceSql}
                ORDER BY m.`{$idCol}` ASC LIMIT {$limit}";
            try {
                $rows = $pdo->query($fallbackRaw)->fetchAll();
            } catch (PDOException $e3) {
                api_error('Messages query failed: ' . $e3->getMessage(), 500);
            }
        }
    }
    if (!$rows) {
        return [];
    }
    foreach ($rows as &$row) {
        $rowAttachments = [];
        if (!empty($row['attachment_path'])) {
            $rowAttachments[] = [
                'file_name' => (string)($row['attachment_name'] ?? basename((string)$row['attachment_path'])),
                'file_path' => (string)$row['attachment_path'],
                'file_url' => (string)$row['attachment_path'],
                'file_size' => (int)($row['attachment_size'] ?? 0),
                'mime_type' => (string)($row['attachment_mime'] ?? ''),
            ];
        }
        $row['attachments'] = $rowAttachments;
        unset($row['attachment_path'], $row['attachment_name'], $row['attachment_size'], $row['attachment_mime']);
    }
    return $rows;
}

function store_message_attachment(array $file, int $messageId): ?array
{
    if (empty($file) || !isset($file['error']) || $file['error'] === UPLOAD_ERR_NO_FILE) {
        return null;
    }
    if ($file['error'] !== UPLOAD_ERR_OK) {
        api_error('Upload failed', 400);
    }
    if (!is_uploaded_file($file['tmp_name'])) {
        api_error('Invalid upload', 400);
    }
    $size = (int)($file['size'] ?? 0);
    if ($size <= 0) {
        api_error('Empty file', 400);
    }
    $maxSize = 5 * 1024 * 1024;
    if ($size > $maxSize) {
        api_error('File too large (max 5MB)', 413);
    }
    $mime = mime_content_type($file['tmp_name']) ?: 'application/octet-stream';
    $allowed = [
        'image/jpeg',
        'image/png',
        'image/gif',
        'image/webp',
        'application/pdf',
        'text/plain',
        'text/csv',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ];
    if (!in_array($mime, $allowed, true)) {
        api_error('File type not allowed', 415);
    }

    $safeName = sanitize_filename((string)($file['name'] ?? 'piece_jointe'));
    $ext = pathinfo($safeName, PATHINFO_EXTENSION);
    $ext = $ext ? '.' . strtolower($ext) : '';
    $dir = messages_upload_dir();
    $fileName = 'msg_' . $messageId . '_' . bin2hex(random_bytes(8)) . $ext;
    $destPath = $dir . DIRECTORY_SEPARATOR . $fileName;
    if (!move_uploaded_file($file['tmp_name'], $destPath)) {
        api_error('Failed to save attachment', 500);
    }
    $relativePath = 'uploads/messages/' . $fileName;
    $now = now_ts();
    return [
        'id' => 0,
        'message_id' => $messageId,
        'file_name' => $safeName,
        'file_path' => $relativePath,
        'file_url' => $relativePath,
        'file_size' => $size,
        'mime_type' => $mime,
        'created_at' => $now,
    ];
}

function send_message(array $data, array $user, array $files = []): array
{
    $recipientId = (int)($data['recipient_id'] ?? 0);
    $body = trim((string)($data['body'] ?? ''));
    $hasAttachment = !empty($files['attachment']) && (($files['attachment']['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE);
    if ($recipientId <= 0 || ($body === '' && !$hasAttachment)) {
        api_error('recipient_id and message required', 422);
    }
    if (!has_messages_table()) {
        api_error('Messages table missing', 503);
    }
    $table = message_table_name();
    $columns = message_column_map();
    $senderCol = $columns['sender'] ?? null;
    $recipientCol = $columns['recipient'] ?? null;
    $bodyCol = $columns['body'] ?? null;
    $createdCol = $columns['created'] ?? null;
    $idCol = $columns['id'] ?? null;
    $filePathCol = $columns['file_path'] ?? null;
    $fileNameCol = $columns['file_name'] ?? null;
    $fileSizeCol = $columns['file_size'] ?? null;
    $mimeTypeCol = $columns['mime_type'] ?? null;
    if (!$senderCol || !$recipientCol || !$bodyCol || !$idCol) {
        api_error('Messages schema incomplete', 500);
    }
    if ($hasAttachment && !$filePathCol) {
        api_error('Attachment columns missing', 500);
    }
    $recipient = fetch_user_by_id($recipientId);
    if (!$recipient || ($recipient['status'] ?? '') !== 'active') {
        api_error('Recipient not found', 404);
    }
    $pdo = db();
    $now = now_ts();
    $cols = [$senderCol, $recipientCol, $bodyCol];
    $vals = [':sender', ':recipient', ':body'];
    $bind = [
        ':sender' => (int)$user['id'],
        ':recipient' => $recipientId,
        ':body' => $body,
    ];
    if ($createdCol) {
        $cols[] = $createdCol;
        $vals[] = ':created';
        $bind[':created'] = $now;
    }
    $sql = 'INSERT INTO `' . $table . '` (' . implode(', ', array_map(fn($c) => "`{$c}`", $cols)) . ') VALUES (' . implode(', ', $vals) . ')';
    $st = $pdo->prepare($sql);
    $st->execute($bind);
    $messageId = (int)$pdo->lastInsertId();
    $attachments = [];
    if ($hasAttachment) {
        if ($filePathCol) {
            $saved = store_message_attachment($files['attachment'], $messageId);
            if ($saved) {
                $updateCols = [$filePathCol => $saved['file_path']];
                if ($fileNameCol) {
                    $updateCols[$fileNameCol] = $saved['file_name'];
                }
                if ($fileSizeCol) {
                    $updateCols[$fileSizeCol] = (int)$saved['file_size'];
                }
                if ($mimeTypeCol) {
                    $updateCols[$mimeTypeCol] = $saved['mime_type'];
                }
                $setParts = [];
                $updateBind = [':id' => $messageId];
                foreach ($updateCols as $col => $val) {
                    $key = ':' . $col;
                    $setParts[] = "`{$col}` = {$key}";
                    $updateBind[$key] = $val;
                }
                if ($setParts) {
                    $stUpdate = $pdo->prepare('UPDATE `' . $table . '` SET ' . implode(', ', $setParts) . ' WHERE `' . $idCol . '` = :id');
                    $stUpdate->execute($updateBind);
                }
                $attachments[] = $saved;
            }
        } else {
            $saved = store_message_attachment($files['attachment'], $messageId);
            if ($saved) {
                $attachments[] = $saved;
            }
        }
    }
    return [
        'id' => $messageId,
        'sender_id' => (int)$user['id'],
        'recipient_id' => $recipientId,
        'body' => $body,
        'created_at' => $now,
        'attachments' => $attachments,
    ];
}

function stream_messages(array $params, array $user): void
{
    $withId = (int)($params['with_user_id'] ?? 0);
    if ($withId <= 0) {
        api_error('with_user_id required', 422);
    }
    $sinceId = (int)($params['since_id'] ?? 0);
    header('Content-Type: text/event-stream; charset=utf-8');
    header('Cache-Control: no-cache');
    header('Connection: keep-alive');
    header('X-Accel-Buffering: no');
    @ob_end_clean();
    ob_implicit_flush(true);
    session_write_close();

    $start = time();
    $lastPing = 0;
    while (time() - $start < 25) {
        $messages = fetch_messages(['with_user_id' => $withId, 'since_id' => $sinceId, 'limit' => 200], $user);
        if ($messages) {
            foreach ($messages as $msg) {
                $sinceId = max($sinceId, (int)$msg['id']);
                echo 'data: ' . json_encode($msg, JSON_UNESCAPED_UNICODE) . "\n\n";
            }
        } elseif (time() - $lastPing > 10) {
            echo "event: ping\ndata: {}\n\n";
            $lastPing = time();
        }
        if (connection_aborted()) {
            break;
        }
        usleep(500000);
    }
    exit;
}
