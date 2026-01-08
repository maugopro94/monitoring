<?php
// Simple API entry point for the Monitoring application.
//
// This script dispatches requests based on the `route` query parameter.
// It relies on helper functions defined in functions_monitoring_api.php.

// Include the helper functions.
require_once __DIR__ . '/functions_monitoring_api.php';

// Allow CORS for local development.  You may restrict this in production.
header('Access-Control-Allow-Origin: *');
session_start();

function apply_qc_scope_params(array $params): array
{
    if (empty($_SESSION['user_id'])) {
        return $params;
    }
    $user = fetch_user_by_id((int)$_SESSION['user_id']);
    if (!$user || ($user['role'] ?? '') !== 'controle_qualite') {
        return $params;
    }
    $pole = trim((string)($user['pole'] ?? ''));
    if ($pole === '') {
        return $params;
    }
    $params['qc_pole'] = $pole;
    return $params;
}

// Read the route parameter from the query string.  Default to empty string.
$route = isset($_GET['route']) ? trim($_GET['route']) : '';

// Collect all parameters except `route` into $params for the helper functions.
$params = $_GET;
unset($params['route']);
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $body = read_body_params();
    if ($body) {
        $params = array_merge($params, $body);
    }
}

// Dispatch based on route.  Supported routes:
//   - observations            : paginated list of observations
//   - observations/geo       : GeoJSON of observation points
//   - observations/stats     : summary statistics
//   - filters/zones          : list of zones
//   - filters/sites          : list of sites (optionally filter by zone)
try {
    switch ($route) {
        case 'observations':
            header('Content-Type: application/json; charset=utf-8');
            $result = q_observations(apply_qc_scope_params($params));
            echo json_encode($result, JSON_UNESCAPED_UNICODE);
            break;
        case 'observations/geo':
            header('Content-Type: application/json; charset=utf-8');
            $result = q_geo(apply_qc_scope_params($params));
            echo json_encode($result, JSON_UNESCAPED_UNICODE);
            break;
        case 'observations/stats':
            header('Content-Type: application/json; charset=utf-8');
            $result = q_stats(apply_qc_scope_params($params));
            echo json_encode($result, JSON_UNESCAPED_UNICODE);
            break;
        case 'observations/species':
            header('Content-Type: application/json; charset=utf-8');
            $items = list_species_options();
            echo json_encode(['items' => $items], JSON_UNESCAPED_UNICODE);
            break;
        case 'members/list':
            header('Content-Type: application/json; charset=utf-8');
            $items = list_members($params);
            echo json_encode(['items' => $items], JSON_UNESCAPED_UNICODE);
            break;
        case 'especes/list':
            header('Content-Type: application/json; charset=utf-8');
            $items = list_especes($params);
            echo json_encode(['items' => $items], JSON_UNESCAPED_UNICODE);
            break;
        case 'observations/export':
            $items = q_observations_export(apply_qc_scope_params($params));
            header('Content-Type: text/html; charset=utf-8');
            echo render_export_html($items, $params);
            break;
        case 'observations/evolution':
            header('Content-Type: application/json; charset=utf-8');
            $result = q_evolution(apply_qc_scope_params($params));
            echo json_encode($result, JSON_UNESCAPED_UNICODE);
            break;
        case 'filters/zones':
            header('Content-Type: application/json; charset=utf-8');
            $result = q_zones(apply_qc_scope_params($params));
            echo json_encode(['items' => $result], JSON_UNESCAPED_UNICODE);
            break;
        case 'filters/sites':
            header('Content-Type: application/json; charset=utf-8');
            $result = q_sites(apply_qc_scope_params($params));
            echo json_encode(['items' => $result], JSON_UNESCAPED_UNICODE);
            break;
        case 'auth/register':
            header('Content-Type: application/json; charset=utf-8');
            $actor = null;
            if (!empty($_SESSION['user_id'])) {
                $actor = fetch_user_by_id((int)$_SESSION['user_id']);
            }
            $result = register_user($params, $actor);
            echo json_encode(['user' => $result], JSON_UNESCAPED_UNICODE);
            break;
        case 'auth/login':
            header('Content-Type: application/json; charset=utf-8');
            $result = login_user($params);
            echo json_encode(['user' => $result], JSON_UNESCAPED_UNICODE);
            break;
        case 'auth/logout':
            header('Content-Type: application/json; charset=utf-8');
            clear_session_user();
            echo json_encode(['ok' => true], JSON_UNESCAPED_UNICODE);
            break;
        case 'auth/me':
            header('Content-Type: application/json; charset=utf-8');
            if (empty($_SESSION['user_id'])) {
                http_response_code(401);
                echo json_encode(['error' => 'Unauthorized'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $user = fetch_user_by_id((int)$_SESSION['user_id']);
            if (!$user) {
                http_response_code(401);
                echo json_encode(['error' => 'Unauthorized'], JSON_UNESCAPED_UNICODE);
                break;
            }
            echo json_encode(['user' => sanitize_user($user)], JSON_UNESCAPED_UNICODE);
            break;
        case 'profile/update':
            header('Content-Type: application/json; charset=utf-8');
            $user = require_session_user();
            $result = update_user_profile($params, $user);
            echo json_encode(['user' => $result], JSON_UNESCAPED_UNICODE);
            break;
        case 'pending/create':
            header('Content-Type: application/json; charset=utf-8');
            $user = require_session_user();
            $result = create_pending_observation($params, $user);
            echo json_encode($result, JSON_UNESCAPED_UNICODE);
            break;
        case 'pending/list':
            header('Content-Type: application/json; charset=utf-8');
            $user = require_session_user();
            $items = list_pending_observations($params, $user);
            echo json_encode(['items' => $items], JSON_UNESCAPED_UNICODE);
            break;
        case 'pending/review':
            header('Content-Type: application/json; charset=utf-8');
            $user = require_session_user(['controleur', 'controle_qualite', 'admin']);
            $items = list_pending_review($params, $user);
            echo json_encode(['items' => $items], JSON_UNESCAPED_UNICODE);
            break;
        case 'pending/approve':
            header('Content-Type: application/json; charset=utf-8');
            $actor = require_session_user(['controleur', 'controle_qualite', 'admin']);
            $id = isset($params['id']) ? (int)$params['id'] : 0;
            if ($id <= 0) {
                throw new ApiException('Missing id', 422);
            }
            $result = approve_pending_observation($id, $actor);
            echo json_encode($result, JSON_UNESCAPED_UNICODE);
            break;
        case 'pending/reject':
            header('Content-Type: application/json; charset=utf-8');
            $actor = require_session_user(['controleur', 'controle_qualite', 'admin']);
            $id = isset($params['id']) ? (int)$params['id'] : 0;
            if ($id <= 0) {
                throw new ApiException('Missing id', 422);
            }
            $note = (string)($params['note'] ?? '');
            $result = reject_pending_observation($id, $actor, $note);
            echo json_encode($result, JSON_UNESCAPED_UNICODE);
            break;
        case 'messages/users':
        case 'messagerie/users':
            header('Content-Type: application/json; charset=utf-8');
            $user = require_session_user();
            $items = list_users_basic($user);
            echo json_encode(['items' => $items], JSON_UNESCAPED_UNICODE);
            break;
        case 'messages/list':
        case 'messagerie/list':
            header('Content-Type: application/json; charset=utf-8');
            $user = require_session_user();
            $items = fetch_messages($params, $user);
            echo json_encode(['items' => $items], JSON_UNESCAPED_UNICODE);
            break;
        case 'messages/send':
        case 'messagerie/send':
            header('Content-Type: application/json; charset=utf-8');
            $user = require_session_user();
            $result = send_message($params, $user, $_FILES ?? []);
            echo json_encode($result, JSON_UNESCAPED_UNICODE);
            break;
        case 'messages/stream':
        case 'messagerie/stream':
            $user = require_session_user();
            stream_messages($params, $user);
            break;
        case 'users/list':
            header('Content-Type: application/json; charset=utf-8');
            $user = require_session_user(['admin', 'controle_qualite']);
            $items = list_users_admin($params, $user);
            echo json_encode(['items' => $items], JSON_UNESCAPED_UNICODE);
            break;
        case 'users/create':
            header('Content-Type: application/json; charset=utf-8');
            $user = require_session_user(['admin', 'controle_qualite']);
            $result = create_user_admin($params, $user);
            echo json_encode(['user' => $result], JSON_UNESCAPED_UNICODE);
            break;
        case 'users/status':
            header('Content-Type: application/json; charset=utf-8');
            $user = require_session_user(['admin', 'controle_qualite']);
            $result = update_user_status($params, $user);
            echo json_encode(['user' => $result], JSON_UNESCAPED_UNICODE);
            break;
        default:
            // Unknown route.  Return a 404 response with helpful info.
            http_response_code(404);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'error' => 'Not found',
                'routes' => [
                    'observations'        => 'List observations with pagination',
                    'observations/geo'    => 'GeoJSON of observations',
                    'observations/stats'  => 'Dashboard statistics',
                    'observations/export' => 'HTML export (print to PDF)',
                    'observations/evolution' => 'Compare periods',
                    'filters/zones'       => 'List of available zones',
                    'filters/sites'       => 'List of available sites (optionally filtered by zone)',
                    'especes/list'        => 'List species catalog',
                    'auth/register'       => 'Register user',
                    'auth/login'          => 'Login user',
                    'auth/logout'         => 'Logout user',
                    'auth/me'             => 'Current user',
                    'pending/create'      => 'Submit observation',
                    'pending/list'        => 'My submissions',
                    'pending/review'      => 'Review submissions',
                    'messages/users'      => 'List users',
                    'messages/list'       => 'List messages',
                    'messages/send'       => 'Send message',
                    'messages/stream'     => 'Stream messages (SSE)',
                    'messagerie/users'    => 'Alias: list users',
                    'messagerie/list'     => 'Alias: list messages',
                    'messagerie/send'     => 'Alias: send message',
                    'messagerie/stream'   => 'Alias: stream messages (SSE)',
                    'users/list'          => 'List users (admin/controle_qualite)',
                    'users/create'        => 'Create user (admin/controle_qualite)',
                    'users/status'        => 'Update user status (admin/controle_qualite)'
                ],
            ], JSON_UNESCAPED_UNICODE);
            break;
    }
} catch (ApiException $e) {
    http_response_code($e->status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'error' => $e->getMessage(),
    ], JSON_UNESCAPED_UNICODE);
} catch (Throwable $e) {
    // Return a 500 with the error message for debugging.  In production,
    // you may want to hide the detailed message.
    http_response_code(500);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'error'   => 'Server error',
        'message' => $e->getMessage(),
        'file'    => $e->getFile(),
        'line'    => $e->getLine(),
    ], JSON_UNESCAPED_UNICODE);
}
