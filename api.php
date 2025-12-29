<?php
// Simple API entry point for the Monitoring application.
//
// This script dispatches requests based on the `route` query parameter.
// It relies on helper functions defined in functions_monitoring_api.php.

// Include the helper functions.
require_once __DIR__ . '/functions_monitoring_api.php';

// Allow CORS for local development.  You may restrict this in production.
header('Access-Control-Allow-Origin: *');
header('Content-Type: application/json; charset=utf-8');

// Read the route parameter from the query string.  Default to empty string.
$route = isset($_GET['route']) ? trim($_GET['route']) : '';

// Collect all parameters except `route` into $params for the helper functions.
$params = $_GET;
unset($params['route']);

// Dispatch based on route.  Supported routes:
//   - observations            : paginated list of observations
//   - observations/geo       : GeoJSON of observation points
//   - observations/stats     : summary statistics
//   - filters/zones          : list of zones
//   - filters/sites          : list of sites (optionally filter by zone)
try {
    switch ($route) {
        case 'observations':
            $result = q_observations($params);
            echo json_encode($result, JSON_UNESCAPED_UNICODE);
            break;
        case 'observations/geo':
            $result = q_geo($params);
            echo json_encode($result, JSON_UNESCAPED_UNICODE);
            break;
        case 'observations/stats':
            $result = q_stats($params);
            echo json_encode($result, JSON_UNESCAPED_UNICODE);
            break;
        case 'filters/zones':
            $result = q_zones($params);
            echo json_encode(['items' => $result], JSON_UNESCAPED_UNICODE);
            break;
        case 'filters/sites':
            $result = q_sites($params);
            echo json_encode(['items' => $result], JSON_UNESCAPED_UNICODE);
            break;
        default:
            // Unknown route.  Return a 404 response with helpful info.
            http_response_code(404);
            echo json_encode([
                'error' => 'Not found',
                'routes' => [
                    'observations'        => 'List observations with pagination',
                    'observations/geo'    => 'GeoJSON of observations',
                    'observations/stats'  => 'Dashboard statistics',
                    'filters/zones'       => 'List of available zones',
                    'filters/sites'       => 'List of available sites (optionally filtered by zone)'
                ],
            ], JSON_UNESCAPED_UNICODE);
            break;
    }
} catch (Throwable $e) {
    // Return a 500 with the error message for debugging.  In production,
    // you may want to hide the detailed message.
    http_response_code(500);
    echo json_encode([
        'error'   => 'Server error',
        'message' => $e->getMessage(),
        'file'    => $e->getFile(),
        'line'    => $e->getLine(),
    ], JSON_UNESCAPED_UNICODE);
}
