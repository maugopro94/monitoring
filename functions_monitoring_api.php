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
    if (function_exists('iconv')) {
        $ascii = iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $value);
        if ($ascii !== false) {
            $value = $ascii;
        }
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
        if ($lon === null || $lat === null) {
            $fallback = lookup_zone_coords($r['zone'] ?? null);
            if (is_array($fallback)) {
                $lon = $fallback['lon'];
                $lat = $fallback['lat'];
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
        'families'   => $families,
    ];
}