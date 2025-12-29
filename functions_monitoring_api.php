<?php
// This library provides helper functions for the monitoring API.
// It is designed to work with the WAMP stack and the monitoring database.
//
// Key differences from the original version:
// - It does not depend on the search_observations_view.  Instead, it
//   operates directly on the `birds` table.
// - All date filtering and sorting uses the `date` column (dd/mm/YYYY
//   string) rather than `date_obs`, because `date_obs` is NULL across
//   the provided dataset【526509672850058†L400-L411】.  Dates are parsed on the fly
//   using STR_TO_DATE.
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
            b.codeFrançais LIKE :q OR
            b.nomFrançais LIKE :q OR
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
        $where .= ' AND b.codeFrançais = :code_fr';
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
    [$whereSql, $bindWhere] = build_where($params);

    // Determine page and page_size
    $page = isset($params['page']) && (int)$params['page'] > 0 ? (int)$params['page'] : 1;
    $pageSize = isset($params['page_size']) && (int)$params['page_size'] > 0 ? (int)$params['page_size'] : 25;
    $pageSize = min($pageSize, 200); // limit to avoid huge loads
    $offset = ($page - 1) * $pageSize;

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
                    NULLIF(b.wiCode, ''),
                    NULLIF(b.codeFrançais, ''),
                    NULLIF(b.site, ''),
                    NULLIF(b.zone, '')
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
    [$whereSql, $bindWhere] = build_where($params, true);

    // Determine limit.  Default 10000 to avoid overloading the map.
    $limit = isset($params['limit']) && (int)$params['limit'] > 0 ? (int)$params['limit'] : 10000;
    $limit = min($limit, 20000);

    // Bbox filter: expects 'minLon,minLat,maxLon,maxLat'
    $bboxClause = '';
    if (!empty($params['bbox'])) {
        $bboxParts = explode(',', $params['bbox']);
        if (count($bboxParts) === 4) {
            list($minLon, $minLat, $maxLon, $maxLat) = array_map('floatval', $bboxParts);
            // Use birds.x_num/y_num first; fallback to site/point later
            $bboxClause = ' AND (
                (
                    b.x_num IS NOT NULL AND b.y_num IS NOT NULL
                    AND b.x_num BETWEEN :minLon AND :maxLon
                    AND b.y_num BETWEEN :minLat AND :maxLat
                ) OR (
                    b.x_num IS NULL OR b.y_num IS NULL
                )
            )';
            $bindWhere[':minLon'] = $minLon;
            $bindWhere[':maxLon'] = $maxLon;
            $bindWhere[':minLat'] = $minLat;
            $bindWhere[':maxLat'] = $maxLat;
        }
    }

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
            HAVING lon IS NOT NULL AND lat IS NOT NULL
            ORDER BY b.updated_at DESC, b.id DESC
            LIMIT :limit';

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
        $features[] = [
            'type' => 'Feature',
            'geometry' => [
                'type' => 'Point',
                'coordinates' => [(float)$r['lon'], (float)$r['lat']],
            ],
            'properties' => [
                'doc_id'   => $r['doc_id'],
                'date_obs' => $r['date_parsed'],
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
    [$whereSql, $bindWhere] = build_where($params, true);

    // KPI counts
    // Observations count
    $sqlObs = 'SELECT COUNT(*) FROM birds b ' . $whereSql;
    $stObs = $pdo->prepare($sqlObs);
    $stObs->execute($bindWhere);
    $countObs = (int)$stObs->fetchColumn();

    // Distinct species count (wiCode)
    $sqlSpecies = 'SELECT COUNT(DISTINCT b.wiCode) FROM birds b ' . $whereSql;
    $stSpecies = $pdo->prepare($sqlSpecies);
    $stSpecies->execute($bindWhere);
    $countSpecies = (int)$stSpecies->fetchColumn();

    // Distinct sites count
    $sqlSites = 'SELECT COUNT(DISTINCT b.site_norm) FROM birds b ' . $whereSql;
    $stSites = $pdo->prepare($sqlSites);
    $stSites->execute($bindWhere);
    $countSites = (int)$stSites->fetchColumn();

    // Distinct zones count
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

    // Time series: observations per month (YYYY-MM)
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

    // Top species (by wiCode)
    $sqlTopSpecies = 'SELECT b.wiCode AS label, COUNT(*) AS value
                      FROM birds b
                      ' . $whereSql . '
                      GROUP BY label
                      ORDER BY value DESC
                      LIMIT 10';
    $stTopSpecies = $pdo->prepare($sqlTopSpecies);
    $stTopSpecies->execute($bindWhere);
    $topSpecies = $stTopSpecies->fetchAll();

    // Top sites
    $sqlTopSites = 'SELECT b.site_norm AS label, COUNT(*) AS value
                    FROM birds b
                    ' . $whereSql . '
                    GROUP BY label
                    ORDER BY value DESC
                    LIMIT 10';
    $stTopSites = $pdo->prepare($sqlTopSites);
    $stTopSites->execute($bindWhere);
    $topSites = $stTopSites->fetchAll();

    // Families distribution
    $sqlFamilies = 'SELECT b.famille AS label, COUNT(*) AS value
                    FROM birds b
                    ' . $whereSql . '
                    GROUP BY label
                    ORDER BY value DESC
                    LIMIT 10';
    $stFamilies = $pdo->prepare($sqlFamilies);
    $stFamilies->execute($bindWhere);
    $families = $stFamilies->fetchAll();

    return [
        'kpis'       => $kpis,
        'time'       => $timeSeries,
        'top_species'=> $topSpecies,
        'top_sites'  => $topSites,
        'families'   => $families,
    ];
}
