<?php
// This library provides helper functions for the monitoring API.
// It is designed to work with the WAMP stack and the monitoring database.
//
// Key differences from the original version:
// - It prefers search_observations_view (when available) for filtering
//   and date_obs support, with fallback to the `birds` table.
// - If search_observations_view is available, date_obs is used; otherwise
//   dates are parsed from the `date` column (dd/mm/YYYY) using STR_TO_DATE.
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
 * Quote a SQL identifier (column name) safely.
 *
 * @param string $name
 * @return string
 */
function sql_ident(string $name): string
{
    return '`' . str_replace('`', '``', $name) . '`';
}

/**
 * Return a set of available columns in the birds table.
 *
 * @return array<string,bool>
 */
function birds_columns(): array
{
    static $columns;
    if (is_array($columns)) {
        return $columns;
    }
    $pdo = db();
    $st = $pdo->query('SHOW COLUMNS FROM birds');
    $columns = [];
    foreach ($st->fetchAll(PDO::FETCH_COLUMN) as $name) {
        $columns[$name] = true;
    }
    return $columns;
}

/**
 * Resolve optional column names that vary across imports.
 *
 * @param string $key
 * @return string|null
 */
function birds_column_name(string $key): ?string
{
    static $map = [
        'code_fr' => ['code_fr', 'codeFrancais', 'codeFrançais', 'codeFrançais', 'codeFranÃ§ais'],
        'nom_fr'  => ['nom_fr', 'nomFrancais', 'nomFrançais', 'nomFrançais', 'nomFranÃ§ais'],
    ];
    if (!isset($map[$key])) {
        return null;
    }
    $columns = birds_columns();
    foreach ($map[$key] as $candidate) {
        if (isset($columns[$candidate])) {
            return $candidate;
        }
    }
    return null;
}

/**
 * Build a qualified column expression (with table alias).
 *
 * @param string $key
 * @return string|null
 */
function birds_column_expr(string $key): ?string
{
    $name = birds_column_name($key);
    return $name ? 'b.' . sql_ident($name) : null;
}

/**
 * NULLIF helper for optional columns.
 *
 * @param string|null $colExpr
 * @return string
 */
function nullif_expr(?string $colExpr): string
{
    return $colExpr ? 'NULLIF(' . $colExpr . ", '')" : 'NULL';
}

/**
 * Build a title expression for list and map views.
 *
 * @param string|null $codeFrCol
 * @return string
 */
function build_title_expr(?string $codeFrCol): string
{
    $parts = [
        "NULLIF(b.wiCode, '')",
        nullif_expr($codeFrCol),
        "NULLIF(b.site, '')",
        "NULLIF(b.zone, '')",
    ];
    return "concat_ws(' - ', " . implode(', ', $parts) . ")";
}

/**
 * Build the SQL WHERE clause and bind array based on request parameters.
 *
 * The monitoring schema stores dates as dd/mm/YYYY in the `date` column.
 * Because the `date_obs` column is null across the dataset, we parse
 * `date` on the fly using STR_TO_DATE for filtering. We build a
 * where-clause beginning with "WHERE 1=1" to simplify appending
 * conditions. Bindings for the prepared statement are returned in
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
 * @return array [string $whereSql, array $bind]
 */
function build_where(array $params): array
{
    $where = 'WHERE 1=1';
    $bind = [];

    // Free text search: match against several fields using LIKE.
    if (!empty($params['q'])) {
        $query = trim((string)$params['q']);
        if ($query !== '') {
            $codeFrCol = birds_column_expr('code_fr');
            $nomFrCol = birds_column_expr('nom_fr');
            $likeFields = array_filter([
                'b.wiCode',
                $codeFrCol,
                $nomFrCol,
                'b.nomScientifique',
                'b.englishName',
                'b.famille',
                'b.zone',
                'b.site',
                'b.observateurs',
                'b.observations',
            ]);
            $parts = [];
            $q = '%' . $query . '%';
            foreach ($likeFields as $i => $field) {
                $ph = ':q' . $i;
                $parts[] = $field . ' LIKE ' . $ph;
                $bind[$ph] = $q;
            }
            $where .= ' AND (' . implode(' OR ', $parts) . ')';
        }
    }
    // Exact match filters
    if (!empty($params['zone'])) {
        $zone = strtoupper(trim((string)$params['zone']));
        if ($zone !== '') {
            $where .= ' AND b.zone_norm = :zone';
            $bind[':zone'] = $zone;
        }
    }
    if (!empty($params['site'])) {
        $site = strtoupper(trim((string)$params['site']));
        if ($site !== '') {
            $where .= ' AND b.site_norm = :site';
            $bind[':site'] = $site;
        }
    }
    if (!empty($params['famille'])) {
        $famille = trim((string)$params['famille']);
        if ($famille !== '') {
            $where .= ' AND b.famille = :famille';
            $bind[':famille'] = $famille;
        }
    }
    if (!empty($params['wicode'])) {
        $wicode = trim((string)$params['wicode']);
        if ($wicode !== '') {
            $where .= ' AND b.wiCode = :wicode';
            $bind[':wicode'] = $wicode;
        }
    }
    if (!empty($params['code_fr'])) {
        $codeFrCol = birds_column_expr('code_fr');
        $codeFr = trim((string)$params['code_fr']);
        if ($codeFrCol && $codeFr !== '') {
            $where .= ' AND ' . $codeFrCol . ' = :code_fr';
            $bind[':code_fr'] = $codeFr;
        }
    }

    // Date range: parse `date` string into DATE using STR_TO_DATE.
    // We only apply date filters if provided. The input is expected in
    // ISO format (YYYY-MM-DD). MySQL will compare DATEs correctly.
    if (!empty($params['date_from']) && preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)$params['date_from'])) {
        $where .= ' AND STR_TO_DATE(b.date, "%d/%m/%Y") >= :date_from';
        $bind[':date_from'] = $params['date_from'];
    }
    if (!empty($params['date_to']) && preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)$params['date_to'])) {
        $where .= ' AND STR_TO_DATE(b.date, "%d/%m/%Y") <= :date_to';
        $bind[':date_to'] = $params['date_to'];
    }

    // Effectif range
    if (isset($params['count_min']) && $params['count_min'] !== '' && is_numeric($params['count_min'])) {
        $where .= ' AND IFNULL(b.effectif_int, 0) >= :count_min';
        $bind[':count_min'] = (int)$params['count_min'];
    }
    if (isset($params['count_max']) && $params['count_max'] !== '' && is_numeric($params['count_max'])) {
        $where .= ' AND IFNULL(b.effectif_int, 0) <= :count_max';
        $bind[':count_max'] = (int)$params['count_max'];
    }

    return [$where, $bind];
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
 * Build the SQL WHERE clause for search_observations_view.
 *
 * @param array $params
 * @param string $alias
 * @return array [string $whereSql, array $bind]
 */
function build_where_view(array $params, string $alias = 'v'): array
{
    $where = 'WHERE 1=1';
    $bind = [];

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

    if (!empty($params['date_from']) && preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)$params['date_from'])) {
        $where .= " AND {$alias}.date_obs >= :date_from";
        $bind[':date_from'] = $params['date_from'];
    }
    if (!empty($params['date_to']) && preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)$params['date_to'])) {
        $where .= " AND {$alias}.date_obs <= :date_to";
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
        $zone = strtoupper(trim((string)$params['zone']));
        if ($zone !== '') {
            $sql .= ' AND b.zone_norm = :zone';
            $bind[':zone'] = $zone;
        }
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
        [$whereSql, $bindWhere] = build_where_view($params, 'v');

        // Total count
        $sqlTotal = 'SELECT COUNT(*) FROM search_observations_view v ' . $whereSql;
        $st = $pdo->prepare($sqlTotal);
        $st->execute($bindWhere);
        $total = (int)$st->fetchColumn();

        $sql = "SELECT
    v.doc_id AS doc_id,
    v.date_obs AS date_parsed,
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
ORDER BY v.date_obs DESC, v.updated_at DESC, v.doc_id DESC
LIMIT :limit OFFSET :offset";
    } else {
        [$whereSql, $bindWhere] = build_where($params);

        // Total count
        $sqlTotal = 'SELECT COUNT(*) FROM birds b ' . $whereSql;
        $st = $pdo->prepare($sqlTotal);
        $st->execute($bindWhere);
        $total = (int)$st->fetchColumn();

        $codeFrCol = birds_column_expr('code_fr');
        $titleExpr = build_title_expr($codeFrCol);
        $codeFrSelect = $codeFrCol ? $codeFrCol . ' AS code_fr' : 'NULL AS code_fr';

        // Items query. Parse date string to DATE for ordering and display.
        $sql = "SELECT
    b.id AS doc_id,
    STR_TO_DATE(b.date, '%d/%m/%Y') AS date_parsed,
    {$titleExpr} AS title,
    b.zone_norm AS zone,
    b.site_norm AS site,
    b.famille,
    b.wiCode,
    {$codeFrSelect},
    b.effectif,
    b.effectif_int
FROM birds b
{$whereSql}
ORDER BY date_parsed DESC, b.updated_at DESC, b.id DESC
LIMIT :limit OFFSET :offset";
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
 * tables if birds.x_num/y_num are null. It returns a GeoJSON
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
        [$whereSql, $bindWhere] = build_where_view($params, 'v');
    } else {
        [$whereSql, $bindWhere] = build_where($params);
    }

    // Determine limit. Default 10000 to avoid overloading the map.
    $limit = isset($params['limit']) && (int)$params['limit'] > 0 ? (int)$params['limit'] : 10000;
    $limit = min($limit, 20000);

    // Bbox filter: expects 'minLon,minLat,maxLon,maxLat'
    $bboxClause = '';
    if (!empty($params['bbox'])) {
        $bboxParts = explode(',', $params['bbox']);
        if (count($bboxParts) === 4) {
            list($minLon, $minLat, $maxLon, $maxLat) = array_map('floatval', $bboxParts);
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
                v.date_obs AS date_parsed,
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
            HAVING lon IS NOT NULL AND lat IS NOT NULL
            ORDER BY v.updated_at DESC, v.doc_id DESC
            LIMIT :limit";
    } else {
        $codeFrCol = birds_column_expr('code_fr');
        $titleExpr = build_title_expr($codeFrCol);
        $codeFrSelect = $codeFrCol ? $codeFrCol . ' AS code_fr' : 'NULL AS code_fr';

        // Query: join birds -> points -> sites to obtain coordinates
        $sql = "SELECT
                b.id AS doc_id,
                COALESCE(p.lon, s.lon, b.x_num) AS lon,
                COALESCE(p.lat, s.lat, b.y_num) AS lat,
                STR_TO_DATE(b.date, '%d/%m/%Y') AS date_parsed,
                b.zone_norm AS zone,
                b.site_norm AS site,
                b.famille,
                b.wiCode,
                {$codeFrSelect},
                {$titleExpr} AS title,
                b.effectif_int AS effectif
            FROM birds b
            LEFT JOIN sites s ON s.name_norm = b.site_norm
            LEFT JOIN points p ON p.site_id = s.id AND p.name = b.point
            {$whereSql}{$bboxClause}
            HAVING lon IS NOT NULL AND lat IS NOT NULL
            ORDER BY b.updated_at DESC, b.id DESC
            LIMIT :limit";
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
        $features[] = [
            'type' => 'Feature',
            'geometry' => [
                'type' => 'Point',
                'coordinates' => [(float)$r['lon'], (float)$r['lat']],
            ],
            'properties' => [
                'doc_id'   => $r['doc_id'],
                'title'    => $r['title'],
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
        [$whereSql, $bindWhere] = build_where_view($params, 'v');

        // KPI counts
        $sqlObs = 'SELECT COUNT(*) FROM search_observations_view v ' . $whereSql;
        $stObs = $pdo->prepare($sqlObs);
        $stObs->execute($bindWhere);
        $countObs = (int)$stObs->fetchColumn();

        $sqlSpecies = 'SELECT COUNT(DISTINCT v.wiCode) FROM search_observations_view v ' . $whereSql;
        $stSpecies = $pdo->prepare($sqlSpecies);
        $stSpecies->execute($bindWhere);
        $countSpecies = (int)$stSpecies->fetchColumn();

        $sqlSites = 'SELECT COUNT(DISTINCT v.site_norm) FROM search_observations_view v ' . $whereSql;
        $stSites = $pdo->prepare($sqlSites);
        $stSites->execute($bindWhere);
        $countSites = (int)$stSites->fetchColumn();

        $sqlZones = 'SELECT COUNT(DISTINCT v.zone_norm) FROM search_observations_view v ' . $whereSql;
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
                        DATE_FORMAT(v.date_obs, "%Y-%m") AS label,
                        COUNT(*) AS value
                    FROM search_observations_view v
                    ' . $whereSql . '
                    AND v.date_obs IS NOT NULL
                    GROUP BY label
                    ORDER BY label';
        $stTime = $pdo->prepare($sqlTime);
        $stTime->execute($bindWhere);
        $timeSeries = $stTime->fetchAll();

        $sqlTopSpecies = 'SELECT v.wiCode AS label, COUNT(*) AS value
                          FROM search_observations_view v
                          ' . $whereSql . '
                          GROUP BY label
                          ORDER BY value DESC
                          LIMIT 10';
        $stTopSpecies = $pdo->prepare($sqlTopSpecies);
        $stTopSpecies->execute($bindWhere);
        $topSpecies = $stTopSpecies->fetchAll();

        $sqlTopSites = 'SELECT v.site_norm AS label, COUNT(*) AS value
                        FROM search_observations_view v
                        ' . $whereSql . '
                        GROUP BY label
                        ORDER BY value DESC
                        LIMIT 10';
        $stTopSites = $pdo->prepare($sqlTopSites);
        $stTopSites->execute($bindWhere);
        $topSites = $stTopSites->fetchAll();

        $sqlFamilies = 'SELECT v.famille AS label, COUNT(*) AS value
                        FROM search_observations_view v
                        ' . $whereSql . '
                        GROUP BY label
                        ORDER BY value DESC
                        LIMIT 10';
        $stFamilies = $pdo->prepare($sqlFamilies);
        $stFamilies->execute($bindWhere);
        $families = $stFamilies->fetchAll();
    } else {
        [$whereSql, $bindWhere] = build_where($params);

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
