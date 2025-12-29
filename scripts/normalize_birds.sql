-- Normalize date_obs and effectif_int in birds.
-- Run this once after importing monitoring.sql.

UPDATE birds
SET
  date_obs = CASE
    WHEN date_obs IS NULL
      AND `date` REGEXP '^[0-9]{2}/[0-9]{2}/[0-9]{4}$'
    THEN STR_TO_DATE(`date`, '%d/%m/%Y')
    ELSE date_obs
  END,
  effectif_int = CASE
    WHEN effectif_int IS NULL THEN
      CASE
        WHEN effectif IS NULL THEN NULL
        WHEN TRIM(effectif) = '' THEN NULL
        WHEN TRIM(effectif) REGEXP '^[0-9]+$' THEN CAST(TRIM(effectif) AS UNSIGNED)
        WHEN TRIM(effectif) REGEXP '[0-9]+' THEN CAST(REGEXP_SUBSTR(TRIM(effectif), '[0-9]+') AS UNSIGNED)
        ELSE NULL
      END
    ELSE effectif_int
  END;
