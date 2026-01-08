# Monitoring - Observations

## Resume
Application web de consultation des observations (tableau, carte, stats).
Frontend en HTML/JS, backend PHP (WAMP), base MySQL.

## Architecture (vue d'ensemble)
- Frontend: `index_moteur.html` (single-page), filtres + tableau + stats.
  - Carte: MapLibre via CDN (WebGL requis).
  - Graphes: Chart.js via CDN.
- Backend: `api.php` (routeur) + `functions_monitoring_api.php` (requete SQL).
- Base de donnees: MySQL `monitoring` (dump `monitoring.sql`).
  - Tables principales: `birds`, `sites`, `points`, `zone`.
  - Vue: `search_observations_view` (utilisee si presente).
  - Donnees de secours pour la carte: `data/zone_coords.json`.

Flux principal:
```
index_moteur.html -> api.php?route=... -> functions_monitoring_api.php -> MySQL
```

## Structure du projet
- `index_moteur.html`: UI (filtres, tableau, stats, carte).
- `api.php`: point d'entree API (routes).
- `functions_monitoring_api.php`: logique SQL + format JSON.
- `monitoring.sql`: schema + donnees.
- `scripts/normalize_birds.sql`: normalisation apres import.
- `data/zone_coords.json`: coordonnees fallback par zone.

## Installation locale (WAMP)
1. Importer `monitoring.sql` dans la base `monitoring` (phpMyAdmin ou CLI).
2. Verifier les identifiants DB dans `functions_monitoring_api.php`:
   `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASS`.
3. (Recommande) Executer une fois `scripts/normalize_birds.sql` pour remplir
   `date_obs` et `effectif_int`.
4. Verifier la presence de `data/zone_coords.json`.

## Lancer l'application
Ouvrir `http://localhost/monitoring/index.html`.
Page d'accueil avec deux zones cliquables:
- Espace visiteur -> `index_moteur.html`
- Espace charge de suivi -> `charge_suivi.html`
- Espace controle qualite -> `controle_qualite.html`

Acces direct visiteur: `http://localhost/monitoring/index_moteur.html`.
Si WebGL est indisponible, l'onglet Carte est masque; utiliser Tableau/Stats.

## Espace Charge de suivi
Ouvrir `http://localhost/monitoring/charge_suivi.html`.

## Espace Controle qualite
Ouvrir `http://localhost/monitoring/controle_qualite.html`.

Profil "Charge de suivi" (role `charge_suivi`) - privileges principaux:
- Authentification: inscription + connexion.
- Soumission d'observations (formulaire inspire de `birds`) vers `observation_pending`.
- Suivi de ses soumissions (etat: pending/approved/rejected).
- Recherche et export PDF (impression) des resultats filtres.
- Rapport: carte + statistiques apres recherche.
- Partage des resultats par messagerie interne.
- Messagerie temps reel (SSE) + pieces jointes.
- Edition du profil (nom/email/telephone) et preferences UI.
- Evolution statistique (comparaison de periodes).
- Aide a la saisie: listes deroulantes (WiCode, code FR, nom FR, nom scientifique, anglais, famille) basees sur `birds`.

Profil "Controle qualite par pole" (role `controle_qualite`) - privileges principaux:
- Meme base que `charge_suivi`.
- Validation ou rejet des observations en attente pour son pole (zone, valeur normalisee).
- Insertion automatique dans `birds` apres validation.
- Gestion des comptes `charge_suivi` de son pole (creation/desactivation).
- Suivi des validations et exports filtres par pole.

Roles associes:
- `charge_suivi`: soumettre + consulter + partager.
- `controleur`: valider/rejeter les observations en attente.
- `controle_qualite`: valider/rejeter les observations de son pole + gestion charge_suivi.
- `admin`: meme droits que controleur + gestion de roles lors inscription.

Flux de validation:
```
charge_suivi -> observation_pending -> validation (controleur/controle_qualite/admin) -> birds
```

## API (routes et parametres)
Base: `api.php?route=...`

Routes:
- `observations`: liste paginee.
  - Params: `page`, `page_size` + filtres.
- `observations/geo`: GeoJSON pour la carte.
  - Params: `limit`, `bbox=minLon,minLat,maxLon,maxLat` + filtres.
- `observations/stats`: KPIs + series.
  - Params: filtres.
- `filters/zones`: liste des zones.
- `filters/sites`: liste des sites (param `zone` optionnel).
- `users/list`: liste des utilisateurs (admin/controle_qualite).
- `users/create`: creation utilisateur (admin/controle_qualite).
- `users/status`: activer/desactiver un utilisateur (admin/controle_qualite).

Filtres supportes:
- `q` (texte libre)
- `zone`, `site`, `famille`
- `wicode`, `code_fr` (backend uniquement)
- `date_from`, `date_to` (YYYY-MM-DD)
- `count_min`, `count_max` (effectif_int)

## Base de donnees (resume)
- `birds`: donnees d'observation (date en texte + colonnes normalisees).
  - `date` (dd/mm/YYYY) -> `date_obs` (DATE) via `normalize_birds.sql`.
  - `effectif` (texte) -> `effectif_int` (int) via `normalize_birds.sql`.
  - `zone_norm`, `site_norm` pour les filtres.
- `sites`: sites avec lat/lon.
- `points`: points par site (lat/lon).
- `zone`: liste de zones.
- `search_observations_view`: vue derivee de `birds`, utilisee si presente.
- `search_index`: present dans le dump, non utilise par l'API actuelle.
- `users`: comptes + roles (`charge_suivi`, `controleur`, `controle_qualite`, `admin`) + champ `pole`.
- `observation_pending`: observations en attente de validation.
- `messagerie`: messagerie interne (piece jointe integree dans la table).

## Maintenance / mises a jour futures
- Ajouter un filtre:
  - Frontend: `collectFilters()` dans `index_moteur.html`.
  - Backend: `build_where()` et `build_where_view()` dans
    `functions_monitoring_api.php`.
  - Optionnel: mettre a jour la vue dans `monitoring.sql`.
- Changer le schema DB:
  - Mettre a jour `monitoring.sql`.
  - Revoir `scripts/normalize_birds.sql` si colonnes modifiees.
  - Ajouter des index sur les colonnes filtrees.
- Changer la carte:
  - Modifier `q_geo()` (sources coords, proprietes, limites).
  - Ajuster `data/zone_coords.json` si besoin.
- Changer les stats:
  - Modifier `q_stats()` + rendu JS dans `index_moteur.html`.
- Ajouter un endpoint:
  - Ajouter la route dans `api.php` + fonction dans `functions_monitoring_api.php`.

## Notes pour assistance IA
- Lire d'abord ce README, puis `api.php`, `functions_monitoring_api.php`,
  `index_moteur.html`.
- Conserver les cles JSON retournees pour ne pas casser l'UI.
- Verifier la presence de `search_observations_view` (l'API l'utilise
  automatiquement si elle existe).
- En cas de points manquants sur la carte, controler `sites`, `points`
  et `data/zone_coords.json`.
