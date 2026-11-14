# site-monitor

Surveillance gratuite (sans IA) de sites web, avec alertes WhatsApp via [CallMeBot](https://www.callmebot.com/blog/free-api-whatsapp-messages/).

- **Pannes** (`monitor.yml`, toutes les 5 min) : site injoignable → alerte, rappel toutes les heures, message au rétablissement.
- **Sécurité, contrôle extérieur** (même workflow) : lit le rapport de sécurité publié par le serveur ; rapport absent, périmé ou anomalie critique → alerte (rappel toutes les 12 h).
- **Bilan du lundi** (`weekly.yml`) : SEO technique, Google Search Console (7 j vs 7 j), versions Next.js/React, sécurité du serveur.

## Secrets (Settings → Secrets and variables → Actions)

| Secret | Contenu |
|---|---|
| `SITES` | une ligne par site : `Nom\|https://adresse` |
| `CALLMEBOT_PHONE` / `CALLMEBOT_APIKEY` | numéro WhatsApp international et clé CallMeBot |
| `AUDIT_URL` / `AUDIT_TOKEN` | adresse du rapport de sécurité du serveur et jeton d'accès |
| `GSC_SERVICE_ACCOUNT_JSON` | clé JSON (une ligne) d'un compte de service ajouté en lecture aux propriétés Search Console |

Aucune adresse ni aucun secret n'apparaît dans le code, les journaux ou `state.json`.

## Tester

Modifier `TEST_WHATSAPP` (message de test) ou `TEST_WEEKLY` (bilan immédiat), ou Actions → Run workflow.
