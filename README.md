# site-monitor

Vérifie des sites web toutes les 5 minutes (GitHub Actions) et envoie une alerte WhatsApp
(via [CallMeBot](https://www.callmebot.com/blog/free-api-whatsapp-messages/)) en cas de panne,
un rappel toutes les heures tant qu'elle dure, puis un message quand le site est rétabli.
Un message de contrôle « surveillance active » part chaque lundi matin.

## Secrets (Settings → Secrets and variables → Actions)

| Secret | Contenu |
|---|---|
| `SITES` | une ligne par site : `Nom\|https://adresse` |
| `CALLMEBOT_PHONE` | numéro au format international, ex. `+33612345678` |
| `CALLMEBOT_APIKEY` | clé envoyée par CallMeBot |

La liste des sites n'apparaît ni dans le code, ni dans les journaux, ni dans `state.json`.

## Tester

Actions → « Surveillance des sites » → Run workflow → mode `test` : envoie un message WhatsApp de test.
