"""Surveillance de sites web avec alertes WhatsApp (CallMeBot).

Lancé toutes les 5 minutes par GitHub Actions (.github/workflows/monitor.yml).

Secrets attendus (variables d'environnement) :
  SITES             une ligne par site : "Nom|https://adresse"  (ou juste l'URL)
  CALLMEBOT_PHONE   ton numéro au format international, ex. +33612345678
  CALLMEBOT_APIKEY  la clé reçue de CallMeBot

Le dépôt est public : ce script n'écrit JAMAIS les adresses des sites dans les
journaux ni dans state.json (les sites y sont identifiés par une empreinte).
"""

import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

STATE_FILE = "state.json"
TIMEOUT = 15            # secondes par requête
RETRY_DELAY = 20        # second essai avant de déclarer une panne
REMINDER_MINUTES = 60   # rappel tant que la panne dure
TZ = ZoneInfo("Europe/Paris")
USER_AGENT = "site-monitor/1.0 (+uptime check)"


def now():
    return datetime.now(timezone.utc)


def fmt(dt):
    return dt.astimezone(TZ).strftime("%d/%m à %H:%M")


def key(url):
    return hashlib.sha256(url.encode()).hexdigest()[:12]


def parse_sites(raw):
    sites = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, url = line.partition("|") if "|" in line else (None, "", line)
        url = url.strip()
        name = (name or urllib.parse.urlparse(url).hostname or url).strip()
        sites.append((name, url))
    return sites


def check(url):
    """Retourne (ok, détail)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            code = resp.status
            return (code < 400, f"HTTP {code}")
    except urllib.error.HTTPError as e:
        return (e.code < 400, f"HTTP {e.code}")
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", e)
        return (False, f"inaccessible ({type(reason).__name__}: {reason})"[:120])
    except Exception as e:  # timeout, SSL, reset...
        return (False, f"inaccessible ({type(e).__name__})")


def check_with_retry(url):
    ok, detail = check(url)
    if not ok:
        time.sleep(RETRY_DELAY)
        ok, detail = check(url)
    return ok, detail


MAX_CHUNK = 700  # CallMeBot tronque les messages trop longs : on découpe par lignes


def chunks(text):
    parts, cur = [], ""
    for line in text.split("\n"):
        line = line[:MAX_CHUNK]
        if cur and len(cur) + len(line) + 1 > MAX_CHUNK:
            parts.append(cur)
            cur = line
        else:
            cur = f"{cur}\n{line}" if cur else line
    if cur:
        parts.append(cur)
    if len(parts) > 1:
        parts = [f"({i}/{len(parts)}) {p}" for i, p in enumerate(parts, 1)]
    return parts


def send_one(text, phone, apikey):
    qs = urllib.parse.urlencode({"phone": phone, "text": text, "apikey": apikey})
    req = urllib.request.Request(
        f"https://api.callmebot.com/whatsapp.php?{qs}", headers={"User-Agent": USER_AGENT}
    )
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read().decode("utf-8", "replace").lower()
                if resp.status == 200 and "invalid" not in body and "error" not in body:
                    return True
                # Réponse explicite de CallMeBot (clé invalide, etc.) : réessayer ne servirait à rien
                print(f"CallMeBot a refusé le message (HTTP {resp.status}).")
                return False
        except Exception as e:  # réseau, délai, erreur serveur : on réessaie
            print(f"Échec d'envoi WhatsApp ({type(e).__name__}), essai {attempt + 1}/3.")
        time.sleep(10)
    return False


def send_whatsapp(text):
    phone = os.environ.get("CALLMEBOT_PHONE", "").strip()
    apikey = os.environ.get("CALLMEBOT_APIKEY", "").strip()
    if not phone or not apikey:
        print("CallMeBot non configuré : message non envoyé.")
        return False
    ok = True
    for i, part in enumerate(chunks(text)):
        if i:
            time.sleep(8)  # CallMeBot limite le débit : on espace les envois
        ok = send_one(part, phone, apikey) and ok
    print("Message WhatsApp envoyé." if ok else "Au moins une partie du message n'a pas été envoyée.")
    return ok


def load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"sites": {}}


def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)
        f.write("\n")


def minutes_between(a, b):
    return int((b - a).total_seconds() // 60)


def fetch_security_report():
    """Rapport JSON du serveur (secrets AUDIT_URL + AUDIT_TOKEN). Retourne (rapport, erreur)."""
    def clean(name):
        # Tolère un collage maladroit : espaces, guillemets ou « NOM= » devant la valeur
        v = os.environ.get(name, "").strip().strip('"').strip("'").strip()
        return v.split("=", 1)[1].strip() if v.upper().startswith(name + "=") else v

    url, token = clean("AUDIT_URL"), clean("AUDIT_TOKEN")
    if not url or not token:
        return None, None
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "X-Audit-Token": token})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8")), None
    except urllib.error.HTTPError as e:
        hint = " : jeton AUDIT_TOKEN ou adresse AUDIT_URL incorrects" if e.code == 404 else ""
        return None, f"rapport de sécurité inaccessible (HTTP {e.code}{hint})"
    except Exception as e:  # noqa: BLE001
        return None, f"rapport de sécurité inaccessible ({type(e).__name__})"


def check_security(state, t):
    """Alerte sur les anomalies critiques du rapport serveur : à l'apparition, rappel toutes les 12 h, à la résolution."""
    import audit_rules

    report, err = fetch_security_report()
    if report is None and err is None:
        return []  # contrôle non configuré
    found = {}
    if err:
        found["unreachable"] = err.capitalize() + " : le serveur ne publie plus son contrôle."
    else:
        for k, level, msg in audit_rules.evaluate(report, t):
            if level == "critique":
                found[key(k)] = msg  # identifiant haché : rien de lisible dans state.json (dépôt public)
    sec = state.setdefault("security", {})
    new = [k for k in found if k not in sec]
    remind = [k for k in found if k in sec and minutes_between(datetime.fromisoformat(sec[k]), t) >= 720]
    resolved = [k for k in sec if k not in found]
    for k in new + remind:
        sec[k] = t.isoformat()
    for k in resolved:
        del sec[k]
    print(f"sécurité : {len(found)} anomalie(s) critique(s), {len(new)} nouvelle(s), {len(resolved)} résolue(s)")
    out = []
    if new or remind:
        out.append(f"🚨 ALERTE SÉCURITÉ SERVEUR ({fmt(t)}) — contrôle extérieur")
        out += [f"• {found[k]}" for k in new]
        out += [f"• (toujours actif) {found[k]}" for k in remind]
        out.append("Réagis vite : demande à Claude d'analyser le serveur.")
    if resolved:
        out.append(f"✅ {len(resolved)} anomalie(s) de sécurité résolue(s) sur le serveur.")
    return out


def main():
    sites = parse_sites(os.environ.get("SITES", ""))
    mode = os.environ.get("MODE", "check")

    if mode == "test":
        ok = send_whatsapp(
            f"✅ Test de la surveillance des sites ({len(sites)} site(s) suivis). "
            "Si tu lis ce message, les alertes WhatsApp fonctionnent."
        )
        sys.exit(0 if ok else 1)

    if not sites:
        print("Aucun site configuré (secret SITES vide).")
        sys.exit(1)

    state = load_state()
    state.setdefault("sites", {})
    t = now()
    down_msgs, up_msgs, reminder_msgs = [], [], []
    down_names = []

    for i, (name, url) in enumerate(sites, 1):
        k = key(url)
        s = state["sites"].setdefault(k, {"down_since": None, "last_alert": None})
        ok, detail = check_with_retry(url)
        print(f"site {i}/{len(sites)} [{k}] : {'OK' if ok else 'EN PANNE'}")

        if ok:
            if s["down_since"]:
                since = datetime.fromisoformat(s["down_since"])
                up_msgs.append(f"✅ {name} est rétabli (panne de {minutes_between(since, t)} min).")
            s.update(down_since=None, last_alert=None)
            continue

        down_names.append(name)
        if not s["down_since"]:
            s["down_since"] = t.isoformat()
            s["last_alert"] = t.isoformat()
            down_msgs.append(f"🔴 {name} ne répond plus : {detail}\n{url}")
        else:
            last = datetime.fromisoformat(s["last_alert"] or s["down_since"])
            if minutes_between(last, t) >= REMINDER_MINUTES:
                since = datetime.fromisoformat(s["down_since"])
                s["last_alert"] = t.isoformat()
                reminder_msgs.append(
                    f"⏰ {name} toujours en panne depuis {fmt(since)} "
                    f"({minutes_between(since, t)} min) : {detail}"
                )

    # Oublie les sites retirés de la liste
    current = {key(url) for _, url in sites}
    for k in list(state["sites"]):
        if k not in current:
            del state["sites"][k]

    parts = []
    if down_msgs or reminder_msgs:
        head = "🚨 PANNE DÉTECTÉE" if down_msgs else "🚨 PANNE EN COURS"
        parts.append(f"{head} ({fmt(t)})")
        if len(down_names) >= 2 and len(down_names) == len(sites):
            parts.append("Tous les sites sont hors ligne : le serveur est probablement arrêté "
                         "(vérifier le VPS dans l'espace OVH).")
        elif len(down_names) >= 2:
            parts.append(f"{len(down_names)} sites en panne en même temps : vérifier le serveur.")
        parts += down_msgs + reminder_msgs
        parts.append("Réagis au plus vite.")
    if up_msgs:
        if parts:
            parts.append("")
        parts.append(f"Rétablissement ({fmt(t)}) :")
        parts += up_msgs

    # Contrôle extérieur du rapport de sécurité du serveur (si le serveur entier n'est pas déjà signalé en panne)
    if len(down_names) < len(sites):
        sec = check_security(state, t)
        if sec:
            if parts:
                parts.append("")
            parts += sec

    if parts:
        send_whatsapp("\n".join(parts))

    save_state(state)
    print(f"Terminé : {len(sites) - len(down_names)} en ligne, {len(down_names)} en panne.")


if __name__ == "__main__":
    main()
