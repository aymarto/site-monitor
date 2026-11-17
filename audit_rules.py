"""Règles d'anomalie appliquées au rapport de sécurité du serveur.

Utilisé à deux endroits :
  - sur le serveur (/usr/local/sbin/security-alert) : alerte WhatsApp dans les 30 minutes ;
  - sur GitHub Actions (monitor.py, weekly.py) : contrôle extérieur, au cas où le serveur se tairait.
Chaque anomalie a un identifiant stable (pour n'alerter qu'une fois) et une gravité : "critique" ou "attention".
"""

import re
from datetime import datetime, timezone

EXPECTED = {
    "login_users": {"root", "ubuntu", "mary"},
    # Seul compte autorisé à se connecter par mot de passe (sans droits administrateur)
    "password_users": {"mary"},
    # Personne dans les groupes sudo/admin : ubuntu passe par /etc/sudoers.d (clé SSH uniquement)
    "admin_group_members": set(),
    "crontabs": {"ubuntu"},
    "cron_d": {"certbot", "e2scrub_all"},
    "sudoers_d": {"90-cloud-init-users", "README"},
    "ubuntu_keys": {"claude-stage-qc-admin"},
    "public_ports": {"22", "80", "443"},
}
PROTECTIONS = ("nginx", "appjail", "fail2ban", "unattended-upgrades", "ssh")
APPJAIL_BASELINE = 29     # paquets bloqués lors des tests de mise en place (15/11/2026)
STALE_MINUTES = 90


def evaluate(report, now=None):
    """Retourne une liste de (id, gravité, message)."""
    now = now or datetime.now(timezone.utc)
    out = []

    def add(key, level, msg):
        out.append((key, level, msg))

    try:
        gen = datetime.strptime(report["generated_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        age = (now - gen).total_seconds() / 60
        if age > STALE_MINUTES:
            add("stale", "critique", f"Rapport de sécurité vieux de {int(age)} min : le contrôle du serveur ne tourne plus.")
    except Exception:  # noqa: BLE001
        add("stale", "critique", "Rapport de sécurité illisible.")

    for name, app in (report.get("apps") or {}).items():
        if app.get("service_active") != "active":
            add(f"app-down:{name}", "critique", f"Le service du site « {name} » est arrêté.")

    for s in PROTECTIONS:
        st = (report.get("services") or {}).get(s)
        if st != "active":
            add(f"prot-down:{s}", "critique", f"Protection « {s} » inactive ({st}).")
    if not str(report.get("ufw", "")).lower().endswith("active"):
        add("ufw-off", "critique", "Le pare-feu (ufw) est désactivé.")
    if not report.get("appjail_rules_present"):
        add("appjail-rules", "critique", "Les règles de la prison réseau ont disparu.")

    ssh = report.get("ssh") or {}
    if ssh.get("passwordauthentication") != "no":
        add("ssh-password", "critique", "La connexion SSH par mot de passe a été réactivée.")
    if ssh.get("permitrootlogin") != "no":
        add("ssh-root", "critique", "La connexion SSH en root a été réautorisée.")
    for user, val in (report.get("ssh_password_per_user") or {}).items():
        if val == "yes" and user not in EXPECTED["password_users"]:
            add(f"ssh-password-user:{user}", "critique", f"Connexion par mot de passe autorisée pour le compte « {user} ».")
    for member in sorted(set(report.get("admin_group_members") or []) - EXPECTED["admin_group_members"]):
        add(f"admin-group:{member}", "critique", f"Le compte « {member} » a été ajouté aux administrateurs (sudo).")

    for f in report.get("exec_files_in_tmp") or []:
        add(f"tmp-exec:{f}", "critique", f"Fichier exécutable suspect : {f}")
    for f in report.get("hidden_dirs_in_tmp") or []:
        add(f"tmp-hidden:{f}", "critique", f"Dossier caché suspect : {f}")

    for field in ("crontabs", "cron_d", "sudoers_d", "login_users"):
        extra = set(report.get(field) or []) - EXPECTED[field]
        for e in sorted(extra):
            add(f"{field}:{e}", "critique", f"Élément inattendu ({field}) : {e}")

    keys = report.get("authorized_keys") or {}
    for home, comments in keys.items():
        allowed = EXPECTED["ubuntu_keys"] if home == "/home/ubuntu" else set()
        for c in sorted(set(comments) - allowed):
            add(f"sshkey:{home}:{c}", "critique", f"Clé SSH inconnue sur {home} : {c}")

    for line in report.get("ssh_logins_7d") or []:
        m = re.search(r"Accepted (password|keyboard-interactive\S*) for (\S+)", line)
        if m and m.group(2) not in EXPECTED["password_users"]:
            add(f"ssh-login-password:{m.group(2)}", "critique", f"Connexion SSH par mot de passe : {line.strip()}")

    for line in report.get("listening_ports") or []:
        try:
            proto, addr = line.split()
        except ValueError:
            continue
        host, _, port = addr.rpartition(":")
        if host.startswith(("0.0.0.0", "[::]", "*")) and proto == "tcp" and port not in EXPECTED["public_ports"]:
            add(f"port:{proto}:{port}", "critique", f"Port ouvert inattendu sur Internet : {proto} {port}")

    for s in report.get("outbound_udp_sockets") or []:
        add(f"udp:{s[:60]}", "critique", f"Connexion UDP sortante inattendue : {s[:120]}")

    blocked = report.get("appjail_blocked_packets")
    if isinstance(blocked, int) and blocked > APPJAIL_BASELINE + 20:
        add("appjail-blocked", "critique",
            f"La prison réseau a bloqué {blocked - APPJAIL_BASELINE} tentatives de trafic interdit "
            "depuis un site : signe possible de piratage.")

    if (report.get("upgradable_security") or 0) > 0:
        add("updates", "attention", f"{report['upgradable_security']} mise(s) à jour de sécurité en attente.")
    if report.get("reboot_required"):
        add("reboot", "attention", "Redémarrage du serveur requis pour finir une mise à jour.")
    try:
        if int(str(report.get("disk_root_used_pct", "0")).strip().rstrip("%")) > 85:
            add("disk", "attention", f"Disque presque plein ({report['disk_root_used_pct']}).")
    except ValueError:
        pass
    return out
