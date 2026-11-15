"""Bilan hebdomadaire envoyé sur WhatsApp chaque lundi matin (GitHub Actions, .github/workflows/weekly.yml).

Contenu : contrôles SEO techniques de chaque site, chiffres Google Search Console (7 jours vs 7 précédents),
versions de Next.js / React du serveur comparées à la dernière version stable, état de sécurité du serveur.
Aucune IA, aucun secret ni adresse de site dans les journaux (le dépôt est public).

Secrets : SITES, CALLMEBOT_PHONE, CALLMEBOT_APIKEY, AUDIT_URL, AUDIT_TOKEN, GSC_SERVICE_ACCOUNT_JSON (facultatif).
"""

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, timedelta
from html.parser import HTMLParser

import audit_rules
from monitor import USER_AGENT, fetch_security_report, now, parse_sites, send_whatsapp

TIMEOUT = 20
SITEMAP_NS = "http://www.sitemaps.org/schemas/sitemap/0.9"
MAX_PAGES = 15


def get(url, headers=None, follow=True):
    """Retourne (code, en-têtes, corps, url_finale, secondes)."""
    h = {"User-Agent": USER_AGENT, **(headers or {})}
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(NoRedirect)
    t0 = now()
    try:
        with opener.open(urllib.request.Request(url, headers=h), timeout=TIMEOUT) as r:
            body = r.read().decode("utf-8", "replace")
            return r.status, dict(r.headers), body, r.geturl(), (now() - t0).total_seconds()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), "", url, (now() - t0).total_seconds()
    except Exception:  # noqa: BLE001
        return 0, {}, "", url, (now() - t0).total_seconds()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.h1 = 0
        self.title = ""
        self._in_title = False
        self.meta = {}
        self.canonical = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "h1":
            self.h1 += 1
        elif tag == "title":
            self._in_title = True
        elif tag == "meta":
            k = a.get("name") or a.get("property")
            if k and "content" in a:
                self.meta.setdefault(k.lower(), a["content"])
        elif tag == "link" and (a.get("rel") or "").lower() == "canonical":
            self.canonical = a.get("href")

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title and not self.title:
            self.title = data.strip()


def norm(u):
    return (u or "").rstrip("/")


def seo_site(name, url):
    """Liste des problèmes SEO d'un site (gravité, texte), et temps de réponse de l'accueil."""
    issues = []
    host = urllib.parse.urlparse(url).hostname
    code, _, body, final, secs = get(url)
    if code != 200:
        return [("critique", f"accueil en erreur ({code or 'injoignable'})")], secs
    if secs > 1.5:
        issues.append(("attention", f"accueil lent ({secs:.1f} s)"))
    if not host.startswith("www.") and host.count(".") == 1:
        c, h, *_ = get(f"https://www.{host}/", follow=False)
        if c not in (301, 308) or norm(h.get("Location")) != norm(f"https://{host}"):
            issues.append(("attention", f"www. ne redirige pas en 301 vers le domaine ({c})"))
    c, _, robots, *_ = get(f"https://{host}/robots.txt")
    if c != 200:
        issues.append(("attention", "robots.txt absent"))
    elif re.search(r"(?im)^disallow:\s*/_next", robots):
        issues.append(("attention", "robots.txt bloque /_next (CSS/JS)"))
    c, _, sm, *_ = get(f"https://{host}/sitemap.xml")
    pages = [url]
    if c != 200:
        issues.append(("attention", "sitemap.xml absent"))
    else:
        if f'xmlns="{SITEMAP_NS}"' not in sm:
            issues.append(("critique", "sitemap.xml : namespace invalide (refusé par Google)"))
        locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", sm)
        pages = [u for u in locs if not re.search(r"\.(pdf|jpe?g|png|webp|gif|mp4|zip)$", u, re.I)][:MAX_PAGES] or [url]
    titles = {}
    for p in pages:
        c, _, html, *_ = get(p)
        path = urllib.parse.urlparse(p).path or "/"
        if c != 200:
            issues.append(("critique", f"{path} en erreur ({c or 'injoignable'})"))
            continue
        t = Tags()
        try:
            t.feed(html)
        except Exception:  # noqa: BLE001
            pass
        if t.h1 != 1:
            issues.append(("attention", f"{path} : {t.h1} titre(s) h1"))
        if not (20 <= len(t.title) <= 70):
            issues.append(("attention", f"{path} : titre de {len(t.title)} caractères"))
        titles.setdefault(t.title, []).append(path)
        d = t.meta.get("description", "")
        if not (50 <= len(d) <= 170):
            issues.append(("attention", f"{path} : description de {len(d)} caractères"))
        if norm(t.canonical) != norm(p):
            issues.append(("attention", f"{path} : canonical incorrect"))
        if not t.meta.get("og:image"):
            issues.append(("attention", f"{path} : pas d'image de partage"))
    for title, paths in titles.items():
        if len(paths) > 1:
            issues.append(("attention", f"titre identique sur {len(paths)} pages"))
    return issues, secs


def gsc_token():
    raw = os.environ.get("GSC_SERVICE_ACCOUNT_JSON", "").strip()
    if not raw:
        return None
    from google.auth.transport.requests import Request
    from google.oauth2 import service_account

    creds = service_account.Credentials.from_service_account_info(
        json.loads(raw), scopes=["https://www.googleapis.com/auth/webmasters.readonly"])
    creds.refresh(Request())
    return creds.token


def gsc_call(token, path, payload=None):
    url = "https://searchconsole.googleapis.com/webmasters/v3/" + path
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET",
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def gsc_site(token, url):
    host = urllib.parse.urlparse(url).hostname
    end = date.today() - timedelta(days=3)  # données Search Console disponibles avec ~3 jours de retard
    periods = [(end - timedelta(days=6), end), (end - timedelta(days=13), end - timedelta(days=7))]
    for prop in (f"https://{host}/", f"sc-domain:{host}"):
        p = urllib.parse.quote(prop, safe="")
        try:
            tot = []
            for a, b in periods:
                r = gsc_call(token, f"sites/{p}/searchAnalytics/query",
                             {"startDate": a.isoformat(), "endDate": b.isoformat()})
                row = (r.get("rows") or [{}])[0]
                tot.append((int(row.get("clicks", 0)), int(row.get("impressions", 0))))
            errs = sum(int(s.get("errors", 0) or 0) for s in gsc_call(token, f"sites/{p}/sitemaps").get("sitemap", []))
            return {"clicks": tot[0][0], "clicks_prev": tot[1][0], "impr": tot[0][1], "impr_prev": tot[1][1],
                    "sitemap_errors": errs}
        except urllib.error.HTTPError as e:
            if e.code in (403, 404):
                continue
            return {"error": f"HTTP {e.code}"}
        except Exception as e:  # noqa: BLE001
            return {"error": type(e).__name__}
    return {"error": "accès refusé (compte de service non ajouté à la propriété ?)"}


def latest(pkg):
    _, _, body, *_ = get(f"https://registry.npmjs.org/{pkg}/latest")
    try:
        return json.loads(body)["version"]
    except Exception:  # noqa: BLE001
        return None


def delta(cur, prev):
    if not prev:
        return "" if not cur else " (nouveau)"
    pct = round((cur - prev) * 100 / prev)
    return f" ({'+' if pct >= 0 else ''}{pct} %)"


def main():
    sites = parse_sites(os.environ.get("SITES", ""))
    t = now()
    crit, warn, lines = [], [], []

    # Sécurité du serveur
    report, err = fetch_security_report()
    if err:
        crit.append(f"Serveur : {err}")
    elif report:
        for _, level, msg in audit_rules.evaluate(report, t):
            (crit if level == "critique" else warn).append(f"Serveur : {msg}")
        nxt, rct = latest("next"), latest("react")
        for app, info in (report.get("apps") or {}).items():
            if nxt and info.get("next") and info["next"] != nxt:
                warn.append(f"{app} : Next.js {info['next']} (dernière : {nxt})")
            if rct and info.get("react") and info["react"] != rct:
                warn.append(f"{app} : React {info['react']} (dernière : {rct})")

    # Search Console : détermine aussi les sites concernés par le SEO (ceux suivis dans la Search Console)
    gsc_lines = []
    seo_sites = sites
    try:
        token = gsc_token()
    except Exception as e:  # noqa: BLE001
        token = None
        gsc_lines.append(f"indisponible ({type(e).__name__} : clé GSC_SERVICE_ACCOUNT_JSON illisible ?)")
    if token:
        seo_sites = []
        for name, url in sites:
            g = gsc_site(token, url)
            if "error" in g:
                print("Search Console : un site non suivi ou inaccessible")
                continue  # site absent de la Search Console (application, page d'attente, autre compte)
            seo_sites.append((name, url))
            gsc_lines.append(f"{name} : {g['clicks']} clics{delta(g['clicks'], g['clicks_prev'])}, "
                             f"{g['impr']} impressions{delta(g['impr'], g['impr_prev'])}")
            if g["sitemap_errors"]:
                warn.append(f"{name} : {g['sitemap_errors']} erreur(s) de sitemap dans Search Console")
        if not seo_sites:
            gsc_lines.append("aucun site accessible : le compte de service a-t-il été ajouté aux propriétés ?")
            seo_sites = sites
    elif not gsc_lines:
        gsc_lines.append("non configurée (secret GSC_SERVICE_ACCOUNT_JSON absent)")

    # SEO
    for name, url in seo_sites:
        issues, _ = seo_site(name, url)
        c = [i for lvl, i in issues if lvl == "critique"]
        w = [i for lvl, i in issues if lvl == "attention"]
        crit += [f"{name} : {i}" for i in c]
        if w:
            warn.append(f"{name} : {len(w)} point(s) SEO, ex. {w[0]}")
        print(f"SEO site : {len(c)} critique(s), {len(w)} attention(s)")

    head = "🚨 SÉCURITÉ" if crit else ("⚠️ À voir" if warn else "✅ Tout va bien")
    lines.append(f"{head} — bilan hebdo des sites ({t.astimezone(__import__('monitor').TZ).strftime('%d/%m')})")
    lines += [f"🚨 {c}" for c in crit[:6]]
    lines += [f"⚠️ {w}" for w in warn[:8]]
    if len(crit[:6]) + len(warn[:8]) < len(crit) + len(warn):
        lines.append(f"… et {len(crit) + len(warn) - len(crit[:6]) - len(warn[:8])} autre(s) point(s).")
    lines.append("📊 Search Console (7 j) :")
    lines += [f"• {g}" for g in gsc_lines]
    if not crit and not warn:
        lines.insert(1, f"Sécurité OK, {len(sites)} sites en ligne, SEO conforme.")
    text = "\n".join(lines)
    print(f"Bilan : {len(crit)} critique(s), {len(warn)} attention(s), {len(text)} caractères.")
    send_whatsapp(text)  # découpé automatiquement en plusieurs messages si besoin


if __name__ == "__main__":
    main()
