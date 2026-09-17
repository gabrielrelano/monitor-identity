#!/usr/bin/env python3
"""
Monitor de disponibilidad para TeamSystem Identity.

Comprueba, para cada entorno:
  1. Disponibilidad HTTP (codigo 200 y contenido esperado)
  2. Tiempo de respuesta (umbrales de warning / critical)
  3. Caducidad del certificado SSL (dias restantes)
  4. Salud funcional del login (pagina de login + descubrimiento OIDC,
     y opcionalmente un login real con credenciales de prueba)

Envia alertas a un canal de Microsoft Teams mediante webhook.
Solo avisa cuando cambia el estado (OK -> FALLO o FALLO -> OK), para no
inundar el canal, con un recordatorio periodico si el fallo persiste.

Sin dependencias externas: solo libreria estandar de Python 3.8+.

Uso:
    export TEAMS_WEBHOOK_URL="https://prod-XX.westeurope.logic.azure.com/..."
    python3 monitor_identity.py
    python3 monitor_identity.py --dry-run     # no envia nada, imprime por consola
    python3 monitor_identity.py --test-alert  # envia una alerta de prueba a Teams
"""

import argparse
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# CONFIGURACION
# ---------------------------------------------------------------------------

TARGETS = [
    {
        "name": "Identity PROD",
        "url": "https://identity.teamsystem.com/",
        "critical": True,           # un fallo aqui se marca como incidencia grave
        "expect_text": ["tsid_logo", "Email"],   # marcadores que deben aparecer en el HTML
        "oidc_discovery": "https://identity.teamsystem.com/.well-known/openid-configuration",
        # Endpoint que sirve los avisos/banner si se pintan por JS. Ponlo aqui
        # cuando lo identifiques en las DevTools (pestana Network, filtro XHR).
        "banner_api": None,
    },
    {
        "name": "Identity STAGE",
        "url": "https://identity-stage.teamsystem.com/",
        "critical": False,
        "expect_text": ["tsid_logo", "Email"],
        "oidc_discovery": "https://identity-stage.teamsystem.com/.well-known/openid-configuration",
        "banner_api": None,
    },
    # --- Paneles de identidad (Espana) ---------------------------------
    # OJO: no se han podido verificar desde fuera. Si alguno solo es
    # accesible desde la red interna o por VPN, el monitor lo dara por
    # caido siempre, porque GitHub ejecuta desde internet publico. En ese
    # caso, borra ese destino de la lista.
    {
        "name": "Identity Panel PROD (ES)",
        "url": "https://identity-panel.teamsystem.es/",
        "critical": True,
        # Sin marcadores de contenido: no sabemos aun que sirve esta pagina.
        # Cuando veas su HTML, pon aqui una palabra que siempre aparezca
        # (un titulo, el nombre de un boton) para detectar paginas en blanco.
        "expect_text": [],
        "oidc_discovery": None,
        "banner_api": None,
    },
    {
        "name": "Identity Panel TEST (ES)",
        "url": "https://identity-panel-test.teamsystem.es/",
        "critical": False,
        "expect_text": [],
        "oidc_discovery": None,
        "banner_api": None,
    },
]

# --- Deteccion de avisos de mantenimiento / tareas programadas -------------
# Palabras que delatan un aviso en la pagina. En minusculas y sin acentos:
# la comparacion normaliza el texto antes de buscar.
MAINTENANCE_KEYWORDS = [
    "manutenzione", "manutenzione programmata", "attivita pianificate",
    "mantenimiento", "tareas programadas", "tarea programada",
    "tareas de mantenimiento", "estimado cliente",
    "scheduled maintenance", "planned maintenance", "maintenance window",
    "servizio non disponibile", "temporaneamente non disponibile",
    "servicio no disponible", "temporalmente no disponible",
    "podria no estar disponible", "potrebbe non essere disponibile",
    "wartungsarbeiten", "manutencao programada", "maintenance planifiee",
]

# Si hay aviso de mantenimiento activo, no escalar los fallos a incidencia
# grave: se notifican igual, pero etiquetados como esperados.
MAINTENANCE_DOWNGRADE = True

# El banner de avisos se inyecta por JavaScript (no hay llamada XHR: se ha
# verificado en DevTools), asi que no aparece en el HTML del servidor.
# Por eso hay tres vias, de mas fiable a menos:
#
#   1. VENTANAS DECLARADAS: las apuntas a mano aqui en cuanto te llega el
#      aviso de mantenimiento. Es lo unico 100% fiable.
#   2. ESCANEO DE SCRIPTS: busca el texto del aviso dentro de los .js del
#      propio dominio, que es donde suele vivir si lo inyecta el front.
#   3. RENDERIZADO REAL: con Playwright instalado y RENDER_JS=1, carga la
#      pagina con un navegador y lee el banner tal cual lo ve el usuario.
#
# Formato de ventana: (inicio, fin) en hora UTC, ISO 8601.
# La ventana anunciada el 17/09/2026: viernes 18/09/2026 23:00-24:00 CEST.
MAINTENANCE_WINDOWS = [
    {
        "desde": "2026-09-18T21:00:00+00:00",   # 23:00 CEST
        "hasta": "2026-09-18T22:00:00+00:00",   # 24:00 CEST
        "descripcion": "Mantenimiento programado de acceso a TeamSystem ID (anunciado en la web)",
        # Lista vacia = afecta a todos los destinos. Los paneles dependen del
        # servicio de acceso, asi que tambien se ven afectados.
        "targets": [],
        # Margen de cortesia antes y despues, en minutos: los mantenimientos
        # rara vez empiezan y acaban al minuto exacto.
        "margen_min": 15,
    },
]

# Escaneo de los .js del propio dominio en busca del texto del aviso
SCAN_SCRIPTS = True
MAX_SCRIPTS = 12              # cuantos ficheros .js revisar como maximo
MAX_SCRIPT_BYTES = 2_000_000  # ignorar bundles mas grandes que esto

# Renderizado con navegador real (opcional, requiere: pip install playwright)
RENDER_JS = os.environ.get("RENDER_JS", "0") == "1"

# Umbrales
RESPONSE_WARN_MS = 1500      # aviso si tarda mas de esto
RESPONSE_CRIT_MS = 4000      # fallo si tarda mas de esto
SSL_WARN_DAYS = 21           # aviso si al certificado le quedan menos dias
SSL_CRIT_DAYS = 7            # fallo si le quedan menos dias
HTTP_TIMEOUT = 15            # segundos
RETRIES = 2                  # reintentos antes de dar por caido (evita falsos positivos)
RETRY_DELAY = 5              # segundos entre reintentos

# Recordatorio si el fallo sigue abierto (minutos). 0 = sin recordatorios.
REMINDER_MINUTES = 60

# Fichero de estado para detectar cambios entre ejecuciones
STATE_FILE = os.environ.get(
    "MONITOR_STATE_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), ".identity_monitor_state.json"),
)

# --- Canales de notificacion ----------------------------------------------
# Telegram (recomendado: llega al movil al instante)
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

# Webhook de Teams (opcional, se puede usar a la vez que Telegram)
TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "")
# "adaptive" para webhooks de Power Automate (recomendado), "messagecard" para el conector clasico
TEAMS_PAYLOAD_FORMAT = os.environ.get("TEAMS_PAYLOAD_FORMAT", "adaptive")

USER_AGENT = "TS-Identity-Monitor/1.0 (+monitorizacion interna)"

# ---------------------------------------------------------------------------
# UTILIDADES
# ---------------------------------------------------------------------------


def now_utc():
    return datetime.now(timezone.utc)


def log(msg):
    print(f"[{now_utc().strftime('%Y-%m-%d %H:%M:%S')}Z] {msg}", flush=True)


def normalizar(texto):
    """Minusculas, sin acentos y sin espacios repetidos, para buscar palabras clave."""
    import unicodedata
    texto = unicodedata.normalize("NFKD", texto)
    texto = "".join(c for c in texto if not unicodedata.combining(c))
    return " ".join(texto.lower().split())


def html_a_texto(html):
    """Extrae el texto visible: quita script, style y etiquetas."""
    import re
    html = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", html)
    html = re.sub(r"(?s)<[^>]+>", " ", html)
    html = html.replace("&nbsp;", " ").replace("&amp;", "&")
    return " ".join(html.split())


def http_get(url, timeout=HTTP_TIMEOUT, opener=None, headers=None):
    """Devuelve (status, body, elapsed_ms). Lanza excepcion si no conecta."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    start = time.perf_counter()
    try:
        fn = opener.open if opener else urllib.request.urlopen
        with fn(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            elapsed = (time.perf_counter() - start) * 1000
            return resp.getcode(), body, elapsed
    except urllib.error.HTTPError as e:
        elapsed = (time.perf_counter() - start) * 1000
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body, elapsed


# ---------------------------------------------------------------------------
# COMPROBACIONES
# ---------------------------------------------------------------------------


def check_http(target):
    """Disponibilidad + contenido + tiempo de respuesta."""
    last_error = None
    for intento in range(1, RETRIES + 2):
        try:
            status, body, elapsed = http_get(target["url"])
            if status != 200:
                last_error = f"HTTP {status}"
                if intento <= RETRIES:
                    time.sleep(RETRY_DELAY)
                    continue
                return fail("http", f"Respuesta HTTP {status}", elapsed)

            faltan = [m for m in target.get("expect_text", []) if m not in body]
            if faltan:
                return fail("http", f"Responde 200 pero falta contenido esperado: {', '.join(faltan)}", elapsed)

            if elapsed > RESPONSE_CRIT_MS:
                r = fail("latency", f"Tiempo de respuesta {elapsed:.0f} ms (limite {RESPONSE_CRIT_MS} ms)", elapsed)
            elif elapsed > RESPONSE_WARN_MS:
                r = warn("latency", f"Lento: {elapsed:.0f} ms (aviso a partir de {RESPONSE_WARN_MS} ms)", elapsed)
            else:
                r = ok("http", f"200 OK en {elapsed:.0f} ms", elapsed)
            r["body"] = body      # se reutiliza para buscar avisos de mantenimiento
            return r

        except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as e:
            last_error = f"{type(e).__name__}: {e}"
            if intento <= RETRIES:
                time.sleep(RETRY_DELAY)
                continue
    return fail("http", f"No responde tras {RETRIES + 1} intentos ({last_error})")


def ventana_activa(nombre_target, momento=None):
    """Devuelve la ventana de mantenimiento declarada que este activa ahora, o None."""
    momento = momento or now_utc()
    for v in MAINTENANCE_WINDOWS:
        objetivos = v.get("targets") or []
        if objetivos and nombre_target not in objetivos:
            continue
        try:
            desde = datetime.fromisoformat(v["desde"])
            hasta = datetime.fromisoformat(v["hasta"])
        except (ValueError, KeyError):
            continue
        margen = timedelta(minutes=v.get("margen_min", 0))
        if (desde - margen) <= momento <= (hasta + margen):
            return v
    return None


def ventana_proxima(nombre_target, horas=48):
    """Ventana declarada que empieza dentro de las proximas N horas."""
    ahora = now_utc()
    for v in MAINTENANCE_WINDOWS:
        objetivos = v.get("targets") or []
        if objetivos and nombre_target not in objetivos:
            continue
        try:
            desde = datetime.fromisoformat(v["desde"])
        except (ValueError, KeyError):
            continue
        if ahora < desde <= ahora + timedelta(hours=horas):
            return v, desde
    return None, None


def scripts_del_dominio(html, base_url):
    """URLs de los <script src> servidos desde el mismo dominio."""
    import re
    base = urllib.parse.urlparse(base_url)
    urls = []
    for src in re.findall(r'(?is)<script[^>]+src=["\']([^"\']+)["\']', html):
        absoluta = urllib.parse.urljoin(base_url, src)
        if urllib.parse.urlparse(absoluta).hostname == base.hostname:
            urls.append(absoluta)
    return urls[:MAX_SCRIPTS]


def renderizar_con_navegador(url):
    """HTML tras ejecutar JavaScript. Devuelve None si Playwright no esta disponible."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log("AVISO: RENDER_JS activo pero Playwright no esta instalado (pip install playwright)")
        return None
    try:
        with sync_playwright() as p:
            navegador = p.chromium.launch(headless=True)
            pagina = navegador.new_page(user_agent=USER_AGENT)
            pagina.goto(url, wait_until="networkidle", timeout=HTTP_TIMEOUT * 1000)
            contenido = pagina.content()
            navegador.close()
            return contenido
    except Exception as e:
        log(f"AVISO: fallo el renderizado con navegador: {type(e).__name__}: {e}")
        return None


def extraer_fechas(texto):
    """Saca fechas y horas del texto del aviso, para incluirlas en la alerta."""
    import re
    patrones = [
        r"\d{1,2}\s+de\s+\w+\s+de\s+\d{4}[^.]{0,60}?\d{1,2}:\d{2}[^.]{0,30}?\d{1,2}:\d{2}",
        r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}[^.]{0,60}?\d{1,2}[:.]\d{2}[^.]{0,30}?\d{1,2}[:.]\d{2}",
        r"\d{1,2}:\d{2}\s*(?:-|a|alle|and|y)\s*\d{1,2}:\d{2}",
    ]
    for p in patrones:
        m = re.search(p, texto, re.IGNORECASE)
        if m:
            return m.group(0).strip()
    return None


def check_maintenance(target, html=None):
    """
    Busca avisos de mantenimiento o tareas programadas.

    Fuentes, por orden: ventana declarada en MAINTENANCE_WINDOWS, HTML servido,
    endpoint de avisos (si se configura), ficheros .js del dominio, y pagina
    renderizada con navegador (si RENDER_JS=1).
    """
    nombre = target["name"]

    # 1. Ventana declarada: lo mas fiable, no depende de scrapear nada
    v = ventana_activa(nombre)
    if v:
        return notice("maintenance",
                      f"VENTANA DE MANTENIMIENTO ACTIVA ({v['desde']} -> {v['hasta']} UTC): {v['descripcion']}")

    fragmentos = []
    if html:
        fragmentos.append(("pagina", html_a_texto(html)))

    # 2. Endpoint de avisos, si algun dia exponen uno
    api = target.get("banner_api")
    if api:
        try:
            status, body, _ = http_get(api)
            if status == 200:
                fragmentos.append(("api", body))
            else:
                return warn("maintenance", f"El endpoint de avisos devuelve HTTP {status}")
        except Exception as e:
            return warn("maintenance", f"Endpoint de avisos inaccesible: {type(e).__name__}: {e}")

    # 3. Ficheros .js del dominio: el banner se inyecta desde cliente
    if SCAN_SCRIPTS and html:
        for js_url in scripts_del_dominio(html, target["url"]):
            try:
                status, body, _ = http_get(js_url)
                if status == 200 and len(body) <= MAX_SCRIPT_BYTES:
                    fragmentos.append((os.path.basename(urllib.parse.urlparse(js_url).path) or "script", body))
            except Exception:
                continue   # un script inaccesible no debe tumbar la comprobacion

    # 4. Renderizado real con navegador
    if RENDER_JS:
        renderizado = renderizar_con_navegador(target["url"])
        if renderizado:
            fragmentos.append(("render", html_a_texto(renderizado)))

    encontrados = []
    for origen, texto in fragmentos:
        plano = normalizar(texto)
        for kw in MAINTENANCE_KEYWORDS:
            k = normalizar(kw)
            pos = plano.find(k)
            if pos != -1:
                ini = max(0, pos - 120)
                fin = min(len(plano), pos + len(k) + 200)
                extracto = plano[ini:fin].strip()
                fechas = extraer_fechas(extracto)
                linea = f"[{origen}] ...{extracto}..."
                if fechas:
                    linea += f"\n  Ventana detectada: {fechas}"
                encontrados.append(linea)
                break

    if encontrados:
        return notice("maintenance", "Aviso publicado en el sitio: " + " | ".join(encontrados[:2]))

    # 5. Aviso anticipado de ventanas que empiezan pronto
    v_prox, inicio = ventana_proxima(nombre)
    if v_prox:
        horas = (inicio - now_utc()).total_seconds() / 3600
        return notice("maintenance",
                      f"Mantenimiento declarado dentro de {horas:.1f} h ({v_prox['desde']} UTC): {v_prox['descripcion']}")

    return ok("maintenance", "Sin avisos de mantenimiento ni ventanas declaradas")


def check_ssl(target):
    """Dias restantes del certificado."""
    parsed = urllib.parse.urlparse(target["url"])
    host = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=HTTP_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        dias = (not_after - now_utc()).days
        emisor = dict(x[0] for x in cert.get("issuer", ()))
        detalle = f"caduca el {not_after.strftime('%Y-%m-%d')} ({dias} dias) - emisor: {emisor.get('organizationName', 'n/d')}"
        if dias <= SSL_CRIT_DAYS:
            return fail("ssl", f"Certificado a punto de caducar: {detalle}")
        if dias <= SSL_WARN_DAYS:
            return warn("ssl", f"Certificado proximo a caducar: {detalle}")
        return ok("ssl", f"Certificado valido, {detalle}")
    except Exception as e:
        return fail("ssl", f"Error validando el certificado: {type(e).__name__}: {e}")


def check_login(target):
    """
    Salud funcional del login.

    Nivel 1 (siempre): la pagina de login sirve el formulario y el endpoint de
    descubrimiento OIDC responde con los endpoints de autorizacion y token.
    Nivel 2 (opcional): login real con credenciales de prueba, si defines
    IDENTITY_TEST_USER / IDENTITY_TEST_PASS. Ver deep_login_check().
    """
    disc = target.get("oidc_discovery")
    if disc:
        try:
            status, body, _ = http_get(disc)
            if status != 200:
                return fail("login", f"Descubrimiento OIDC devuelve HTTP {status}")
            data = json.loads(body)
            for campo in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                if not data.get(campo):
                    return fail("login", f"Descubrimiento OIDC sin '{campo}'")
        except json.JSONDecodeError:
            return fail("login", "El descubrimiento OIDC no devuelve JSON valido")
        except Exception as e:
            return fail("login", f"Descubrimiento OIDC inaccesible: {type(e).__name__}: {e}")

    usuario = os.environ.get("IDENTITY_TEST_USER")
    clave = os.environ.get("IDENTITY_TEST_PASS")
    if usuario and clave:
        return deep_login_check(target, usuario, clave)

    if disc:
        return ok("login", "Formulario de login y metadatos OIDC correctos")
    return ok("login", "Sin comprobacion funcional configurada para este destino")


def deep_login_check(target, usuario, clave):
    """
    Login sintetico de extremo a extremo.

    OJO: hay que ajustar los nombres de campo y la URL de POST al flujo real.
    Sacalos de las DevTools del navegador (pestana Network) haciendo un login
    en STAGE, y usa siempre una cuenta de prueba dedicada, nunca una real.
    """
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    try:
        status, body, _ = http_get(target["url"], opener=opener)
        if status != 200:
            return fail("login", f"No carga la pagina de login (HTTP {status})")

        # Token antiforgery de ASP.NET Core
        token = ""
        marcador = 'name="__RequestVerificationToken"'
        if marcador in body:
            frag = body.split(marcador, 1)[1]
            if 'value="' in frag:
                token = frag.split('value="', 1)[1].split('"', 1)[0]

        datos = urllib.parse.urlencode({
            "Input.Email": usuario,          # <-- ajustar al formulario real
            "Input.Password": clave,         # <-- ajustar al formulario real
            "__RequestVerificationToken": token,
        }).encode()

        req = urllib.request.Request(
            target["url"],
            data=datos,
            headers={"User-Agent": USER_AGENT, "Content-Type": "application/x-www-form-urlencoded"},
        )
        inicio = time.perf_counter()
        with opener.open(req, timeout=HTTP_TIMEOUT) as resp:
            cuerpo = resp.read().decode("utf-8", errors="replace")
            codigo = resp.getcode()
        elapsed = (time.perf_counter() - inicio) * 1000

        exito = any(c.name.lower().startswith((".aspnetcore.identity", "idsrv")) for c in cj)
        if codigo in (200, 302) and exito:
            return ok("login", f"Login sintetico correcto en {elapsed:.0f} ms")
        if "invalid" in cuerpo.lower() or "error" in cuerpo.lower():
            return fail("login", "El login sintetico es rechazado (credenciales o flujo cambiado)")
        return warn("login", f"Login sintetico sin confirmar (HTTP {codigo}, sin cookie de sesion)")
    except Exception as e:
        return fail("login", f"Error en el login sintetico: {type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# RESULTADOS Y ESTADO
# ---------------------------------------------------------------------------


def ok(check, msg, ms=None):
    return {"check": check, "status": "OK", "message": msg, "ms": ms}


def notice(check, msg, ms=None):
    """Informativo: no es un fallo, pero quieres enterarte (mantenimiento anunciado)."""
    return {"check": check, "status": "NOTICE", "message": msg, "ms": ms}


def warn(check, msg, ms=None):
    return {"check": check, "status": "WARN", "message": msg, "ms": ms}


def fail(check, msg, ms=None):
    return {"check": check, "status": "FAIL", "message": msg, "ms": ms}


def cargar_estado():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def guardar_estado(estado):
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(estado, f, indent=2)
    except OSError as e:
        log(f"AVISO: no se pudo escribir el estado en {STATE_FILE}: {e}")


# ---------------------------------------------------------------------------
# NOTIFICACION A TEAMS
# ---------------------------------------------------------------------------

COLORES = {"FAIL": "attention", "WARN": "warning", "NOTICE": "accent", "OK": "good"}
EMOJI = {"FAIL": "🔴", "WARN": "🟡", "NOTICE": "🔵", "OK": "🟢"}


def construir_adaptive_card(titulo, severidad, lineas):
    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {"type": "TextBlock", "text": f"{EMOJI.get(severidad, '')} {titulo}",
                     "weight": "Bolder", "size": "Medium", "color": COLORES.get(severidad, "default"), "wrap": True},
                    {"type": "TextBlock", "text": "\n\n".join(lineas), "wrap": True},
                    {"type": "TextBlock", "text": now_utc().strftime("%Y-%m-%d %H:%M:%S UTC"),
                     "isSubtle": True, "size": "Small", "spacing": "Small"},
                ],
                "actions": [
                    {"type": "Action.OpenUrl", "title": "Abrir PROD", "url": "https://identity.teamsystem.com/"},
                    {"type": "Action.OpenUrl", "title": "Abrir STAGE", "url": "https://identity-stage.teamsystem.com/"},
                ],
            },
        }],
    }


def construir_message_card(titulo, severidad, lineas):
    color = {"FAIL": "D93025", "WARN": "F9AB00", "NOTICE": "1A73E8", "OK": "188038"}.get(severidad, "808080")
    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": color,
        "summary": titulo,
        "title": f"{EMOJI.get(severidad, '')} {titulo}",
        "text": "\n\n".join(lineas),
    }


def enviar_telegram(titulo, severidad, lineas, dry_run=False):
    """Envia el aviso a Telegram con la API de bots."""
    import html as _html
    if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
        return None   # canal no configurado

    def fmt(t):
        # Escapar HTML y convertir **negrita** al formato de Telegram
        t = _html.escape(t)
        partes = t.split("**")
        salida = ""
        for i, p in enumerate(partes):
            salida += f"<b>{p}</b>" if i % 2 else p
        return salida

    cuerpo = f"{EMOJI.get(severidad, '')} <b>{_html.escape(titulo)}</b>\n\n"
    cuerpo += "\n\n".join(fmt(l) for l in lineas if l)
    cuerpo += f"\n\n<i>{now_utc().strftime('%Y-%m-%d %H:%M:%S UTC')}</i>"
    cuerpo = cuerpo[:4000]   # limite de Telegram

    if dry_run:
        log(f"[DRY-RUN Telegram] {severidad}: {titulo}")
        return True

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": cuerpo,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
        # Los avisos informativos no vibran el movil; los fallos si
        "disable_notification": severidad in ("OK", "NOTICE"),
    }
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            respuesta = json.loads(resp.read().decode("utf-8"))
            if not respuesta.get("ok"):
                log(f"ERROR Telegram: {respuesta.get('description')}")
                return False
        return True
    except urllib.error.HTTPError as e:
        detalle = e.read().decode("utf-8", errors="replace")[:300]
        log(f"ERROR Telegram HTTP {e.code}: {detalle}")
        return False
    except Exception as e:
        log(f"ERROR Telegram: {type(e).__name__}: {e}")
        return False


def notificar(titulo, severidad, lineas, dry_run=False):
    """Envia el aviso por todos los canales configurados."""
    resultados = [enviar_telegram(titulo, severidad, lineas, dry_run),
                  enviar_teams(titulo, severidad, lineas, dry_run)]
    enviados = [r for r in resultados if r is not None]
    if not enviados:
        log(f"[SIN CANALES CONFIGURADOS] {severidad}: {titulo}")
        for l in lineas:
            log(f"    {l}")
        return True
    return any(enviados)


def enviar_teams(titulo, severidad, lineas, dry_run=False):
    if not TEAMS_WEBHOOK_URL:
        return None   # canal no configurado
    if dry_run:
        log(f"[DRY-RUN Teams] {severidad}: {titulo}")
        for l in lineas:
            log(f"    {l}")
        return True

    payload = (construir_adaptive_card if TEAMS_PAYLOAD_FORMAT == "adaptive" else construir_message_card)(
        titulo, severidad, lineas)
    req = urllib.request.Request(
        TEAMS_WEBHOOK_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            if resp.getcode() not in (200, 202):
                log(f"AVISO: Teams devolvio HTTP {resp.getcode()}")
                return False
        return True
    except Exception as e:
        log(f"ERROR enviando a Teams: {type(e).__name__}: {e}")
        return False


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------


SEVERIDAD = {"OK": 0, "NOTICE": 1, "WARN": 2, "FAIL": 3}


def evaluar_target(target):
    r_http = check_http(target)
    html = r_http.pop("body", None)
    resultados = [r_http]

    # Si no responde, el resto de comprobaciones no aportan nada
    if not (r_http["status"] == "FAIL" and r_http["check"] == "http"):
        resultados.append(check_login(target))

    # El aviso de mantenimiento se comprueba SIEMPRE, tambien (y sobre todo)
    # si el sitio no responde: es lo que distingue una caida de una ventana
    # de mantenimiento anunciada.
    resultados.append(check_maintenance(target, html))

    resultados.append(check_ssl(target))
    return resultados


def main():
    ap = argparse.ArgumentParser(description="Monitor de TeamSystem Identity")
    ap.add_argument("--dry-run", action="store_true", help="no envia a Teams, solo imprime")
    ap.add_argument("--test-alert", action="store_true", help="envia una alerta de prueba y sale")
    ap.add_argument("--always-notify", action="store_true", help="notifica en cada ejecucion, no solo en cambios")
    ap.add_argument("--exit-zero", action="store_true", help="salir siempre con codigo 0 (util en GitHub Actions)")
    args = ap.parse_args()

    if args.test_alert:
        exito = notificar("Prueba del monitor de Identity", "OK",
                             ["Si ves este mensaje, las notificaciones estan bien configuradas."], args.dry_run)
        sys.exit(0 if exito else 1)

    estado = cargar_estado()
    hay_fallo = False
    hay_aviso = False

    for target in TARGETS:
        nombre = target["name"]
        resultados = evaluar_target(target)
        peor = max((r["status"] for r in resultados), key=lambda s: SEVERIDAD[s])

        aviso_mtto = next((r for r in resultados
                           if r["check"] == "maintenance" and r["status"] == "NOTICE"), None)
        en_ventana = ventana_activa(nombre) is not None

        for r in resultados:
            log(f"{nombre} / {r['check']}: {r['status']} - {r['message']}")

        previo = estado.get(nombre, {})
        estado_previo = previo.get("status", "OK")
        ultimo_aviso = previo.get("last_alert_ts", 0)
        minutos_desde_aviso = (time.time() - ultimo_aviso) / 60

        cambio = peor != estado_previo
        recordatorio = (peor != "OK" and REMINDER_MINUTES > 0 and minutos_desde_aviso >= REMINDER_MINUTES)

        if cambio or recordatorio or args.always_notify:
            if peor == "OK" and estado_previo != "OK":
                titulo = f"RECUPERADO: {nombre}"
                lineas = [f"El servicio vuelve a estar operativo."] + \
                         [f"**{r['check']}**: {r['message']}" for r in resultados]
            elif peor == "NOTICE":
                titulo = f"AVISO PUBLICADO: {nombre}"
                lineas = ["El sitio esta publicando un aviso de mantenimiento o tarea programada.",
                          f"URL: {target['url']}",
                          aviso_mtto["message"] if aviso_mtto else ""]
            else:
                if target.get("critical") and peor == "FAIL":
                    etiqueta = "INCIDENCIA"
                    if MAINTENANCE_DOWNGRADE and en_ventana:
                        etiqueta = "CAIDA DENTRO DE VENTANA DE MANTENIMIENTO"
                    elif MAINTENANCE_DOWNGRADE and aviso_mtto:
                        etiqueta = "FALLO CON AVISO DE MANTENIMIENTO PUBLICADO"
                else:
                    etiqueta = peor
                titulo = f"{etiqueta}: {nombre}"
                lineas = [f"**{r['check']}**: {r['message']}" for r in resultados
                          if r["status"] != "OK"] or \
                         [f"**{r['check']}**: {r['message']}" for r in resultados]
                lineas.insert(0, f"URL: {target['url']}")
            notificar(titulo, peor, lineas, args.dry_run)
            estado[nombre] = {"status": peor, "last_alert_ts": time.time(),
                              "since": now_utc().isoformat()}
        else:
            estado[nombre] = {"status": peor,
                              "last_alert_ts": ultimo_aviso,
                              "since": previo.get("since", now_utc().isoformat())}

        if peor == "FAIL":
            # Dentro de ventana declarada no es una incidencia que deba
            # escalar: sale con codigo 1 (aviso) en vez de 2 (fallo).
            if en_ventana and MAINTENANCE_DOWNGRADE:
                hay_aviso = True
            else:
                hay_fallo = True
        elif peor == "WARN":
            hay_aviso = True

    guardar_estado(estado)
    if args.exit_zero:
        sys.exit(0)
    if hay_fallo:
        sys.exit(2)
    sys.exit(1 if hay_aviso else 0)


if __name__ == "__main__":
    main()
