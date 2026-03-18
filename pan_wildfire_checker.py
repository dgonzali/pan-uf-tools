#!/usr/bin/env python3
"""
pan_wildfire_checker.py
-----------------------
Consulta el veredicto de WildFire para una o varias URLs.

Flujo por URL:
  1. GET /publicapi/get/verdict  → veredicto inmediato si WildFire ya la conoce.
  2. Si la URL es desconocida (-102), se envía a análisis con /publicapi/submit/link
     y espera el veredicto en bucle (polling) hasta obtener respuesta o agotar el timeout.

Endpoint base: https://wildfire.paloaltonetworks.com/publicapi
Auth:          Form field 'apikey' en cada petición

Uso:
    python pan_wildfire_checker.py                         # Modo interactivo
    python pan_wildfire_checker.py -u <url>                # URL individual
    python pan_wildfire_checker.py -u <u1> -u <u2>        # Múltiples URLs
    python pan_wildfire_checker.py -f <fichero.txt>        # Fichero (uno por línea)
    python pan_wildfire_checker.py -D -u <url>             # Debug: respuesta XML cruda
    python pan_wildfire_checker.py --wait-timeout 0 -u <url>  # Sin espera tras submit
"""

import argparse
import os
import sys
import time
import xml.etree.ElementTree as ET

import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ──────────────────────────────────────────────────────────────────────────────
# Constantes
# ──────────────────────────────────────────────────────────────────────────────
WF_BASE      = "https://wildfire.paloaltonetworks.com/publicapi"
URL_VERDICT  = f"{WF_BASE}/get/verdict"
URL_SUBMIT   = f"{WF_BASE}/submit/link"

# Polling tras submit: intervalo y timeout por defecto (segundos)
DEFAULT_POLL_INTERVAL = 15   # consulta cada 15 s
DEFAULT_POLL_TIMEOUT  = 300  # espera máximo 5 minutos (0 = no esperar)

# Veredictos que indican que el análisis aún no ha terminado
PENDING_CODES = {"-100", "-102"}

# Mapa de veredictos numéricos
VERDICTS = {
    "0":    ("benign",   "benign"),
    "1":    ("malware",  "malware"),
    "2":    ("grayware", "grayware"),
    "4":    ("phishing", "phishing"),
    "5":    ("c2",       "C2"),
    "-100": ("pending",  "pending (análisis en curso)"),
    "-101": ("error",    "error en el análisis"),
    "-102": ("unknown",  "desconocida"),
    "-103": ("invalid",  "hash/url inválido"),
}

# ──────────────────────────────────────────────────────────────────────────────
# Colores ANSI
# ──────────────────────────────────────────────────────────────────────────────
class Color:
    HEADER = "\033[95m"
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

VERDICT_COLORS = {
    "benign":   Color.GREEN,
    "malware":  Color.RED + Color.BOLD,
    "grayware": Color.YELLOW,
    "phishing": Color.RED,
    "c2":       Color.RED + Color.BOLD,
    "pending":  Color.YELLOW,
    "unknown":  Color.DIM,
    "error":    Color.RED,
    "invalid":  Color.RED,
}

# ──────────────────────────────────────────────────────────────────────────────
# Configuración desde .env
# ──────────────────────────────────────────────────────────────────────────────
def load_config() -> str:
    load_dotenv()
    api_key = os.getenv("WILDFIRE_API_KEY")
    if not api_key:
        print(
            f"{Color.RED}[ERROR]{Color.RESET} Falta la variable WILDFIRE_API_KEY en el fichero .env."
        )
        sys.exit(1)
    return api_key.strip()


# ──────────────────────────────────────────────────────────────────────────────
# Debug
# ──────────────────────────────────────────────────────────────────────────────
def print_debug(label: str, raw: str) -> None:
    print(f"\n{Color.YELLOW}{'─'*10} DEBUG: {label} {'─'*10}{Color.RESET}")
    print(raw.strip())
    print(f"{Color.YELLOW}{'─'*40}{Color.RESET}\n")


# ──────────────────────────────────────────────────────────────────────────────
# Parse XML de WildFire
# ──────────────────────────────────────────────────────────────────────────────
def _parse_verdict_xml(xml_text: str) -> tuple[str, str, str]:
    """
    Parsea la respuesta XML de /get/verdict.
    Devuelve (verdict_code, verdict_label, analysis_time).
    """
    try:
        root = ET.fromstring(xml_text)
        info = root.find(".//get-verdict-info")
        if info is None:
            # Buscar mensaje de error
            msg_node = root.find(".//error-message")
            if msg_node is not None:
                return "-101", f"error: {msg_node.text}", ""
            return "-101", "error: respuesta inesperada", ""

        verdict_code = (info.findtext("verdict") or "-101").strip()
        analysis_time = (info.findtext("analysis_time") or "").strip()
        return verdict_code, VERDICTS.get(verdict_code, ("?", verdict_code))[1], analysis_time

    except ET.ParseError as exc:
        return "-101", f"error XML: {exc}", ""


def _parse_submit_xml(xml_text: str) -> str:
    """
    Parsea la respuesta XML de /submit/link.
    Devuelve el SHA256 si está disponible o un mensaje de estado.
    """
    try:
        root = ET.fromstring(xml_text)
        sha256 = root.findtext(".//sha256") or root.findtext(".//url")
        status = root.findtext(".//status") or "submitted"
        if sha256:
            return f"Enviado – SHA256: {sha256}"
        return f"Enviado – estado: {status}"
    except ET.ParseError:
        return "Enviado (respuesta no parseable)"


# ──────────────────────────────────────────────────────────────────────────────
# Llamadas a la API
# ──────────────────────────────────────────────────────────────────────────────
def _do_get_verdict(url: str, api_key: str, debug: bool = False) -> tuple[str, str, str, str, str | None]:
    """
    Llama a /get/verdict y devuelve (code, label, atime, raw, error).
    """
    try:
        resp = requests.post(
            URL_VERDICT,
            data={"apikey": api_key, "url": url},
            timeout=20,
        )
        resp.raise_for_status()
        if debug:
            print_debug(f"GET VERDICT → {url}", resp.text)
        code, label, atime = _parse_verdict_xml(resp.text)
        return code, label, atime, resp.text, None
    except requests.exceptions.ConnectionError:
        return "", "", "", "", "No se puede conectar con WildFire"
    except requests.exceptions.Timeout:
        return "", "", "", "", "Tiempo de espera agotado (get/verdict)"
    except requests.exceptions.HTTPError as exc:
        return "", "", "", "", f"Error HTTP {exc.response.status_code} (get/verdict)"
    except Exception as exc:  # noqa: BLE001
        return "", "", "", "", str(exc)


def get_verdict(
    url: str,
    api_key: str,
    debug: bool = False,
    poll_timeout: int = DEFAULT_POLL_TIMEOUT,
    poll_interval: int = DEFAULT_POLL_INTERVAL,
) -> dict:
    """
    Consulta el veredicto de una URL en WildFire.
    Si es desconocida (-102), la envía a análisis y espera el resultado
    en bucle (polling) durante poll_timeout segundos (0 = no esperar).
    """
    result = {
        "url":           url,
        "verdict_code":  "",
        "verdict_label": "",
        "analysis_time": "",
        "submitted":     False,
        "submit_status": "",
        "raw_verdict":   "",
        "raw_submit":    "",
        "error":         None,
        "poll_attempts": 0,
    }

    # ── 1. Consultar veredicto inicial ──────────────────────────────────────
    code, label, atime, raw, err = _do_get_verdict(url, api_key, debug)
    if err:
        result["error"] = err
        return result

    result.update({
        "verdict_code":  code,
        "verdict_label": label,
        "analysis_time": atime,
        "raw_verdict":   raw,
    })

    # ── 2. Si es desconocida → submit + polling ─────────────────────────────
    if code != "-102":
        return result

    # 2a. Enviar a análisis
    try:
        sresp = requests.post(
            URL_SUBMIT,
            data={"apikey": api_key, "link": url},
            timeout=20,
        )
        sresp.raise_for_status()
        result["raw_submit"]    = sresp.text
        result["submitted"]     = True
        result["submit_status"] = _parse_submit_xml(sresp.text)
        if debug:
            print_debug(f"SUBMIT LINK → {url}", sresp.text)
    except Exception as exc:  # noqa: BLE001
        result["submit_status"] = f"Error al enviar: {exc}"
        return result

    # 2b. Polling mientras WildFire analiza
    if poll_timeout <= 0:
        return result

    print(
        f"  {Color.YELLOW}⏳ URL enviada a WildFire. "
        f"Esperando veredicto (máx. {poll_timeout}s, cada {poll_interval}s)...{Color.RESET}"
    )

    elapsed   = 0
    attempt   = 0
    spinner   = ["⠋", "⠙", "⠸", "⠴", "⠦", "⠇"]

    while elapsed < poll_timeout:
        time.sleep(poll_interval)
        elapsed += poll_interval
        attempt += 1
        result["poll_attempts"] = attempt

        spin = spinner[attempt % len(spinner)]
        print(
            f"  {Color.DIM}{spin} Intento #{attempt} ({elapsed}s transcurridos)...{Color.RESET}",
            end=" ", flush=True,
        )

        code, label, atime, raw, err = _do_get_verdict(url, api_key, debug)
        if err:
            print(f"{Color.RED}error de red{Color.RESET}")
            continue

        print(f"{color_for(code)}{label}{Color.RESET}")

        if code not in PENDING_CODES:
            # Veredicto definitivo
            result.update({
                "verdict_code":  code,
                "verdict_label": label,
                "analysis_time": atime,
                "raw_verdict":   raw,
            })
            return result

    # Timeout alcanzado — devolvemos el último estado conocido
    print(
        f"  {Color.YELLOW}⚠ Timeout alcanzado ({poll_timeout}s). "
        f"La URL sigue en análisis; vuelve a consultar más tarde.{Color.RESET}"
    )
    result.update({
        "verdict_code":  "-100",
        "verdict_label": VERDICTS["-100"][1],
    })
    return result


def color_for(code: str) -> str:
    """Devuelve el código de color ANSI para un veredicto."""
    v_key = VERDICTS.get(code, ("?",))[0]
    return VERDICT_COLORS.get(v_key, "")


# ──────────────────────────────────────────────────────────────────────────────
# Presentación
# ──────────────────────────────────────────────────────────────────────────────
SEPARATOR = "─" * 95


def _verdict_colored(code: str, label: str) -> str:
    v_key = VERDICTS.get(code, ("?",))[0]
    color = VERDICT_COLORS.get(v_key, "")
    return f"{color}{label}{Color.RESET}"


def print_table(results: list[dict], title: str = "") -> None:
    if title:
        print(f"\n{Color.BOLD}{Color.HEADER}{title}{Color.RESET}")

    print(SEPARATOR)
    header = f"{'URL':<45} {'VEREDICTO':<28} {'ANÁLISIS':<22} {'ENVIADO'}"
    print(f"{Color.BOLD}{header}{Color.RESET}")
    print(SEPARATOR)

    for r in results:
        if r["error"]:
            print(f"{r['url']:<45} {Color.RED}ERROR: {r['error']}{Color.RESET}")
            continue

        submitted_str = f"{Color.GREEN}Sí{Color.RESET}" if r["submitted"] else f"{Color.DIM}No{Color.RESET}"
        print(
            f"{r['url']:<45} "
            f"{_verdict_colored(r['verdict_code'], r['verdict_label']):<38} "
            f"{r['analysis_time'][:19]:<22} "
            f"{submitted_str}"
        )
        if r["submitted"] and r["submit_status"]:
            print(f"  {Color.DIM}↳ {r['submit_status']}{Color.RESET}")

    print(SEPARATOR)


def print_single(r: dict) -> None:
    """Muestra un resultado individual con más detalle."""
    print(SEPARATOR)
    if r["error"]:
        print(f"  {Color.RED}ERROR:{Color.RESET} {r['error']}")
        print(SEPARATOR)
        return

    print(f"  {Color.BOLD}URL      :{Color.RESET}  {r['url']}")
    print(f"  {Color.BOLD}Veredicto:{Color.RESET}  {_verdict_colored(r['verdict_code'], r['verdict_label'])}")

    if r["analysis_time"]:
        print(f"  {Color.BOLD}Analizado:{Color.RESET}  {r['analysis_time']}")

    if r["submitted"]:
        print(f"  {Color.BOLD}Enviado  :{Color.RESET}  {Color.GREEN}{r['submit_status']}{Color.RESET}")
    else:
        print(f"  {Color.BOLD}Enviado  :{Color.RESET}  {Color.DIM}No (ya existía en la base de datos){Color.RESET}")

    print(SEPARATOR)


# ──────────────────────────────────────────────────────────────────────────────
# Modos de operación
# ──────────────────────────────────────────────────────────────────────────────
def process_urls(
    urls: list[str],
    api_key: str,
    debug: bool = False,
    poll_timeout: int = DEFAULT_POLL_TIMEOUT,
) -> list[dict]:
    results = []
    for url in urls:
        url = url.strip()
        if not url:
            continue
        print(f"  {Color.YELLOW}→{Color.RESET} Consultando {url} ...", end=" ", flush=True)
        r = get_verdict(url, api_key, debug=debug, poll_timeout=poll_timeout)
        results.append(r)
        if r["error"]:
            print(f"{Color.RED}ERROR{Color.RESET}")
        elif r["submitted"] and r["verdict_code"] in PENDING_CODES:
            # Ya imprimimos el progreso del polling, sólo añadimos salto de línea
            pass
        elif r["submitted"]:
            # Veredicto obtenido tras polling
            print(f"{color_for(r['verdict_code'])}{r['verdict_label']}{Color.RESET}")
        else:
            print(f"{color_for(r['verdict_code'])}{r['verdict_label']}{Color.RESET}")
    return results


def mode_batch(urls: list[str], api_key: str, debug: bool = False, poll_timeout: int = DEFAULT_POLL_TIMEOUT) -> None:
    print(f"\n{Color.BOLD}Procesando {len(urls)} URL(s)...{Color.RESET}")
    results = process_urls(urls, api_key, debug=debug, poll_timeout=poll_timeout)
    print_table(results, title="Resultado")


def mode_interactive(api_key: str, debug: bool = False, poll_timeout: int = DEFAULT_POLL_TIMEOUT) -> None:
    print(
        f"\n{Color.BOLD}{Color.HEADER}"
        "╔═══════════════════════════════════════════════╗\n"
        "║  PAN WildFire Checker  –  Modo interactivo  ║\n"
        "╚═══════════════════════════════════════════════╝"
        f"{Color.RESET}"
    )
    print("  API: WildFire Cloud (wildfire.paloaltonetworks.com)")
    if debug:
        print(f"  {Color.YELLOW}[DEBUG ACTIVADO]{Color.RESET}")
    if poll_timeout > 0:
        print(f"  Espera máxima tras submit: {Color.CYAN}{poll_timeout}s{Color.RESET} (cada {DEFAULT_POLL_INTERVAL}s)")
    else:
        print(f"  {Color.DIM}Polling desactivado (--wait-timeout 0){Color.RESET}")
    print("  Escribe 'salir' o 'exit' para terminar.\n")

    history: list[dict] = []

    while True:
        try:
            url = input(f"{Color.BOLD}URL a consultar:{Color.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if url.lower() in {"salir", "exit", "quit", "q"}:
            break
        if not url:
            continue

        r = get_verdict(url, api_key, debug=debug, poll_timeout=poll_timeout)
        history.append(r)
        print_single(r)

        try:
            again = input(
                f"\n{Color.BOLD}¿Deseas hacer otra consulta? (s/n):{Color.RESET} "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if again not in {"s", "si", "sí", "yes", "y"}:
            break

        print()

    if history:
        print_table(history, title=f"Resumen final – {len(history)} consulta(s)")
    else:
        print("\nNo se realizó ninguna consulta.")


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Consulta el veredicto de WildFire para una o varias URLs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  python pan_wildfire_checker.py\n"
            "  python pan_wildfire_checker.py -u http://malware-site.com\n"
            "  python pan_wildfire_checker.py -u u1.com -u u2.com\n"
            "  python pan_wildfire_checker.py -f urls.txt\n"
            "  python pan_wildfire_checker.py -D -u http://test.com  # con debug\n"
        ),
    )
    parser.add_argument(
        "-u", "--url",
        action="append",
        dest="urls",
        metavar="URL",
        help="URL a consultar (se puede repetir).",
    )
    parser.add_argument(
        "-f", "--file",
        metavar="FICHERO",
        help="Fichero de texto con una URL por línea.",
    )
    parser.add_argument(
        "-D", "--debug",
        action="store_true",
        default=False,
        help="Muestra la respuesta XML cruda de la API tras cada petición.",
    )
    parser.add_argument(
        "--wait-timeout",
        type=int,
        default=DEFAULT_POLL_TIMEOUT,
        metavar="SEG",
        help=(
            f"Segundos máximos esperando el veredicto tras enviar una URL a análisis "
            f"(por defecto {DEFAULT_POLL_TIMEOUT}s; usa 0 para no esperar)."
        ),
    )
    return parser.parse_args()


def main() -> None:
    args    = parse_args()
    api_key = load_config()

    urls: list[str] = []

    if args.urls:
        urls.extend(args.urls)

    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                file_urls = [line.strip() for line in fh if line.strip()]
            print(
                f"{Color.GREEN}[INFO]{Color.RESET} "
                f"Leídas {len(file_urls)} URLs desde '{args.file}'."
            )
            urls.extend(file_urls)
        except FileNotFoundError:
            print(f"{Color.RED}[ERROR]{Color.RESET} No se encuentra el fichero '{args.file}'.")
            sys.exit(1)

    if urls:
        # Deduplicar conservando orden
        seen, unique = set(), []
        for u in urls:
            if u not in seen:
                seen.add(u)
                unique.append(u)
        mode_batch(unique, api_key, debug=args.debug, poll_timeout=args.wait_timeout)
    else:
        mode_interactive(api_key, debug=args.debug, poll_timeout=args.wait_timeout)


if __name__ == "__main__":
    main()
