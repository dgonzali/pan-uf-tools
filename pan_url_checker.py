#!/usr/bin/env python3
"""
pan_url_checker.py
------------------
Consulta la categoría de URLs a través de la API de un firewall Palo Alto Networks.

Uso:
    python pan_url_checker.py                     # Modo interactivo
    python pan_url_checker.py -u <url>            # URL individual
    python pan_url_checker.py -f <fichero.txt>    # Fichero con URLs (una por línea)
    python pan_url_checker.py -u <url> -u <url2>  # Múltiples URLs
    python pan_url_checker.py -D -u <url>         # Debug: muestra respuesta cruda
"""

import argparse
import os
import sys
import xml.etree.ElementTree as ET

import requests
import urllib3
from dotenv import load_dotenv

# Suprimir advertencias de certificado SSL auto-firmado
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ──────────────────────────────────────────────────────────────────────────────
# Colores ANSI para la terminal
# ──────────────────────────────────────────────────────────────────────────────
class Color:
    HEADER  = "\033[95m"
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

RISK_COLORS = {
    "low-risk":      Color.GREEN,
    "medium-risk":   Color.YELLOW,
    "high-risk":     Color.RED,
    "critical-risk": Color.RED + Color.BOLD,
}

# ──────────────────────────────────────────────────────────────────────────────
# Carga de configuración desde .env
# ──────────────────────────────────────────────────────────────────────────────
def load_config() -> tuple[str, str]:
    load_dotenv()
    fw_ip   = os.getenv("FIREWALL_IP")
    api_key = os.getenv("PAN_API_KEY")

    if not fw_ip or not api_key:
        print(
            f"{Color.RED}[ERROR]{Color.RESET} Faltan variables de entorno. "
            "Asegúrate de que el fichero .env contiene FIREWALL_IP y PAN_API_KEY."
        )
        sys.exit(1)

    return fw_ip.strip(), api_key.strip()


# ──────────────────────────────────────────────────────────────────────────────
# Consulta a la API del firewall
# ──────────────────────────────────────────────────────────────────────────────
def print_debug(label: str, raw: str) -> None:
    """Imprime la respuesta cruda de la API en modo debug."""
    print(f"\n{Color.YELLOW}{'─'*10} DEBUG: {label} {'─'*10}{Color.RESET}")
    print(raw.strip())
    print(f"{Color.YELLOW}{'─'*40}{Color.RESET}\n")


def query_url_category(url: str, fw_ip: str, api_key: str, debug: bool = False) -> dict:
    """
    Realiza la consulta y devuelve un dict con:
        { "url": str, "category": str, "risk": str, "raw": str, "error": str|None }
    """
    endpoint = f"https://{fw_ip}/api/"
    params   = {
        "type": "op",
        "cmd":  f"<test><url-info-cloud>{url}</url-info-cloud></test>",
    }
    headers  = {"X-PAN-KEY": api_key}

    result = {"url": url, "category": "N/A", "risk": "N/A", "raw": "", "error": None}

    try:
        resp = requests.get(
            endpoint,
            params=params,
            headers=headers,
            verify=False,
            timeout=15,
        )
        resp.raise_for_status()
        result["raw"] = resp.text
        if debug:
            print_debug(url, resp.text)
        _parse_response(resp.text, result)

    except requests.exceptions.ConnectionError:
        result["error"] = f"No se puede conectar al firewall {fw_ip}"
    except requests.exceptions.Timeout:
        result["error"] = "Tiempo de espera agotado"
    except requests.exceptions.HTTPError as exc:
        result["error"] = f"Error HTTP {exc.response.status_code}"
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)

    return result


def _parse_response(xml_text: str, result: dict) -> None:
    """
    Parsea la respuesta XML del firewall.

    Formato esperado en <result>:
        BM:\n
        example.com,<num>,<num>,<category>,<risk>\n
    """
    try:
        root = ET.fromstring(xml_text)
        if root.attrib.get("status") != "success":
            result["error"] = "La API devolvió status != success"
            return

        result_node = root.find("result")
        if result_node is None or not result_node.text:
            result["error"] = "Respuesta sin nodo <result>"
            return

        raw_text = result_node.text.strip()
        # Buscamos la línea CSV con los datos (ignoramos la línea "BM:")
        for line in raw_text.splitlines():
            line = line.strip()
            if not line or line.upper().startswith("BM:"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 5:
                result["category"] = parts[3]
                result["risk"]     = parts[4]
                return
            elif len(parts) >= 4:
                result["category"] = parts[3]
                return

        result["error"] = f"Formato de respuesta inesperado: {raw_text}"

    except ET.ParseError as exc:
        result["error"] = f"Error parseando XML: {exc}"


# ──────────────────────────────────────────────────────────────────────────────
# Presentación de resultados
# ──────────────────────────────────────────────────────────────────────────────
HEADER_LINE = f"{'URL':<45} {'CATEGORÍA':<30} {'RIESGO'}"
SEPARATOR   = "─" * 85


def _format_row(r: dict) -> str:
    if r["error"]:
        return f"{r['url']:<45} {Color.RED}ERROR: {r['error']}{Color.RESET}"

    risk_color = RISK_COLORS.get(r["risk"].lower(), "")
    return (
        f"{r['url']:<45} "
        f"{Color.CYAN}{r['category']:<30}{Color.RESET} "
        f"{risk_color}{r['risk']}{Color.RESET}"
    )


def print_table(results: list[dict], title: str = "") -> None:
    if title:
        print(f"\n{Color.BOLD}{Color.HEADER}{title}{Color.RESET}")
    print(SEPARATOR)
    print(f"{Color.BOLD}{HEADER_LINE}{Color.RESET}")
    print(SEPARATOR)
    for r in results:
        print(_format_row(r))
    print(SEPARATOR)


# ──────────────────────────────────────────────────────────────────────────────
# Modos de operación
# ──────────────────────────────────────────────────────────────────────────────
def process_urls(urls: list[str], fw_ip: str, api_key: str, debug: bool = False) -> list[dict]:
    """Procesa una lista de URLs y devuelve los resultados."""
    results = []
    for url in urls:
        url = url.strip()
        if not url:
            continue
        print(f"  {Color.YELLOW}→{Color.RESET} Consultando {url} ...", end=" ", flush=True)
        r = query_url_category(url, fw_ip, api_key, debug=debug)
        results.append(r)
        if r["error"]:
            print(f"{Color.RED}ERROR{Color.RESET}")
        else:
            print(f"{Color.GREEN}OK{Color.RESET}")
    return results


def mode_single_or_file(urls: list[str], fw_ip: str, api_key: str, debug: bool = False) -> None:
    """Modo no interactivo: URL(s) directas o desde fichero."""
    print(f"\n{Color.BOLD}Procesando {len(urls)} URL(s)...{Color.RESET}")
    results = process_urls(urls, fw_ip, api_key, debug=debug)
    print_table(results, title="Resultado")


def mode_interactive(fw_ip: str, api_key: str, debug: bool = False) -> None:
    """Modo interactivo: pide URLs al usuario hasta que responda 'no'."""
    print(
        f"\n{Color.BOLD}{Color.HEADER}"
        "╔══════════════════════════════════════════╗\n"
        "║  PAN URL Checker  –  Modo interactivo   ║\n"
        "╚══════════════════════════════════════════╝"
        f"{Color.RESET}"
    )
    print(f"  Firewall: {Color.CYAN}{fw_ip}{Color.RESET}")
    if debug:
        print(f"  {Color.YELLOW}[DEBUG ACTIVADO]{Color.RESET}")
    print("  Escribe 'salir' o 'exit' para terminar sin más consultas.\n")

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

        r = query_url_category(url, fw_ip, api_key, debug=debug)
        history.append(r)
        print_table([r])

        try:
            again = input(f"\n{Color.BOLD}¿Deseas hacer otra consulta? (s/n):{Color.RESET} ").strip().lower()
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
        description="Consulta categorías de URL en un firewall Palo Alto Networks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  python pan_url_checker.py\n"
            "  python pan_url_checker.py -u bbva.es\n"
            "  python pan_url_checker.py -u bbva.es -u google.com\n"
            "  python pan_url_checker.py -f urls.txt\n"
            "  python pan_url_checker.py -D -u bbva.es  # con debug\n"
        ),
    )
    parser.add_argument(
        "-u", "--url",
        action="append",
        dest="urls",
        metavar="URL",
        help="URL a consultar (se puede repetir para múltiples URLs).",
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
    return parser.parse_args()


def main() -> None:
    args    = parse_args()
    fw_ip, api_key = load_config()

    # Recopilar URLs
    urls: list[str] = []

    if args.urls:
        urls.extend(args.urls)

    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                file_urls = [line.strip() for line in fh if line.strip()]
            print(f"{Color.GREEN}[INFO]{Color.RESET} Leídas {len(file_urls)} URLs desde '{args.file}'.")
            urls.extend(file_urls)
        except FileNotFoundError:
            print(f"{Color.RED}[ERROR]{Color.RESET} No se encuentra el fichero '{args.file}'.")
            sys.exit(1)

    if urls:
        # Eliminar duplicados manteniendo el orden
        seen = set()
        unique_urls = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                unique_urls.append(u)
        mode_single_or_file(unique_urls, fw_ip, api_key, debug=args.debug)
    else:
        # Sin argumentos → modo interactivo
        mode_interactive(fw_ip, api_key, debug=args.debug)


if __name__ == "__main__":
    main()
