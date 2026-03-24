#!/usr/bin/env python3
"""
pan_domain_checker.py
---------------------
Consulta información de dominios a través de la API Threat Vault de
DNS Security de Palo Alto Networks.

Endpoint: POST https://api.dns.service.paloaltonetworks.com/v1/domain/info
Auth:     Header X-DNS-API-APIKEY

Uso:
    python pan_domain_checker.py                     # Modo interactivo
    python pan_domain_checker.py -d <dominio>        # Dominio individual
    python pan_domain_checker.py -d <d1> -d <d2>    # Múltiples dominios
    python pan_domain_checker.py -f <fichero.txt>    # Fichero (uno por línea)
    python pan_domain_checker.py -D -d <dominio>     # Debug: muestra respuesta cruda
"""

import argparse
import json
import os
import sys

import requests
from dotenv import load_dotenv

# ──────────────────────────────────────────────────────────────────────────────
# Constantes
# ──────────────────────────────────────────────────────────────────────────────
API_ENDPOINT = "https://api.dns.service.paloaltonetworks.com/v1/domain/info"
BATCH_SIZE   = 20  # máximo permitido por la API

# ──────────────────────────────────────────────────────────────────────────────
# Colores ANSI
# ──────────────────────────────────────────────────────────────────────────────
class Color:
    HEADER  = "\033[95m"
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    BLUE    = "\033[94m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

CATEGORY_COLORS = {
    "malware":            Color.RED + Color.BOLD,
    "command-and-control": Color.RED + Color.BOLD,
    "c2":                 Color.RED + Color.BOLD,
    "phishing":           Color.RED,
    "grayware":           Color.YELLOW,
    "parked":             Color.DIM,
    "benign":             Color.GREEN,
}

VERDICT_LABELS = {
    0: f"{Color.GREEN}benign{Color.RESET}",
    1: f"{Color.RED}malicious{Color.RESET}",
    2: f"{Color.YELLOW}grayware{Color.RESET}",
    4: f"{Color.YELLOW}phishing{Color.RESET}",
}

# ──────────────────────────────────────────────────────────────────────────────
# Configuración desde .env
# ──────────────────────────────────────────────────────────────────────────────
def load_config() -> str:
    load_dotenv()
    api_key = os.getenv("DNS_API_KEY")
    if not api_key:
        print(
            f"{Color.RED}[ERROR]{Color.RESET} Falta la variable de entorno DNS_API_KEY en el fichero .env."
        )
        sys.exit(1)
    return api_key.strip()


# ──────────────────────────────────────────────────────────────────────────────
# Debug
# ──────────────────────────────────────────────────────────────────────────────
def print_debug(label: str, data: dict | str) -> None:
    """Imprime la respuesta JSON cruda de la API en modo debug."""
    print(f"\n{Color.YELLOW}{'─'*10} DEBUG: {label} {'─'*10}{Color.RESET}")
    if isinstance(data, dict):
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        print(data)
    print(f"{Color.YELLOW}{'─'*40}{Color.RESET}\n")


# ──────────────────────────────────────────────────────────────────────────────
# Consulta a la API (batch)
# ──────────────────────────────────────────────────────────────────────────────
def query_domains_batch(domains: list[str], api_key: str, debug: bool = False) -> list[dict]:
    """
    Envía hasta BATCH_SIZE dominios en una sola petición POST.
    Devuelve lista de resultados normalizados:
        [{
            "domain":   str,
            "verdict":  int | None,
            "category": str,
            "evidences": list[str],
            "ips":      list[str],
            "error":    str | None,
        }]
    """
    payload  = {"domains": [{"domain": d} for d in domains]}
    headers  = {
        "X-DNS-API-APIKEY": api_key,
        "Content-Type":     "application/json",
    }

    try:
        resp = requests.post(API_ENDPOINT, json=payload, headers=headers, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        if debug:
            print_debug(f"{len(domains)} dominio(s)", data)
    except requests.exceptions.ConnectionError:
        return [_error_result(d, "No se puede conectar con la API") for d in domains]
    except requests.exceptions.Timeout:
        return [_error_result(d, "Tiempo de espera agotado") for d in domains]
    except requests.exceptions.HTTPError as exc:
        msg = f"Error HTTP {exc.response.status_code}"
        return [_error_result(d, msg) for d in domains]
    except Exception as exc:  # noqa: BLE001
        return [_error_result(d, str(exc)) for d in domains]

    if not data.get("success", False):
        msg = data.get("message", "La API devolvió success=false")
        return [_error_result(d, msg) for d in domains]

    results_map: dict[str, dict] = {}
    for item in data.get("results", []):
        results_map[item["domain"]] = _normalize(item)

    # Si algún dominio no viene en la respuesta, lo marcamos como no encontrado
    output = []
    for d in domains:
        if d in results_map:
            output.append(results_map[d])
        else:
            output.append(_error_result(d, "Sin datos en la respuesta"))
    return output


def _error_result(domain: str, msg: str) -> dict:
    return {
        "domain":    domain,
        "verdict":   None,
        "category":  "N/A",
        "evidences": [],
        "ips":       [],
        "error":     msg,
    }


def _normalize(item: dict) -> dict:
    """Extrae y normaliza los campos relevantes de un resultado de la API."""
    # Evidencias más recientes (primera entrada del historial)
    cat_histories = item.get("categoryHistories", [])
    evidences = cat_histories[0].get("evidences", []) if cat_histories else []

    # IPs conocidas (las más recientes, máximo 3)
    ip_histories = item.get("ipHistories", [])
    ips = [h["ip"] for h in ip_histories[:3]]

    return {
        "domain":    item.get("domain", ""),
        "verdict":   item.get("verdict"),
        "category":  item.get("category", "unknown"),
        "evidences": evidences,
        "ips":       ips,
        "error":     None,
    }


def query_all_domains(domains: list[str], api_key: str, debug: bool = False) -> list[dict]:
    """Procesa todos los dominios en lotes y muestra progreso."""
    all_results = []
    total = len(domains)
    batches = [domains[i:i + BATCH_SIZE] for i in range(0, total, BATCH_SIZE)]

    for idx, batch in enumerate(batches, start=1):
        if len(batches) > 1:
            print(
                f"  {Color.YELLOW}→{Color.RESET} "
                f"Lote {idx}/{len(batches)} ({len(batch)} dominios) ...",
                end=" ", flush=True,
            )
        else:
            print(
                f"  {Color.YELLOW}→{Color.RESET} "
                f"Consultando {len(batch)} dominio(s) ...",
                end=" ", flush=True,
            )
        results = query_domains_batch(batch, api_key, debug=debug)
        errors  = sum(1 for r in results if r["error"])
        if errors:
            print(f"{Color.YELLOW}{len(batch) - errors} OK, {errors} error(s){Color.RESET}")
        else:
            print(f"{Color.GREEN}OK{Color.RESET}")
        all_results.extend(results)

    return all_results


# ──────────────────────────────────────────────────────────────────────────────
# Presentación
# ──────────────────────────────────────────────────────────────────────────────
SEPARATOR = "─" * 95

def _category_colored(category: str) -> str:
    color = CATEGORY_COLORS.get(category.lower(), Color.CYAN)
    return f"{color}{category}{Color.RESET}"

def _verdict_colored(verdict) -> str:
    if verdict is None:
        return f"{Color.DIM}N/A{Color.RESET}"
    return VERDICT_LABELS.get(verdict, f"{Color.DIM}{verdict}{Color.RESET}")


def print_table(results: list[dict], title: str = "") -> None:
    if title:
        print(f"\n{Color.BOLD}{Color.HEADER}{title}{Color.RESET}")

    print(SEPARATOR)
    header = f"{'DOMINIO':<40} {'CATEGORÍA':<28} {'VEREDICTO':<14} {'IPs CONOCIDAS'}"
    print(f"{Color.BOLD}{header}{Color.RESET}")
    print(SEPARATOR)

    for r in results:
        if r["error"]:
            print(
                f"{r['domain']:<40} "
                f"{Color.RED}ERROR: {r['error']}{Color.RESET}"
            )
            continue

        ips_str = ", ".join(r["ips"]) if r["ips"] else f"{Color.DIM}—{Color.RESET}"
        print(
            f"{r['domain']:<40} "
            f"{_category_colored(r['category']):<38} "
            f"{_verdict_colored(r['verdict']):<24} "
            f"{ips_str}"
        )

        # Evidencias (sangría)
        if r["evidences"]:
            for ev in r["evidences"]:
                print(f"  {Color.DIM}↳ {ev}{Color.RESET}")

    print(SEPARATOR)


def print_single(r: dict) -> None:
    """Muestra un único resultado con más detalle."""
    print(SEPARATOR)
    if r["error"]:
        print(f"  {Color.RED}ERROR:{Color.RESET} {r['error']}")
        print(SEPARATOR)
        return

    print(f"  {Color.BOLD}Dominio  :{Color.RESET}  {r['domain']}")
    print(f"  {Color.BOLD}Categoría:{Color.RESET}  {_category_colored(r['category'])}")
    print(f"  {Color.BOLD}Veredicto:{Color.RESET}  {_verdict_colored(r['verdict'])}")

    if r["ips"]:
        print(f"  {Color.BOLD}IPs      :{Color.RESET}  {', '.join(r['ips'])}")

    if r["evidences"]:
        print(f"  {Color.BOLD}Evidencias:{Color.RESET}")
        for ev in r["evidences"]:
            print(f"    {Color.DIM}• {ev}{Color.RESET}")

    print(SEPARATOR)


# ──────────────────────────────────────────────────────────────────────────────
# Modos de operación
# ──────────────────────────────────────────────────────────────────────────────
def mode_batch(domains: list[str], api_key: str, debug: bool = False) -> None:
    print(f"\n{Color.BOLD}Procesando {len(domains)} dominio(s)...{Color.RESET}")
    results = query_all_domains(domains, api_key, debug=debug)
    print_table(results, title="Resultado")


def mode_interactive(api_key: str, debug: bool = False) -> None:
    print(
        f"\n{Color.BOLD}{Color.HEADER}"
        "╔══════════════════════════════════════════════╗\n"
        "║  PAN Domain Checker  –  Modo interactivo   ║\n"
        "╚══════════════════════════════════════════════╝"
        f"{Color.RESET}"
    )
    print("  API: DNS Security Threat Vault")
    if debug:
        print(f"  {Color.YELLOW}[DEBUG ACTIVADO]{Color.RESET}")
    print("  Escribe 'salir' o 'exit' para terminar.\n")

    history: list[dict] = []

    while True:
        try:
            domain = input(f"{Color.BOLD}Dominio a consultar:{Color.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if domain.lower() in {"salir", "exit", "quit", "q"}:
            break
        if not domain:
            continue

        results = query_domains_batch([domain], api_key, debug=debug)
        r = results[0]
        history.append(r)
        print_single(r)

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
        description="Consulta información de dominios via Threat Vault DNS Security API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  python pan_domain_checker.py\n"
            "  python pan_domain_checker.py -d malware-site.com\n"
            "  python pan_domain_checker.py -d d1.com -d d2.com\n"
            "  python pan_domain_checker.py -f dominios.txt\n"
        ),
    )
    parser.add_argument(
        "-d", "--domain",
        action="append",
        dest="domains",
        metavar="DOMINIO",
        help="Dominio a consultar (se puede repetir).",
    )
    parser.add_argument(
        "-f", "--file",
        metavar="FICHERO",
        help="Fichero de texto con un dominio por línea.",
    )
    parser.add_argument(
        "-D", "--debug",
        action="store_true",
        default=False,
        help="Muestra la respuesta JSON cruda de la API tras cada petición.",
    )
    return parser.parse_args()


def main() -> None:
    args    = parse_args()
    api_key = load_config()

    domains: list[str] = []

    if args.domains:
        domains.extend(args.domains)

    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                file_domains = [line.strip() for line in fh if line.strip()]
            print(
                f"{Color.GREEN}[INFO]{Color.RESET} "
                f"Leídos {len(file_domains)} dominios desde '{args.file}'."
            )
            domains.extend(file_domains)
        except FileNotFoundError:
            print(f"{Color.RED}[ERROR]{Color.RESET} No se encuentra el fichero '{args.file}'.")
            sys.exit(1)

    if domains:
        # Deduplicar conservando orden
        seen, unique = set(), []
        for d in domains:
            if d not in seen:
                seen.add(d)
                unique.append(d)
        mode_batch(unique, api_key, debug=args.debug)
    else:
        mode_interactive(api_key, debug=args.debug)


if __name__ == "__main__":
    main()
