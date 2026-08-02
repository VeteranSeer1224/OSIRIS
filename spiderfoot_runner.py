#!/usr/bin/env python3
"""
SpiderFoot Runner for OSIRIS Pipeline

Runs streamlined or customized SpiderFoot scans programmatically
and exports structured JSON results for sense_clean.py.
"""

from __future__ import annotations

import argparse
import json
import logging
import multiprocessing as mp
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable

from artifact_io import atomic_write_json

# Ensure OSIRIS/spiderfoot is in sys.path
_SF_DIR = Path(__file__).resolve().parent / "spiderfoot"
if str(_SF_DIR) not in sys.path:
    sys.path.insert(0, str(_SF_DIR))

_SPIDERFOOT_IMPORT_ERROR: Exception | None = None
try:
    from spiderfoot import SpiderFootDb, SpiderFootHelpers  # type: ignore[attr-defined]
    from spiderfoot.logger import logListenerSetup, logWorkerSetup
    from sflib import SpiderFoot
    from sfscan import startSpiderFootScanner
except Exception as exc:  # third-party import errors can be non-ImportError
    _SPIDERFOOT_IMPORT_ERROR = exc


class SpiderFootUnavailableError(RuntimeError):
    """Raised before collection when the optional SpiderFoot runtime is unusable."""


class SpiderFootScanError(RuntimeError):
    """Raised when a collector run does not reach FINISHED cleanly."""

    def __init__(self, message: str, *, status: str, scan_id: str | None = None):
        super().__init__(message)
        self.status = status
        self.scan_id = scan_id


def require_spiderfoot_runtime() -> None:
    """Fail before any scan when the local optional collector cannot be imported."""
    if _SPIDERFOOT_IMPORT_ERROR is not None:
        raise SpiderFootUnavailableError(
            "SpiderFoot runtime is unavailable; install the pinned collector extras "
            f"and resolve its dependencies before live collection. Root cause: {_SPIDERFOOT_IMPORT_ERROR}"
        ) from _SPIDERFOOT_IMPORT_ERROR

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SFRunner] %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


CUSTOM_USE_CASES = {
    "osiris_fast": [
        "sfp_whois",
        "sfp_dnsresolve",
        "sfp_crt",
        "sfp_sslcert",
        "sfp_pageinfo",
        "sfp_strangeheaders",
    ],
    "osiris_full": [
        "sfp_whois",
        "sfp_dnsresolve",
        "sfp_crt",
        "sfp_sslcert",
        "sfp_pageinfo",
        "sfp_spider",
        "sfp_strangeheaders",
        "sfp_sublist3r",
        "sfp_email",
        "sfp_emailformat",
        "sfp_haveibeenpwned",
        "sfp_shodan",
        "sfp_robtex",
    ],
    "threat_intel": [
        "sfp_abusech",
        "sfp_abuseipdb",
        "sfp_alienvault",
        "sfp_cinsscore",
        "sfp_emergingthreats",
        "sfp_greynoise",
        "sfp_hybrid_analysis",
        "sfp_pulsedive",
        "sfp_threatfox",
        "sfp_virustotal",
    ],
    "infrastructure": [
        "sfp_dnsresolve",
        "sfp_dnsbrute",
        "sfp_dnsgrep",
        "sfp_sublist3r",
        "sfp_crt",
        "sfp_shodan",
        "sfp_censys",
        "sfp_robtex",
        "sfp_portscan_tcp",
        "sfp_bgpview",
        "sfp_arin",
        "sfp_ripe",
    ],
    "identity": [
        "sfp_email",
        "sfp_emailformat",
        "sfp_haveibeenpwned",
        "sfp_hunter",
        "sfp_socialprofiles",
        "sfp_accounts",
        "sfp_keybase",
        "sfp_github",
    ],
    "vulnerabilities": [
        "sfp_tool_nuclei",
        "sfp_tool_retirejs",
        "sfp_tool_wappalyzer",
        "sfp_tool_whatweb",
        "sfp_subdomain_takeover",
        "sfp_openbugbounty",
    ],
}


STREAMLINED_MODULES = {
    "INTERNET_NAME": [
        "sfp_whois",
        "sfp_dnsresolve",
        "sfp_crt",
        "sfp_sslcert",
        "sfp_pageinfo",
        "sfp_spider",
        "sfp_strangeheaders",
        "sfp_sublist3r",
    ],
    "EMAILADDR": [
        "sfp_email",
        "sfp_emailformat",
        "sfp_haveibeenpwned",
        "sfp_hunter",
    ],
    "IP_ADDRESS": [
        "sfp_dnsresolve",
        "sfp_whois",
        "sfp_robtex",
        "sfp_shodan",
    ],
    "IPV6_ADDRESS": [
        "sfp_dnsresolve",
        "sfp_whois",
    ],
}


def _wait_for_scan(
    process: Any,
    dbh: Any,
    scan_id: str,
    *,
    timeout_seconds: float,
    cancel_check: Callable[[], bool] | None,
    status_callback: Callable[[str, str], None] | None,
    poll_interval: float,
) -> str:
    """Monitor a collector process and return only a successful terminal status."""
    deadline = time.monotonic() + float(timeout_seconds)
    terminal_status = "UNKNOWN"
    try:
        while True:
            if cancel_check is not None and cancel_check():
                terminal_status = "CANCELLED"
                dbh.scanInstanceSet(scan_id, status="ABORT-REQUESTED")
                raise SpiderFootScanError(
                    "SpiderFoot scan cancelled by investigator",
                    status=terminal_status, scan_id=scan_id,
                )
            if time.monotonic() >= deadline:
                terminal_status = "TIMEOUT"
                dbh.scanInstanceSet(scan_id, status="ABORT-REQUESTED")
                raise SpiderFootScanError(
                    f"SpiderFoot scan exceeded {timeout_seconds:g} seconds",
                    status=terminal_status, scan_id=scan_id,
                )
            info = dbh.scanInstanceGet(scan_id)
            if info:
                terminal_status = str(info[5])
                if status_callback is not None:
                    status_callback(terminal_status, scan_id)
                if terminal_status in {"ERROR-FAILED", "ABORT-REQUESTED", "ABORTED", "FINISHED"}:
                    break
            elif not process.is_alive() and process.exitcode is not None:
                raise SpiderFootScanError(
                    f"SpiderFoot worker exited unexpectedly with code {process.exitcode}",
                    status="WORKER-EXITED", scan_id=scan_id,
                )
            time.sleep(float(poll_interval))
    except KeyboardInterrupt as exc:
        dbh.scanInstanceSet(scan_id, status="ABORT-REQUESTED")
        raise SpiderFootScanError(
            "SpiderFoot scan interrupted by investigator",
            status="CANCELLED", scan_id=scan_id,
        ) from exc
    if terminal_status != "FINISHED":
        raise SpiderFootScanError(
            f"SpiderFoot scan did not finish successfully: {terminal_status}",
            status=terminal_status, scan_id=scan_id,
        )
    return terminal_status


def run_scan(
    target: str,
    output_file: str | Path,
    modules: str | list[Any] | None = None,
    use_case: str | None = None,
    timeout_seconds: float = 900,
    cancel_check: Callable[[], bool] | None = None,
    status_callback: Callable[[str, str], None] | None = None,
    poll_interval: float = 1.0,
) -> Path:
    require_spiderfoot_runtime()
    if not 1 <= float(timeout_seconds) <= 86_400:
        raise ValueError("timeout_seconds must be between 1 and 86400")
    if not 0.05 <= float(poll_interval) <= 10:
        raise ValueError("poll_interval must be between 0.05 and 10")
    output_file = Path(output_file).resolve()
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Initialize configuration
    sfConfig = {
        '_debug': False,
        '_maxthreads': 3,
        '__logging': True,
        '__outputfilter': None,
        '_useragent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) OSIRIS/1.0',
        '_dnsserver': '',
        '_fetchtimeout': 5,
        '_internettlds': 'https://publicsuffix.org/list/effective_tld_names.dat',
        '_internettlds_cache': 72,
        '_genericusers': "",
        '__database': f"{SpiderFootHelpers.dataPath()}/spiderfoot.db",
        '__modules__': None,
        '__correlationrules__': None,
        '_socks1type': '',
    }

    loggingQueue: mp.Queue[Any] = mp.Queue()
    log_listener = logListenerSetup(loggingQueue, sfConfig)
    logWorkerSetup(loggingQueue)

    mod_dir = str(_SF_DIR / "modules")
    sfModules = SpiderFootHelpers.loadModulesAsDict(mod_dir, ['sfp_template.py'])
    sfConfig['__modules__'] = sfModules

    dbh = SpiderFootDb(sfConfig, init=True)
    sf = SpiderFoot(sfConfig)

    # Detect target type
    clean_target = target.strip('"\'')
    target_type = SpiderFootHelpers.targetTypeFromString(clean_target)
    if not target_type:
        # Fallback heuristic if targetTypeFromString returns None
        if "@" in clean_target:
            target_type = "EMAILADDR"
        elif "." in clean_target:
            target_type = "INTERNET_NAME"
        else:
            raise ValueError(f"Could not determine SpiderFoot target type for: {target}")

    logger.info(f"Target: {clean_target} (Type detected: {target_type})")

    # Determine module list
    modlist = []
    if modules:
        if isinstance(modules, str):
            modlist = [m.strip() for m in modules.split(",") if m.strip()]
        else:
            modlist = list(modules)
    elif use_case:
        uc_key = use_case.lower()
        if uc_key in CUSTOM_USE_CASES:
            logger.info(f"Using custom OSIRIS use case: '{use_case}'")
            modlist = [m for m in CUSTOM_USE_CASES[uc_key] if m in sfModules]
        else:
            uc = use_case.capitalize()
            for mod, mdata in sfModules.items():
                if uc == "All" or uc in mdata.get("group", []):
                    modlist.append(mod)
    else:
        # Default streamlined scan based on target type
        default_mods = STREAMLINED_MODULES.get(target_type, [])
        if default_mods:
            logger.info(f"No modules/use-case specified. Streamlining scan for {target_type} with default modules.")
            modlist = [m for m in default_mods if m in sfModules]
        else:
            logger.info(f"Streamlining scan: enabling modules consuming {target_type}.")
            modlist = sf.modulesConsuming([target_type])

    # Filter out invalid or internal modules
    modlist = [m for m in modlist if m in sfModules and not m.startswith("__")]

    if not modlist:
        raise ValueError("No valid modules enabled for scan.")

    # Storage module is required to write results to SQLite DB
    if "sfp__stor_db" not in modlist:
        modlist.append("sfp__stor_db")

    logger.info(f"Enabled modules ({len(modlist) - 1}): {', '.join([m for m in modlist if m != 'sfp__stor_db'])}")

    cfg = sf.configUnserialize(dbh.configGet(), sfConfig)
    scan_name = clean_target
    scan_id = SpiderFootHelpers.genScanInstanceId()

    logger.info(f"Starting SpiderFoot scan ID: {scan_id}")
    p = mp.Process(
        target=startSpiderFootScanner,
        args=(loggingQueue, scan_name, scan_id, clean_target, target_type, modlist, cfg),
    )
    p.daemon = True
    p.start()

    # Wait for scan completion, fail closed on timeout/cancellation/error, and
    # guarantee that the worker and logging resources do not leak.
    try:
        terminal_status = _wait_for_scan(
            p, dbh, scan_id, timeout_seconds=timeout_seconds,
            cancel_check=cancel_check, status_callback=status_callback,
            poll_interval=poll_interval,
        )
        logger.info("Scan terminal status: %s", terminal_status)
    finally:
        p.join(timeout=5)
        if p.is_alive():
            p.terminate()
            p.join(timeout=5)
        if p.is_alive() and hasattr(p, "kill"):
            p.kill()
            p.join(timeout=5)
        log_listener.stop()
        loggingQueue.close()
        loggingQueue.join_thread()

    # Extract structured results
    rows = dbh.scanResultEvent(scan_id)
    results = []
    for r in rows:
        # r: generated(0), data(1), source_data(2), module(3), type(4), confidence(5),
        #    visibility(6), risk(7), hash(8), source_event_hash(9), event_descr(10), ...
        results.append({
            "generated": r[0],
            "data": r[1],
            "source": r[2] or "",
            "module": r[3],
            "type": r[4],          # raw code e.g. INTERNET_NAME, EMAILADDR
            "type_descr": r[10],   # human readable e.g. Domain Name
            "confidence": r[5],
        })

    atomic_write_json(output_file, results)

    logger.info(f"Exported {len(results)} scan events to {output_file}")
    return output_file


def main():
    parser = argparse.ArgumentParser(description="Run streamlined SpiderFoot scan and export JSON for OSIRIS.")
    parser.add_argument("target_pos", nargs="?", help="Positional target (domain, email, IP)")
    parser.add_argument("output_pos", nargs="?", help="Positional output JSON path")
    parser.add_argument("-s", "--target", help="Target (domain, email, IP)")
    parser.add_argument("-o", "--output", help="Output JSON path")
    parser.add_argument("-m", "--modules", help="Comma-separated modules to run")
    parser.add_argument("-u", "--use-case", help="Use case (osiris_fast, osiris_full, threat_intel, infrastructure, identity, vulnerabilities, footprint, passive, investigate, all)")
    parser.add_argument("--timeout", type=float, default=900, help="Maximum scan duration in seconds")

    args = parser.parse_args()
    target = args.target or args.target_pos
    output = args.output or args.output_pos

    if not target or not output:
        parser.error("Both target and output file must be specified.")

    run_scan(target, output, modules=args.modules, use_case=args.use_case, timeout_seconds=args.timeout)


if __name__ == "__main__":
    main()
