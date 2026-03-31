# -*- coding: utf-8 -*-
"""
report_paths.py -- Estrutura centralizada de pastas para resultados.

results/
  <package>/
    apk/          -- APKs baixados do dispositivo
    decompiled/   -- smali, java (saida dos decompiladores)
    static/       -- analise estatica: APKiD, Androguard, MobSFScan, secrets,
                     native scan, beautifest, apk_check, apk_analyzer
    dynamic/      -- analise dinamica: vuln scanner, method tracer,
                     crypto monitor, intent fuzzer, meminfo
    network/      -- traffic monitor, net monitor, logcat
    databases/    -- DB browser
"""
from datetime import datetime
from pathlib import Path

RESULTS_ROOT = Path("results")


def _ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def static_dir(pkg: str) -> Path:
    """Analise estatica — com timestamp unico por sessao."""
    d = RESULTS_ROOT / pkg / "static" / _ts()
    d.mkdir(parents=True, exist_ok=True)
    return d


def dynamic_dir(pkg: str) -> Path:
    """Analise dinamica — com timestamp unico por sessao."""
    d = RESULTS_ROOT / pkg / "dynamic" / _ts()
    d.mkdir(parents=True, exist_ok=True)
    return d


def network_dir(pkg: str) -> Path:
    """Monitores de rede/logcat — sem timestamp (acumula na mesma pasta)."""
    d = RESULTS_ROOT / pkg / "network"
    d.mkdir(parents=True, exist_ok=True)
    return d


def apk_dir(pkg: str) -> Path:
    d = RESULTS_ROOT / pkg / "apk"
    d.mkdir(parents=True, exist_ok=True)
    return d


def decompiled_dir(pkg: str) -> Path:
    d = RESULTS_ROOT / pkg / "decompiled"
    d.mkdir(parents=True, exist_ok=True)
    return d


def databases_dir(pkg: str) -> Path:
    d = RESULTS_ROOT / pkg / "databases"
    d.mkdir(parents=True, exist_ok=True)
    return d
