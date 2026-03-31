<div align="center">

```
  [:: NoxDroid ::]
    (\_/)
   ( •ᴗ•)  Android Pentest Toolkit
   />🍃    by Mr_ofcodyx
```

# NoxDroid

**Android security toolkit — análise estática, dinâmica, bypass e interceptação em um único menu.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?style=flat-square&logo=windows)](https://www.microsoft.com/windows)
[![Frida](https://img.shields.io/badge/Frida-latest-orange?style=flat-square)](https://frida.re)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

</div>

---

## O que é

NoxDroid é uma toolkit de pentest Android para Windows. Funciona tanto com o **Nox Player** quanto com **dispositivos físicos** via ADB — detecta automaticamente o que está conectado e adapta o menu.

Automatiza desde a configuração do ambiente (Magisk, Frida, certificados CA) até análise estática e dinâmica de APKs, tudo via menus interativos no terminal.

---

## Funcionalidades

**Setup**
- Instalação do Kitsune Mask (Magisk para Nox Player)
- Setup completo: MaFrida + Zygisk-Assistant + AlwaysTrustUserCerts + Certificado CA
- Certificado CA (Burp Suite / mitmproxy / custom) com push automático via ADB

**Análise Estática**
- Análise completa de APK (SSL pinning, root detection, anti-debug, crypto, WebView, injection)
- APK Check — proteções, root, emulador, debug, proxy, SDKs
- Secrets Finder — API keys, tokens, credenciais em código (relatório HTML)
- APKLeaks — URIs, endpoints e secrets via regex
- Native Scanner — analisa `.so`: RCE, secrets, JNI, URLs
- APKiD — identifica compiladores, packers, obfuscators
- Androguard — análise profunda: permissões, APIs, componentes, certificado
- MobSFScan — análise de código fonte Java/Kotlin/XML
- AndroidBeautifest — componentes exportados, deep links, comandos ADB
- jadx-gui — decompilador visual

**Análise Dinâmica**
- Vuln Scanner — testa componentes, providers, intents, logs via ADB (inspirado no Drozer)
- Intent Fuzzer — fuzzing manual de intents em componentes exportados
- Objection — hooking, memory, filesystem, bypass
- Frida Tools — menu completo com scripts organizados por categoria
- Traffic Monitor — captura HTTP/HTTPS em tempo real
- Crypto Monitor — intercepta Cipher, Mac, MessageDigest via Frida
- Network Connections — conexões TCP/UDP ativas via `/proc/net`
- Method Tracer — rastreia chamadas Java via Frida Stalker

**Interceptação**
- Proxy Switch — detecta IP local automaticamente, configura Burp/mitmproxy/custom no dispositivo
- Certificado CA — push e guia de instalação manual

**Dispositivo**
- ADB Shell interativo com root e autocomplete
- Magisk Monitor — logs em tempo real
- DB Browser — navega bancos SQLite do dispositivo
- File Browser — navega sistema de arquivos com detecção SQLite/binário/texto

**Relatórios**
- Viewer integrado — navega e abre todos os relatórios gerados organizados por package e categoria

---

## Requisitos

- Windows 10/11
- Python 3.10+
- Nox Player 7.x **ou** dispositivo Android físico com ADB habilitado
- Conexão com a internet (dependências e ferramentas são baixadas automaticamente)

> O NoxDroid instala e atualiza automaticamente todas as dependências Python e ferramentas externas (jadx, apktool, APKEditor, DB Browser, JDK 21) na primeira execução.

---

## Instalação

```bash
git clone https://github.com/mrofcodyx/noxdroid.git
cd noxdroid
pip install -r requirements.txt
python main.py
```

Na primeira execução o NoxDroid:
1. Verifica e instala todas as dependências Python
2. Baixa e configura as ferramentas externas em `tools/`
3. Detecta automaticamente o dispositivo conectado (Nox, emulador ou físico)
4. Executa debloat inicial (apenas Nox Player)

---

## Estrutura

```
noxdroid/
├── main.py                    # Entry point — menus principais
├── requirements.txt
├── core/
│   ├── banner.py              # Banner, termos de uso, créditos
│   ├── deps.py                # Gerenciador de dependências e ferramentas externas
│   ├── env_check.py           # Verificação de ambiente e inicialização
│   ├── device_detect.py       # Detecção automática de dispositivo (Nox/emulador/físico)
│   ├── adb_guard.py           # Guard centralizado de conexão ADB
│   └── report_paths.py        # Estrutura centralizada de pastas de resultados
├── modules/
│   ├── frida_tools.py         # Menu Frida com 3 níveis de navegação
│   ├── apk_analyzer.py        # Análise completa de APK
│   ├── apk_check.py           # Verificação de proteções
│   ├── secrets_finder.py      # Busca de secrets em código
│   ├── vuln_scanner.py        # Scanner de vulnerabilidades dinâmico
│   ├── intent_fuzzer.py       # Fuzzer de intents manual
│   ├── results_viewer.py      # Visualizador de relatórios
│   ├── objection_menu.py      # Menu Objection
│   ├── beautifest.py          # AndroidBeautifest
│   ├── androguard_analyzer.py
│   ├── apkid_analyzer.py
│   ├── mobsfscan_analyzer.py
│   ├── native_scanner.py
│   ├── method_tracer.py
│   ├── proxy_switch.py
│   ├── cert_setup.py
│   ├── db_browser.py
│   ├── _file_browser.py
│   ├── _logcat_monitor.py
│   ├── _net_monitor.py
│   ├── _traffic_monitor.py
│   ├── adb_shell.py
│   ├── magisk_modules.py
│   ├── magisk_monitor.py
│   ├── frida_magisk.py
│   ├── kitsune.py
│   ├── debloat.py
│   └── pkg_picker.py
├── Fripts/
│   ├── stack.js               # Stack trace helper (injetado automaticamente)
│   ├── Bypass/                # SSL pinning, root, biometric, screen, all-in-one
│   ├── Recon/                 # Network, crypto, hooking, enum, vuln inspector
│   └── Unity/                 # Il2Cpp enum e field modifier
├── tools/                     # Ferramentas externas (gerenciadas automaticamente)
└── utils/
    └── common.py
```

---

## Frida Scripts incluídos

| Categoria | Scripts |
|-----------|---------|
| Bypass / SSL Pinning | `basic_sslpinning`, `bypass_sslpinning`, `okhttp3_bypass`, `ssl_bypass_conscrypt`, `trustmanager_bypass`, `flutter_tls_bypass` |
| Bypass / Root | `rootdetec`, `antiRoot_1`, `antiRoot_2`, `rootBeerBypass`, `cordova_root_bypass` |
| Bypass / Outros | `biometricBypass`, `developer_mode_bypass`, `Remove_flag_secure` |
| All-in-One | `noxdroid_priv` — root + native + ADB + emulator + keystore + SSL + HTTP + screen |
| Recon / Network | `url_interceptor`, `logs` |
| Recon / Crypto | `keystore_spy`, `crypto_monitor`, `frida_crypto_hooks`, `hook_AESDESRSA`, `dumpSqlcipher`, `earlyInstr_Sqlcipher` |
| Recon / Enum | `listClass`, `listClass2`, `listClassAndMethods`, `listMethodsAndProps` |
| Recon / Hooking | `hookCipher`, `strcmpHook`, `hook_RegisterNatives`, `interceptingMethods`, `changingValuesMethods` |
| Recon / Vuln | `webview_inspector`, `intent_inspector`, `ui_security_inspector`, `gps_spoof` |
| Unity | `discover`, `fieldModifier-GENERIC`, `writeScore-example` |

---

## Aviso Legal

Esta ferramenta foi desenvolvida **exclusivamente para fins de segurança ofensiva, pesquisa e testes de penetração autorizados**.

O uso não autorizado pode constituir crime (Lei nº 12.737/2012 e equivalentes internacionais).
Os autores não se responsabilizam por danos ou consequências legais decorrentes do uso indevido.

**Use com responsabilidade. Hack ético. Respeite a lei.**

---

## Créditos

| Contribuição | Autor |
|---|---|
| Criador & Desenvolvedor Principal | [Mr_ofcodyx](https://github.com/mrofcodyx) |
| Frida Scripts (root/ssl bypass) | [lautarovculic](https://github.com/lautarovculic) |
| AndroidBeautifest | [lautarovculic](https://github.com/lautarovculic/androidBeautifest) |
| Frida Crypto Hooks | [Magpol (MiscFrida)](https://github.com/Magpol/MiscFrida) |
| Root Bypass (base) | Daniele Linguaglossa, Simone Quatrini |
| Androguard | [androguard-project](https://github.com/androguard/androguard) |
| APKiD | [rednaga](https://github.com/rednaga/APKiD) |
| APKLeaks | [dwisiswant0](https://github.com/dwisiswant0/apkleaks) |
| MobSFScan | [MobSF Project](https://github.com/MobSF/mobsfscan) |
| Kitsune Mask | [1q23lyc45](https://github.com/1q23lyc45/KitsuneMagisk) |
| MaFrida | [theShinigami](https://github.com/theShinigami/MaFrida) |

---

<div align="center">
  Feito com 💙 por <a href="https://github.com/mrofcodyx/noxdroid">Mr_ofcodyx</a>
</div>
