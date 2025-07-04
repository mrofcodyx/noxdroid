<h1 align="center">
🐾 NoxDroid – Android Security Toolkit
</h1>
<p align="center"><img src="https://github.com/user-attachments/assets/b17ff714-ff09-46e6-bdf4-c9382911ed4f" width="600"/></p>

**NoxDroid** é uma poderosa toolkit para pentesters que utilizam o emulador **Nox Player** como ambiente de testes Android. Inspirado em projetos como [Noxer](https://github.com/AggressiveUser/noxer/) e [BrutDroid](https://github.com/Brut-Security/BrutDroid/), o **NoxDroid** unifica, automatiza e expande funcionalidades essenciais para análise estática e dinâmica de aplicativos Android.

---

## ✨ Recursos Principais

- 📱 **Frida Tools Menu** com suporte a múltiplos scripts de bypass (SSL Pinning, Root Detect, Emulador Dectect)
- 🧪 Instalação automática do **MaFrida** via Magisk (para rodar Frida de forma invisível e confiável)
- 🔐 Configuração automática de certificados Burp Suite com suporte ao módulo **AlwaysTrustUserCerts**
- 🛠️ Instalação de módulos como **Frida**, **Magisk**, **Kitsune Mask**, com checagens automatizadas
- 🌙 Compatível com Nox Player 7.x + Kitsune Mask Delta (Zygisk/Magisk para x86_64)

---

## 🚀 Como funciona?

O NoxDroid foi criado para rodar diretamente no seu host (Windows), integrando via `adb` com o emulador Nox (rooted). Ele automatiza tarefas como:

1. Verificação de ambiente e dependências
2. Instalação de módulos via `magisk`
3. Upload e instalação de certificados CA
4. Configuração automatizada do Mafrida
5. Execução de ferramentas ofensivas como Frida scripts personalizados

O uso é simplificado por menus interativos e comandos de linha de forma elegante e clara.

---

## 🧠 Por que [Kitsune Magisk](https://github.com/1q23lyc45/KitsuneMagisk/) e [Mafrida](https://github.com/theShinigami/MaFrida/) são importantes?

- **Kitsune Mask Delta** é uma modificação do Magisk que permite root no Nox Player sem bootloop ou instabilidade. Ele suporta **Zygisk**, **Magisk Modules** e facilita a integração com ferramentas de segurança.

- **MaFrida** é um módulo alternativo ao tradicional Magisk Frida, capaz de baixar e gerenciar automaticamente diferentes versões do `frida-server`, com suporte a auto-start no boot. Isso garante que o Frida funcione mesmo em ambientes mais restritivos.
---

## 🛠️ Requisitos

- 🐍 **Python 3.9+**
- 🌍 **Conexão com a Internet**
- 🌐 **Burp Suite** para configuração do certificado.
- 📱 **ADB** do Nox Player corretamente configurado no PATH
- 🖥️ **Nox Player v7.x** instalado com acesso root recomendado **Android 9+**

---

## ⚡ Instalação

### 1. Clone o Repositório:
```bash
git clone https://github.com/mrofcodyx/noxdroid.git
cd noxdroid
```

### 2. Instale as Dependências:
```bash
python -m pip install -r requirements.txt
```

### 3. Execute o NoxDroid:
```bash
python -m main
```

---

## 📜 Créditos e Inspirações

Este projeto foi fortemente inspirado nos seguintes projetos:

- 🎯 [**Noxer**](https://github.com/AggressiveUser/noxer/) – por [**AggressiveUser**](https://github.com/AggressiveUser)
- 🧨 [**BrutDroid**](https://github.com/Brut-Security/BrutDroid/) – por [**Brut-Security**](https://github.com/Brut-Security)

 Agradecimentos especiais a ambos os autores pela contribuição valiosa à comunidade de segurança Android. O NoxDroid foi desenvolvido com o propósito de expandir essas ideias e torná-las ainda mais automatizadas e modulares.

---
## 📬 Contato

Sinta-se à vontade para contribuir, abrir *issues* ou sugerir melhorias.  
Este projeto é feito com 💙 por um entusiasta de segurança ofensiva.
