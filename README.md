# 🛡️ Aegis: Zero-Trust Execution Guard for Autonomous AI Agents

## Overview
L'adozione crescente di agenti IA (LLM-based) con capacità di esecuzione autonoma pone sfide di sicurezza critiche. Fornire a un LLM accesso non filtrato al file system locale, a database aziendali o alla rete espone l'infrastruttura a rischi severi, tra cui data exfiltration, esecuzione di codice arbitrario (RCE) e attacchi di tipo *Indirect Prompt Injection*.

Aegis è un prototipo di security sidecar progettato per applicare un modello Zero-Trust alle azioni eseguite da agenti IA autonomi. A differenza degli approcci tradizionali basati sull'analisi euristica del prompt (soggetti a bypass), Aegis opera a livello di runtime, intercettando e filtrando le chiamate di sistema (I/O) prima che l'azione venga effettivamente completata.

## Core Features & Architecture

Il sistema implementa l'isolamento dell'agente attraverso tre moduli principali:

1. **Egress Network Controller (`core/network_guard.py`)**
   Implementa un interception layer tramite *monkey-patching* del modulo `socket` (`socket.create_connection`).
   - Fornisce validazione strict-allowlist (Default-Deny) per il traffico TCP/HTTP in uscita.
   - Previene l'esfiltrazione di dati verso endpoint non autorizzati.

2. **File System Access Supervisor (`core/fs_guard.py`)**
   Agisce tramite overriding della built-in function `open()`.
   - Applica un confinamento logico (Safe Zone/Chroot-like) basato su path resolution (`os.path.commonpath`).
   - Neutralizza tentativi di *Directory Traversal* e applica blocklist basate sull'estensione per proteggere asset sensibili (es. `.env`, `.pem`, file di configurazione).

3. **Telemetry & Observability Pipeline (`app.py` & `core/logger.py`)**
   Garantisce l'osservabilità in tempo reale del comportamento dell'agente.
   - **Audit Logging:** Ogni operazione intercettata (consentita o bloccata) viene registrata in un log strutturato (JSONL) per l'analisi forense.
   - **Real-time Dashboard:** Un'interfaccia sviluppata in Streamlit processa il data stream (tramite Pandas), visualizzando metriche di compromissione, distribuzioni dei target e un audit log interattivo.

## Technology Stack
- **Core Engine:** Python 3 (Runtime hooking, I/O interception)
- **Data Pipeline:** JSONL (Structured logging), Pandas (Data transformation)
- **Visualization:** Streamlit (Real-time dashboarding)

## Quick Start (PoC Setup)

L'ambiente di test dimostra l'efficacia dei security guardrail contro simulazioni di comportamenti anomali da parte dell'agente.

1. **Installazione dipendenze:**
   ```bash
   pip install -r requirements.txt