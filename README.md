# 🛡️ Aegis Guard

Aegis Guard è un Proof of Concept di policy e telemetria per agenti Python. Usa due hook installati tramite monkey patching per registrare e applicare decisioni su specifiche operazioni di I/O nel processo.

La policy si applica alle chiamate che attraversano gli hook mentre sono attivi. Il progetto non fornisce isolamento a livello di sistema operativo, controllo generale del traffico di rete, protezione generale contro l'esfiltrazione o garanzie di integrità del log.

## Architettura

- **Filesystem** (`core/fs_guard.py`) — L'hook su `builtins.open` verifica il percorso rispetto al workspace, applica una blocklist di nomi ed estensioni e blocca l'accesso al percorso del log attraverso l'API intercettata.
- **Rete** (`core/network_guard.py`) — L'hook su `socket.create_connection` confronta il nome host ricevuto con una allowlist.
- **Audit** (`core/logger.py`) — Le decisioni di policy sono registrate in JSONL. `ALLOWED` indica che la policy consente di tentare l'operazione, il cui esito dipende dall'I/O successivo.
- **Dashboard** (`app.py`) — Streamlit e Pandas leggono il JSONL e mostrano i conteggi e i record al caricamento e al refresh manuale.

## Quick Start

I comandi usano PowerShell su Windows e vanno eseguiti dalla radice del repository. Il riepilogo della suite si riferisce a Python 3.13.3.

### Ambiente virtuale e dipendenze

```powershell
python --version
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install -r requirements-test.txt
```

### Test

```powershell
.\.venv\Scripts\python.exe -m pytest
```

Ultima esecuzione riportata su Python 3.13.3: **61 PASS, 10 SKIP, 0 FAIL, 0 XFAIL**. Pytest mostra le motivazioni degli skip a fine esecuzione. Quattro casi con symlink possono essere saltati quando la creazione dei link è indisponibile o non autorizzata. Il caso junction richiede Windows e `cmd.exe`.

Sei casi relativi all'import e al lifecycle della demo richiedono `AEGIS_TEST_AGENT=1`. Questi test usano I/O simulato per le azioni della demo.

```powershell
$env:AEGIS_TEST_AGENT = '1'
.\.venv\Scripts\python.exe -m pytest
Remove-Item Env:AEGIS_TEST_AGENT
```

### Demo e dashboard

**La demo può effettuare richieste HTTP/HTTPS reali e operazioni sul filesystem.** Può aggiungere righe a `aegis_audit.jsonl` e creare o sovrascrivere `temp_report.txt`. Eseguila in una copia locale di prova.

```powershell
.\.venv\Scripts\python.exe test_agent.py
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Avvia demo e dashboard dalla stessa radice del repository. La dashboard legge il log da quella directory. Usa **Refresh Telemetry** per ricaricare i dati quando sono presenti eventi.
