import os
import argparse
import logging
import winreg

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("reg_autorun.log"),
        logging.StreamHandler()
    ]
)

def set_autorun_registry(name, path, regkey, dry_run=False):
    """Adiciona uma chave de autorun ao registro do Windows."""
    try:
        # Escolhendo o hive (HKCU ou HKLM)
        reghive = winreg.HKEY_CURRENT_USER if regkey < 2 else winreg.HKEY_LOCAL_MACHINE
        
        # Escolhendo a subchave (Run ou RunOnce)
        regpath = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run" if regkey % 2 == 0 else r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"

        if dry_run:
            logging.info(f"[DRY-RUN] Simulando configuração de chave '{name}' com valor '{path}' em {regpath}.")
            return True

        # Abrindo e configurando o registro
        with winreg.ConnectRegistry(None, reghive) as reg:
            with winreg.OpenKey(reg, regpath, 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, path)
                logging.info(f"Chave de autorun '{name}' configurada com sucesso em {regpath}.")
        return True
    except PermissionError:
        logging.error("Permissões insuficientes para modificar o registro. Execute como administrador.")
        return False
    except Exception as e:
        logging.error(f"Erro ao configurar o registro: {e}")
        return False

def remove_autorun_registry(name, regkey, dry_run=False):
    """Remove uma chave de autorun do registro do Windows."""
    try:
        # Escolhendo o hive (HKCU ou HKLM)
        reghive = winreg.HKEY_CURRENT_USER if regkey < 2 else winreg.HKEY_LOCAL_MACHINE
        
        # Escolhendo a subchave (Run ou RunOnce)
        regpath = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run" if regkey % 2 == 0 else r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"

        if dry_run:
            logging.info(f"[DRY-RUN] Simulando remoção de chave '{name}' de {regpath}.")
            return True

        # Abrindo e removendo a chave
        with winreg.ConnectRegistry(None, reghive) as reg:
            with winreg.OpenKey(reg, regpath, 0, winreg.KEY_WRITE) as key:
                winreg.DeleteValue(key, name)
                logging.info(f"Chave de autorun '{name}' removida com sucesso de {regpath}.")
        return True
    except FileNotFoundError:
        logging.warning(f"A chave '{name}' não foi encontrada em {regpath}.")
        return False
    except PermissionError:
        logging.error("Permissões insuficientes para modificar o registro. Execute como administrador.")
        return False
    except Exception as e:
        logging.error(f"Erro ao remover chave do registro: {e}")
        return False

def main(args):
    """Função principal."""
    if args.action == "add":
        set_autorun_registry(args.name, args.path, args.regkey, args.dry_run)
    elif args.action == "remove":
        remove_autorun_registry(args.name, args.regkey, args.dry_run)
    else:
        logging.error("Ação inválida. Use 'add' para adicionar ou 'remove' para remover.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gerenciador avançado de autorun no registro do Windows.")
    parser.add_argument("action", choices=["add", "remove"], help="Ação a ser executada: 'add' para adicionar ou 'remove' para remover.")
    parser.add_argument("--name", required=True, help="Nome da chave no registro.")
    parser.add_argument("--path", help="Caminho do executável para 'add'. Necessário para adicionar uma chave.")
    parser.add_argument("--regkey", type=int, default=1, help="Chave de registro: 1=HKCU RunOnce, 2=HKCU Run, 3=HKLM RunOnce, 4=HKLM Run.")
    parser.add_argument("--dry-run", action="store_true", help="Simula as ações sem realizar alterações.")
    
    args = parser.parse_args()
    
    # Validações básicas
    if args.action == "add" and not args.path:
        logging.error("Ação 'add' requer o parâmetro '--path'.")
    else:
        main(args)
