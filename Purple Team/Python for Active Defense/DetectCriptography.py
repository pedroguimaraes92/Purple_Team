import os
import psutil
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

directory_to_monitor = os.path.join(os.getcwd(), "Documents")

class MonitorEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith(".encrypted"):
            print(f"[ALERTA] Arquivo Criptografado Detectado: {event.src_path}")
            os.remove(event.src_path)
            print(f"Arquivo Deletado: {event.src_path}")

def monitor_directory(directory):
    event_handler = MonitorEventHandler()
    observer = Observer()
    observer.schedule(event_handler, directory, recursive=True)
    observer.start()
    print(f"Monitorando alterações em: {directory}")
    return observer

def detect_suspicious_process():
    while True:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = " ".join(proc.info['cmdline'])
                if "Crypto.Cipher" in cmdline:
                    print(f"[ALERTA] Processo Suspeito Detectado: {proc.info['name']} (PID: {proc.info['pid']})")
                    proc.terminate()
                    print(f"Processo {proc.info['name']} Terminado.")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        time.sleep(2)

if __name__ == "__main__":
    observer = monitor_directory(directory_to_monitor)

    try:
        detect_suspicious_process()
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
