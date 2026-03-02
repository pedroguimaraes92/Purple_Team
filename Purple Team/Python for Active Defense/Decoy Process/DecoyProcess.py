import signal
import sys
from time import sleep

def terminated(signum, frame):
    """Função chamada quando um sinal de término é recebido."""
    try:
        siginfo = signal.sigwaitinfo({signal.SIGINT, signal.SIGTERM})
        with open("terminated.txt", "w") as f:
            f.write(f"Process terminated by PID {siginfo.si_pid} due to signal {siginfo.si_signo}\n")
        print(f"Received signal {siginfo.si_signo} from process {siginfo.si_pid}, terminating.")
    except Exception as e:
        print(f"Error while writing to file: {e}")
    sys.exit(0)

# Configura o tratamento de sinais SIGTERM e SIGINT
signal.signal(signal.SIGTERM, terminated)
signal.signal(signal.SIGINT, terminated)

# Loop principal aguardando a recepção de sinais
print("Waiting for termination signals (SIGTERM or SIGINT)...")
while True:
    sleep(1)  # Faz o script "dormir" até o sinal ser recebido
