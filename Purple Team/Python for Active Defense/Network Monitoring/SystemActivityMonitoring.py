import win32evtlog
from collections import defaultdict

server = "localhost"
logtype = "Security"
flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

# Usando defaultdict para simplificar a contagem
failures = defaultdict(int)

def checkEvents():
    try:
        # Abrindo o log de eventos
        h = win32evtlog.OpenEventLog(server, logtype)
        while True:
            events = win32evtlog.ReadEventLog(h, flags, 0)
            if events:
                for event in events:
                    # Verifica se o evento corresponde a uma falha de login (EventID 4625)
                    if event.EventID == 4625:
                        # Extraímos a conta de usuário da stringInserts (campo que contém detalhes do evento)
                        if event.StringInserts and event.StringInserts[0].startswith("S-1-5-21"):
                            account = event.StringInserts[1]
                            # Incrementa a contagem de falhas para o usuário
                            failures[account] += 1
            else:
                break
    except Exception as e:
        print(f"Erro ao ler o log de eventos: {e}")

# Inicia a checagem de eventos
checkEvents()

# Exibe os resultados
if failures:
    print("Falhas de login por conta:")
    for account, count in failures.items():
        print(f"{account}: {count} falhas de login")
else:
    print("Nenhuma falha de login encontrada.")
