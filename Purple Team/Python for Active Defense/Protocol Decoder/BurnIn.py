import random, requests
from time import sleep

def makeRequest(url):
    try:
        response = requests.get(url)
        # Se necessário, pode-se processar a resposta aqui
        print(f"Requested URL: {url} Status Code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error with URL {url}: {e}")

def getURL():
    return sites[random.randint(0, len(sites)-1)].rstrip()

clickthrough = 0.5
sleeptime = 1  # Pode ser ajustado conforme necessário

def browsingSession():
    while random.random() < clickthrough:
        url = getURL()
        makeRequest(url)
        sleep(random.uniform(0, sleeptime))  # Usando uniform para tempos mais variados

try:
    with open("sites.txt", "r") as f:
        sites = f.readlines()
    browsingSession()
except FileNotFoundError:
    print("Error: The file 'sites.txt' was not found.")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
