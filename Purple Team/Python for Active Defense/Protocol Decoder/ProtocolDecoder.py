import re
from scapy.all import *
from scapy.layers.http import *
from base64 import b64decode

b64regex = b"[A-Za-z0-9+/=]+"

def extractData(data):    
    data = data.rstrip()
    matches = re.findall(b64regex, data)
    for match in matches:
        if len(match) == 0:
            continue
        try:
            # Verifica e corrige padding de base64
            if not len(match) % 4 == 0:
                padnum = (4 - len(match) % 4) % 4
                match += b"=" * padnum
            decoded = b64decode(match).decode("utf-8")
            if len(decoded) > 5 and decoded.isprintable():
                print("Decoded: %s" % decoded)
        except Exception as e:
            print(f"Error decoding Base64: {e}")
            continue

def extractHTTP(p):
    fields = None
    if p.haslayer(HTTPRequest):
        fields = p[HTTPRequest].fields
    else:
        fields = p[HTTPResponse].fields
    for f in fields:
        data = fields[f]
        if isinstance(data, str):
            extractData(data)
        elif isinstance(data, dict):
            for d in data:
                extractData(data[d])
        elif isinstance(data, list) or isinstance(data, tuple):
            for d in data:
                extractData(d)

def extractRaw(p):
    if p.haslayer(Raw):
        extractData(p[Raw].load)

def analyzePackets(p):
    if p.haslayer(HTTPRequest) or p.haslayer(HTTPResponse):
        p.show()
        extractHTTP(p)
    elif p.haslayer(Raw):
        extractRaw(p)

# Inicia a captura de pacotes com filtragem para HTTP (porta 80 ou 443)
sniff(prn=analyzePackets, filter="tcp port 80 or tcp port 443")
