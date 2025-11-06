
from TrustSocket import ClientTCP

if __name__ == '__main__':
    client = ClientTCP(rsa_key_file=r'config\client_key.pem', ip='127.0.0.1', port=9066)