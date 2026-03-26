
from TrustSocket import ClientTCP

class TestClient:
    def __init__(self):
        self.client = ClientTCP(rsa_key_file=r'config\client_key.pem', ip='127.0.0.1', port=9066)
        self.test_event()

    def test_event(self):
        info = {
            'event': '测试',
            'event_name': '服务器您好，这里是客户端'
        }
        _data = self.client.client_aes.encrypt(info)
        result = self.client.send_message(_data)
        print(result)

if __name__ == '__main__':
    TestClient()
