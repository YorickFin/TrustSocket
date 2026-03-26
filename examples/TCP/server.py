
from TrustSocket import ServerTCP


class TestServer:
    def __init__(self):
        self.server = ServerTCP(rsa_key_file=r'config\server_key.pem', ip='127.0.0.1', port=9066)
        self.server.register_event('测试', self.test_event)
        self.server.start()


    def test_event(self, data, client_socket):
        info = {
            'event': '测试',
            'event_name': '客户端您好，这里是服务器',
            'status': True
        }
        _data = self.server.server_aes.encrypt(data['token'], info)
        self.server.send_message(_data, client_socket)

if __name__ == '__main__':
    TestServer()

