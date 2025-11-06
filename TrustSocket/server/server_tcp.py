
import time
from threading import Thread, Lock
from socket import socket, AF_INET, SOCK_STREAM

from ..crypto_tools import ServerRSA, ServerAES, FileHash
from ..constants import MESSAGE_HEAD_RSA, MESSAGE_HEAD_AES, MESSAGE_END

class ServerTCP:

    def __init__(self, rsa_key_file: str, host: str, port: int, buflen: int=4096):
        self.host = host
        self.port = port
        self.buflen = buflen

        self._event_dict = {}
        self.register_event('update_aes_key', self._update_aes_key)
        self.register_event('test_aes_key', self._test_aes_key)

        self.server_rsa = ServerRSA(rsa_key_file)
        self.server_aes = ServerAES()

    def register_event(self, event_name: str, func):
        """注册事件"""
        self._event_dict[event_name] = func

    def unregister_event(self, event_name: str):
        """注销事件"""
        if event_name in self._event_dict:
            del self._event_dict[event_name]

    def trigger_event(self, event_name: str, data: dict, client_socket):
        """触发事件"""
        if event_name in self._event_dict:
            self._event_dict[event_name](data, client_socket)
        else:
            raise ValueError(f"事件 {event_name} 不存在")

    def _update_aes_key(self, data: dict, client_socket):
        """更新AES密钥"""
        token = self.server_aes.update_keys(data)
        sign_data = self.server_rsa.sign({'event': 'update_aes_key', 'token': token, 'status': True})
        self.send_message(client_socket, sign_data)

    def _test_aes_key(self, data: dict, client_socket):
        """测试AES密钥"""
        encrypted_data = self.server_aes.encrypt(data['token'], {'event': 'test_aes_key', 'status': True})
        self.send_message(client_socket, encrypted_data)

    def start(self):
        """启动服务"""
        with socket(AF_INET, SOCK_STREAM) as server_socket:
            server_socket.bind((self.host, self.port))
            server_socket.listen()
            print(f"服务启动在：{self.host}:{self.port}")
            while True:
                client_socket, address = server_socket.accept()
                print(f"来自客户端 {address} 的连接")
                Thread(target=self.handle_client, args=(client_socket, address)).start()

    def handle_client(self, client_socket, address):
        """处理客户端请求"""
        try:
            with client_socket:
                # 接收数据
                recved_data = b''
                while True:
                    recved = client_socket.recv(self.buflen)
                    if not recved:
                        break
                    recved_data += recved
                    if MESSAGE_END in recved_data:
                        break

                # 解密数据
                head_data = recved_data[:len(MESSAGE_HEAD_RSA)]
                if head_data == MESSAGE_HEAD_RSA:
                    data = self.server_rsa.decrypt(recved_data)
                elif head_data == MESSAGE_HEAD_AES:
                    data = self.server_aes.decrypt(recved_data)
                else:
                    print(f"客户端 {address} 发送了非法数据")
                    return
                print(f"客户端 {address} 发送的数据：{data}")
                self.trigger_event(data['event'], data, client_socket)
        except Exception as e:
            print(f"客户端 {address} 连接异常：{e}")
            return

    def send_message(self, client_socket, data: bytes):
        """发送消息"""
        client_socket.sendall(data)