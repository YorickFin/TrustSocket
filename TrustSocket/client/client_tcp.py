
import time
from threading import Thread, Lock
from socket import socket, AF_INET, SOCK_STREAM

from ..crypto_tools import ClientRSA, ClientAES, FileHash
from ..constants import MESSAGE_HEAD_RSA, MESSAGE_HEAD_AES, MESSAGE_END

class ClientTCP:
    """
    客户端TCP类
    Args:
        rsa_key_file: RSA私钥文件路径
        ip: 服务器IP地址
        port: 服务器端口号
        buflen: 缓冲区大小
    """

    def __init__(self, rsa_key_file: str, ip: str, port: int, buflen: int=4096):

        self.ip = ip
        self.port = port
        self.buflen = buflen

        self._lock = Lock()

        self.client_rsa = ClientRSA(rsa_key_file)
        self.client_aes = ClientAES()

        Thread(target=self._update_aes_key).start()  # 启动密钥更新线程

    def _update_aes_key(self) -> None:
        """更新AES密钥"""
        MAX_RETRIES = 5  # 最大重试次数

        while True:
            current_time = int(time.time())

            with self._lock:
                client_key = self.client_aes.client_key
                needs_key_update = (
                    client_key is None or
                    current_time - client_key["time"] > client_key["timeline"] - 30
                )
                if needs_key_update:
                    retry_count = 0  # 重试次数
                    success = False  # 是否成功
                    last_error = None  # 最后一次错误信息
                    timeline = 300 if client_key is None else 3600  # 密钥有效期

                    while retry_count < MAX_RETRIES and not success:
                        try:
                            if retry_count > 0:
                                print(f"第 {retry_count} 次重试更新AES密钥...")
                                time.sleep(5)  # 等待5秒后重试

                            # 生成新的密钥
                            result = self.client_aes.generate_key(timeline=timeline)
                            key_info = {
                                "event": "update_aes_key",
                                "key": result["key"].hex(),
                                "time": result["time"],
                                "timeline": result["timeline"]
                            }

                            encrypted_data = self.client_rsa.encrypt(key_info)  # RSA加密AES密钥信息
                            return_info = self.send_message(encrypted_data)  # 发送消息

                            if return_info["event"] == "update_aes_key" and return_info["status"]:
                                # 更新AES密钥
                                self.client_aes.token = return_info["token"].encode('utf-8')
                                self.client_aes.client_key = {
                                    "key": result["key"],
                                    "time": result["time"],
                                    "timeline": result["timeline"]
                                }
                                print("AES密钥更新成功")
                                success = self._test_aes_key()  # 测试AES密钥
                            else:
                                raise Exception(f"更新AES密钥失败：{return_info}")
                        except Exception as e:
                            retry_count += 1
                            last_error = e
                            print(f"AES密钥更新失败 (尝试 {retry_count}/{MAX_RETRIES}): {e}")

                    # 重试次数达到上限
                    if not success:
                        raise Exception(f"更新AES密钥失败，已重试{MAX_RETRIES}次: {last_error}")
            time.sleep(60)  # 每分钟检查一次

    def _test_aes_key(self) -> bool:
        """测试AES密钥"""
        # with self._lock:
        info = {
            "event": "test_aes_key"
        }
        encrypted_data = self.client_aes.encrypt(info)  # AES 加密测试信息
        return_info = self.send_message(encrypted_data)  # 发送消息
        if return_info["event"] == "test_aes_key" and return_info["status"]:
            print("AES密钥测试成功")
            return True
        else:
            print("AES密钥测试失败")
            return False

    def send_message(self, data: bytes) -> dict:
        """发送消息"""

        with socket(AF_INET, SOCK_STREAM) as client_socket:
            client_socket.connect((self.ip, self.port))
            client_socket.sendall(data)  # 发送数据

            # 接收数据
            recved_data = b''
            while True:
                recved = client_socket.recv(self.buflen)
                if not recved:
                    break
                recved_data += recved
                if MESSAGE_END in recved_data:
                    break

            # 解析数据
            head_data = recved_data[:len(MESSAGE_HEAD_RSA)]
            if head_data == MESSAGE_HEAD_RSA:
                # 验证RSA签名
                verify_result, data = self.client_rsa.verify(recved_data)
                if verify_result:
                    return data
                raise Exception("消息签名验证失败, 请检查密钥是否正确，或联系管理员")
            elif head_data == MESSAGE_HEAD_AES:
                # 解密数据
                data = self.client_aes.decrypt(recved_data)
                return data
            else:
                raise Exception("未知消息类型")

    def send_file(self, file_data: str) -> None:
        """发送文件(AES加密)"""

    def recv_file(self, file_path: str) -> None:
        """接收文件(AES加密)"""

