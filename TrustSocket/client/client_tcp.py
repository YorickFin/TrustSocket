
import time
from threading import Thread, Lock, Event
from socket import socket, AF_INET, SOCK_STREAM

from ..crypto_tools import ClientRSA, ClientAES
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
        self._aes_key_ready = Event()  # 用于指示AES密钥是否已更新完成

        self.client_rsa = ClientRSA(rsa_key_file)
        self.client_aes = ClientAES()

        # 启动密钥更新线程
        key_update_thread = Thread(target=self._update_aes_key)
        key_update_thread.daemon = True
        key_update_thread.start()

        # 等待AES密钥更新完成
        self._aes_key_ready.wait()
        print("ClientTCP初始化完成，AES密钥已更新")

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
                            new_key = self.client_aes.generate_key(timeline=timeline)
                            key_info = {
                                "event": "update_aes_key",
                                "key": new_key["key"].hex(),
                                "time": new_key["time"],
                                "timeline": new_key["timeline"]
                            }

                            encrypted_data = self.client_rsa.encrypt(key_info)  # RSA加密AES密钥信息
                            result = self.send_message(encrypted_data)  # 发送消息

                            if result["event"] == "update_aes_key" and result["status"]:
                                # 更新AES密钥
                                self.client_aes.token = result["token"].encode('utf-8')
                                self.client_aes.client_key = {
                                    "key": new_key["key"],
                                    "time": new_key["time"],
                                    "timeline": new_key["timeline"]
                                }
                                print("AES密钥更新成功")
                                success = self._test_aes_key()  # 测试AES密钥
                                if success:
                                    self._aes_key_ready.set()  # 标记AES密钥已准备就绪
                            else:
                                raise Exception(f"更新AES密钥失败：{result}")
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
        result = self.send_message(encrypted_data)  # 发送消息
        if result["event"] == "test_aes_key" and result["status"]:
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
                verify, data = self.client_rsa.verify(recved_data)
                if verify:
                    return data
                raise Exception("消息签名验证失败, 请检查密钥是否正确，或联系管理员")
            elif head_data == MESSAGE_HEAD_AES:
                # 解密数据
                data = self.client_aes.decrypt(recved_data)
                return data
            else:
                raise Exception("未知消息类型")

