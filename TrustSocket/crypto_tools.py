import os
import json
import time
import base64
import hashlib
from typing import Union
from threading import Thread, Lock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class ClientRSA:
    """
    RSA加密工具类(客户端)
    Args:
        rsa_key_file: RSA密钥文件路径
    """

    def __init__(self, rsa_key_file: str=None):
        if rsa_key_file is None or not os.path.isfile(rsa_key_file):
            raise ValueError("rsa_key_file 不能为空或不是有效的文件")

        self.client_key = self.load_rsa_key(rsa_key_file)

    def load_rsa_key(self, key_file_path: str) -> rsa.RSAPublicKey:
        """
        从文件加载RSA公钥
        Args:
            key_file_path: 密钥文件路径
        Returns:
            公钥数据
        """

        with open(key_file_path, "rb") as f:
            key_data = f.read()

        try:
            key = serialization.load_pem_public_key(key_data)
            print(f"已加载公钥: {key_file_path}")
        except Exception as e:
            raise ValueError(f"加载RSA公钥错误: {e}")

        return key

    def encrypt(self, data: dict) -> bytes:
        """
        使用公钥加密数据
        Args:
            data: 待加密数据
        Returns:
            加密后的数据
        """
        if data is None:
            raise ValueError("data 不能为 None")

        # 序列化数据
        data_bytes = json.dumps(data).encode('utf-8')

        # 检查数据长度
        max_length = (self.client_key.key_size // 8) - 2 * hashes.SHA256.digest_size - 2
        if len(data_bytes) > max_length:
            raise ValueError(f"数据过长，最大支持 {max_length} 字节")

        encrypted_data = self.client_key.encrypt(
            data_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_data

    def verify(self, data: bytes, signature: bytes) -> tuple[bool, Union[dict, None]]:
        """
        使用公钥验证签名
        Args:
            data: 待验证数据
            signature: 签名
        Returns:
            验证结果, 解密后的数据
        """
        if data is None or signature is None:
            raise ValueError("data 和 signature 不能为 None")

        try:
            self.client_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True, json.loads(data.decode('utf-8'))
        except Exception:
            return False, None


class ServerRSA:
    """
    RSA加密工具类(服务端)
    Args:
        rsa_key_file: RSA密钥文件路径
    """

    def __init__(self, rsa_key_file: str=None):
        if rsa_key_file is None or not os.path.isfile(rsa_key_file):
            raise ValueError("rsa_key_file 不能为空或不是有效的文件")

        self.server_key = self.load_rsa_key(rsa_key_file)

    def load_rsa_key(self, key_file_path: str) -> rsa.RSAPrivateKey:
        """
        从文件加载RSA私钥
        Args:
            key_file_path: 密钥文件路径
        Returns:
            私钥数据
        """

        with open(key_file_path, "rb") as f:
            key_data = f.read()

        try:
            key = serialization.load_pem_private_key(key_data, password=None)
            print(f"已加载私钥: {key_file_path}")
        except Exception as e:
            raise ValueError(f"加载RSA私钥错误: {e}")

        return key

    def decrypt(self, data: bytes) -> dict:
        """
        使用私钥解密数据
        Args:
            data: 待解密数据
        Returns:
            解密后的数据
        """
        if data is None:
            raise ValueError("data 不能为 None")

        decrypted_data = self.server_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 反序列化数据
        return json.loads(decrypted_data.decode('utf-8'))

    def sign(self, data: dict) -> tuple[bytes, bytes]:
        """
        使用私钥签名数据
        Args:
            data: 待签名数据
        Returns:
            序列化数据, 签名
        """
        if data is None:
            raise ValueError("data 不能为 None")

        # 序列化数据
        data_bytes = json.dumps(data).encode('utf-8')

        # 生成签名
        signature = self.server_key.sign(
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return data_bytes, signature

    @classmethod
    def generate_key(cls, save_key_dir: str, public_exponent: int=65537, key_size: int=2048) -> str:
        """
        生成RSA密钥对并保存到文件
        Args:
            save_key_dir: 密钥保存目录
            public_exponent: RSA公钥指数
            key_size: 密钥长度
        Returns:
            密钥生成信息
        """
        if not os.path.isdir(save_key_dir):
            raise ValueError(f"{save_key_dir} 不是有效的目录")

        # 生成RSA私钥
        private_key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size,
            backend=default_backend()
        )

        # 获取公钥
        public_key = private_key.public_key()

        # 序列化私钥
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # 序列化公钥
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # 保存密钥文件
        private_key_path = os.path.join(save_key_dir, "server_key.pem")
        public_key_path = os.path.join(save_key_dir, "client_key.pem")
        with open(private_key_path, "wb") as f:
            f.write(private_pem)
        with open(public_key_path, "wb") as f:
            f.write(public_pem)

        info = f"密钥已生成: 私钥 -> {private_key_path}, 公钥 -> {public_key_path}"
        print(info)
        return info


class ClientAES:
    """
    AES加密工具类(客户端)
    Args:
        timeline: 密钥有效期（秒）
    """

    def __init__(self, timeline: int = 3600):
        if not timeline or timeline < 60:
            raise ValueError("密钥有效期不能小于60秒")

        self.generate_key(timeline)

        self.client_key = None
        self.client_key_send = {}

    def generate_key(self, timeline: int=3600) -> None:
        """
        生成AES密钥
        Args:
            timeline: 密钥有效期（秒）
        Returns:
            密钥信息
        """
        if not timeline or timeline < 60:
            raise ValueError("密钥有效期不能小于60秒")

        key = AESGCM.generate_key(bit_length=256)

        self.client_key = key

        self.client_key_send = {
            "key": key.hex(),  # 转换为十六进制字符串便于传输
            "time": time.time(),
            "timeline": timeline
        }
        print(f"客户端密钥已生成: {self.client_key_send}")

    def encrypt(self, data: dict, associated_data: bytes = None) -> bytes:
        """
        加密数据
        Args:
            data: 待加密数据
            associated_data: 关联数据
        Returns:
            加密后的数据
        """
        if not data:
            raise ValueError("data 不能为空")

        # 序列化数据
        data_bytes = json.dumps(data, ensure_ascii=False).encode('utf-8')

        # 加密
        aesgcm = AESGCM(self.client_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data_bytes, associated_data)

        return nonce + ciphertext

    def decrypt(self, encrypted_data: bytes, associated_data: bytes = None) -> dict:
        """
        解密数据
        Args:
            encrypted_data: 待解密数据
            associated_data: 关联数据
        Returns:
            解密后的数据
        """
        if not encrypted_data:
            raise ValueError("encrypted_data 不能为空")

        if len(encrypted_data) < 13:
            raise ValueError("加密数据格式错误")

        # 分离 nonce 和密文
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        # 解密
        aesgcm = AESGCM(self.client_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
        except Exception as e:
            raise ValueError("解密失败: 数据可能被篡改或关联数据不匹配") from e

        # 反序列化
        try:
            return json.loads(plaintext.decode('utf-8'))
        except json.JSONDecodeError as e:
            raise ValueError("解密后的数据格式错误") from e


class ServerAES:
    """
    AES加密工具类(服务端)
    """

    def __init__(self):
        self._lock = Lock()
        self.server_keys = {}  # 服务端密钥: {user_id: {"key": bytes, "time": int, "timeline": int}}
        Thread(target=self._cleanup_expired_keys, daemon=True).start()

    def _cleanup_expired_keys(self) -> None:
        """
        清理过期密钥
        """
        while True:
            time.sleep(60)  # 每分钟检查一次
            current_time = time.time()

            with self._lock:
                expired_users = [
                    user_id for user_id, key_info in self.server_keys.items()
                    if current_time - key_info["time"] > key_info["timeline"]
                ]

                for user_id in expired_users:
                    del self.server_keys[user_id]
                    print(f"服务端已清除过期密钥: {user_id}")

    def update_keys(self, key_info: dict) -> None:
        """
        更新密钥
        Args:
            key_info: 密钥信息
        """
        with self._lock:
            self.server_keys[key_info["user_id"]] = {
                "key": bytes.fromhex(key_info["key"]),  # 从十六进制转换回字节
                "time": key_info["time"],
                "timeline": key_info["timeline"]
            }
        print(f"服务端密钥已更新: {key_info}")

    def encrypt(self, data: dict, user_id: str, associated_data: bytes = None) -> bytes:
        """
        加密数据
        Args:
            data: 待加密数据
            user_id: 用户唯一标识
            associated_data: 关联数据
        Returns:
            加密后的数据
        """
        if not data:
            raise ValueError("data 不能为空")

        with self._lock:
            if user_id not in self.server_keys:
                raise ValueError(f"服务端未找到用户 {user_id} 的密钥")
            key = self.server_keys[user_id]["key"]

        # 序列化数据
        data_bytes = json.dumps(data, ensure_ascii=False).encode('utf-8')

        # 加密
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data_bytes, associated_data)

        return nonce + ciphertext

    def decrypt(self, encrypted_data: bytes, user_id: str, associated_data: bytes = None) -> dict:
        """
        解密数据
        Args:
            encrypted_data: 待解密数据
            user_id: 用户唯一标识
            associated_data: 关联数据
        Returns:
            解密后的数据
        """
        if not encrypted_data:
            raise ValueError("encrypted_data 不能为空")

        if len(encrypted_data) < 13:
            raise ValueError("加密数据格式错误")

        with self._lock:
            if user_id not in self.server_keys:
                raise ValueError(f"服务端未找到用户 {user_id} 的密钥")
            key = self.server_keys[user_id]["key"]

        # 分离 nonce 和密文
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        # 解密
        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
        except Exception as e:
            raise ValueError("解密失败: 数据可能被篡改或关联数据不匹配") from e

        # 反序列化
        try:
            return json.loads(plaintext.decode('utf-8'))
        except json.JSONDecodeError as e:
            raise ValueError("解密后的数据格式错误") from e


class PasswordHash:
    """密码哈希工具类"""

    @classmethod
    def hash_password(cls, password: str, salt: bytes=None,
                       length: int=32, n: int=2**14, r: int=8, p: int=1) -> dict:
        """
        使用 Scrypt 哈希密码

        Args:
            password: 密码
            salt: 盐值
            length: 哈希长度
            n: CPU/内存成本因子
            r: 块大小
            p: 并行化因子
        """
        if salt is None:
            salt = os.urandom(16)

        kdf = Scrypt(
            salt=salt,
            length=length,
            n=n,
            r=r,
            p=p,
            backend=default_backend()
        )

        password_hash = kdf.derive(password.encode('utf-8'))

        return {
            "hash": base64.b64encode(password_hash).decode('utf-8'),
            "salt": base64.b64encode(salt).decode('utf-8'),
            "params": {
                "length": length,
                "n": n,
                "r": r,
                "p": p
            }
        }

    @classmethod
    def verify_password(cls, password: str, stored_info: dict) -> bool:
        """验证密码"""
        try:
            kdf = Scrypt(
                salt=base64.b64decode(stored_info["salt"]),
                length=stored_info["params"]["length"],
                n=stored_info["params"]["n"],
                r=stored_info["params"]["r"],
                p=stored_info["params"]["p"],
                backend=default_backend()
            )

            kdf.verify(
                password.encode('utf-8'),
                base64.b64decode(stored_info["hash"])
            )
            return True
        except Exception:
            return False


class FileHash:
    """文件哈希工具类"""

    @classmethod
    def get_file_hash(cls, file_path: str) -> tuple[bytes, bytes]:
        """
        计算文件哈希值
        Args:
            file_path: 文件路径
        Returns:
            文件数据，文件哈希值
        """
        if not os.path.isfile(file_path):
            raise ValueError(f"{file_path} 不是有效的文件")

        with open(file_path, "rb") as f:
            file_data = f.read()
        return file_data, hashlib.sha256(file_data).hexdigest().encode('utf-8')

    @classmethod
    def verify_file_hash(cls, file_path: str, hash256: bytes) -> bool:
        """
        验证文件哈希值
        Args:
            file_path: 文件路径
            hash256: 文件哈希值
        Returns:
            验证结果
        """
        if not os.path.isfile(file_path):
            raise ValueError(f"{file_path} 不是有效的文件")

        with open(file_path, "rb") as f:
            file_data = f.read()
        return hashlib.sha256(file_data).hexdigest().encode('utf-8') == hash256


