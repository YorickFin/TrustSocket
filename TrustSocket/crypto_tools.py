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

class CryptoRSA:
    """
    RSA加密工具类

    Args:
        key_file: 现有密钥文件路径
        save_key_dir: 新生成密钥的保存目录
        public_exponent: RSA公钥指数
        key_size: 密钥长度
    """

    def __init__(self, key_file: str=None, save_key_dir: str=None, public_exponent: int=65537, key_size: int=2048):

        self.RSA_KEY = None

        if key_file:
            self.load_rsa_key(key_file)
        elif save_key_dir:
            self.generate_rsa_key(save_key_dir, public_exponent, key_size)
        else:
            raise ValueError("必须提供 key_file 或 save_key_dir 参数")

    def generate_rsa_key(self, save_key_dir: str, public_exponent: int=65537, key_size: int=2048) -> None:
        """生成RSA密钥对并保存到文件"""

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

        print(f"密钥已生成: 私钥 -> {private_key_path}, 公钥 -> {public_key_path}")

    def load_rsa_key(self, key_file_path: str) -> None:
        """从文件加载RSA密钥"""

        if not os.path.isfile(key_file_path):
            raise ValueError(f"{key_file_path} 不是有效的文件")

        with open(key_file_path, "rb") as f:
            key_data = f.read()

        try:
            # 尝试作为私钥加载
            key = serialization.load_pem_private_key(key_data, password=None)
            print(f"已加载私钥: {key_file_path}")
        except Exception:
            try:
                # 尝试作为公钥加载
                key = serialization.load_pem_public_key(key_data)
                print(f"已加载公钥: {key_file_path}")
            except Exception as e:
                raise ValueError(f"无法加载RSA密钥: {e}")

        self.RSA_KEY = key

    def encrypt(self, data: dict) -> bytes:
        """使用公钥加密数据"""
        if data is None:
            raise ValueError("data 不能为 None")

        if not isinstance(self.RSA_KEY, rsa.RSAPublicKey):
            raise TypeError("加密操作需要公钥")

        # 序列化数据
        data_bytes = json.dumps(data).encode('utf-8')

        # 检查数据长度
        max_length = (self.RSA_KEY.key_size // 8) - 2 * hashes.SHA256.digest_size - 2
        if len(data_bytes) > max_length:
            raise ValueError(f"数据过长，最大支持 {max_length} 字节")

        encrypted_data = self.RSA_KEY.encrypt(
            data_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_data

    def decrypt(self, data: bytes) -> dict:
        """使用私钥解密数据"""
        if data is None:
            raise ValueError("data 不能为 None")

        if not isinstance(self.RSA_KEY, rsa.RSAPrivateKey):
            raise TypeError("解密操作需要私钥")

        # 解密数据
        decrypted_data = self.RSA_KEY.decrypt(
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
        """使用私钥签名数据"""
        if data is None:
            raise ValueError("data 不能为 None")

        if not isinstance(self.RSA_KEY, rsa.RSAPrivateKey):
            raise TypeError("签名操作需要私钥")

        # 序列化数据
        data_bytes = json.dumps(data).encode('utf-8')

        # 生成签名
        signature = self.RSA_KEY.sign(
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return data_bytes, signature

    def verify(self, data: bytes, signature: bytes) -> tuple[bool, Union[dict, None]]:
        """使用公钥验证签名"""
        if data is None or signature is None:
            raise ValueError("data 和 signature 不能为 None")

        if not isinstance(self.RSA_KEY, rsa.RSAPublicKey):
            raise TypeError("验证签名操作需要公钥")

        try:
            self.RSA_KEY.verify(
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

    @property
    def key_type(self) -> str:
        """返回当前密钥类型"""
        if isinstance(self.RSA_KEY, rsa.RSAPrivateKey):
            return "private"
        elif isinstance(self.RSA_KEY, rsa.RSAPublicKey):
            return "public"
        else:
            return "unknown"


class CryptoAES:
    """
    AES加密工具类

    Args:
        is_server: 是否为服务端实例
    """

    def __init__(self, is_server: bool = False):
        self.is_server = is_server
        self._lock = Lock()

        # 客户端使用单个密钥，服务端使用多个密钥
        self.client_key = None  # 客户端密钥: {"key": bytes, "time": int, "timeline": int}
        self.server_keys = {}   # 服务端密钥: {user_mail: {"key": bytes, "time": int, "timeline": int}}

        # 只有服务端启动清理线程
        if self.is_server:
            self._running = True
            Thread(target=self._cleanup_expired_keys, daemon=True).start()

    def generate_key(self, user_mail: str, timeline: int = 3600) -> dict:
        """生成AES密钥(客户端使用)"""
        if self.is_server:
            raise RuntimeError("此方法仅限客户端使用")

        key = AESGCM.generate_key(bit_length=256)
        key_info = {
            "key": key,
            "time": int(time.time()),
            "timeline": timeline
        }

        self.client_key = key_info

        # 返回密钥信息，便于传输给服务端
        return {
            "user_mail": user_mail,
            "key": key.hex(),  # 转换为十六进制字符串便于传输
            "time": key_info["time"],
            "timeline": timeline
        }

    def update_keys(self, key_info: dict) -> None:
        """更新密钥(服务端使用)"""
        if not self.is_server:
            raise RuntimeError("此方法仅限服务端使用")

        user_mail = key_info["user_mail"]
        key = bytes.fromhex(key_info["key"])  # 从十六进制转换回字节

        with self._lock:
            self.server_keys[user_mail] = {
                "key": key,
                "time": key_info["time"],
                "timeline": key_info["timeline"]
            }

    def _cleanup_expired_keys(self) -> None:
        """服务端清理过期密钥(服务端使用)"""
        if not self.is_server:
            raise RuntimeError("此方法仅限服务端使用")

        while self._running:
            time.sleep(60)  # 每分钟检查一次
            current_time = time.time()

            with self._lock:
                expired_users = [
                    user_mail for user_mail, key_info in self.server_keys.items()
                    if current_time - key_info["time"] > key_info["timeline"]
                ]

                for user_mail in expired_users:
                    del self.server_keys[user_mail]
                    print(f"服务端已清除过期密钥: {user_mail}")

    def stop_cleanup(self) -> None:
        """停止清理线程（服务端使用）"""
        if self.is_server:
            self._running = False

    def _get_key(self, user_mail: str) -> bytes:
        """获取密钥（内部方法）"""
        if not self.is_server:
            # 客户端模式：使用自己的密钥
            if self.client_key is None:
                raise ValueError("客户端密钥未生成，请先调用 generate_key")
            # 检查密钥是否过期
            if time.time() - self.client_key["time"] > self.client_key["timeline"]:
                raise ValueError("客户端密钥已过期，请重新生成")
            return self.client_key["key"]
        else:
            # 服务端模式：从密钥库获取
            with self._lock:
                if user_mail not in self.server_keys:
                    raise ValueError(f"服务端未找到用户 {user_mail} 的密钥")
                key_info = self.server_keys[user_mail]
                return key_info["key"]

    def encrypt(self, data: dict, user_mail: str=None, associated_data: bytes = None) -> bytes:
        """加密数据"""
        if not data:
            raise ValueError("data 不能为空")

        key = self._get_key(user_mail)

        # 序列化数据
        data_bytes = json.dumps(data, ensure_ascii=False).encode('utf-8')

        # 加密
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data_bytes, associated_data)

        return nonce + ciphertext

    def decrypt(self, encrypted_data: bytes, user_mail: str=None, associated_data: bytes = None) -> dict:
        """解密数据"""
        if not encrypted_data:
            raise ValueError("encrypted_data 不能为空")

        if len(encrypted_data) < 13:
            raise ValueError("加密数据格式错误")

        key = self._get_key(user_mail)

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


class ScryptPassword:
    """
    Scrypt 密码哈希工具类

    Args:
        length: 哈希长度
        n: CPU/内存成本因子
        r: 块大小
        p: 并行化因子
    """

    def __init__(self, length=32, n=2**14, r=8, p=1):
        self.length = length
        self.n = n
        self.r = r
        self.p = p

    def hash_password(self, password: str, salt: bytes = None) -> dict:
        """使用 Scrypt 哈希密码"""
        if salt is None:
            salt = os.urandom(16)

        kdf = Scrypt(
            salt=salt,
            length=self.length,
            n=self.n,
            r=self.r,
            p=self.p,
            backend=default_backend()
        )

        password_hash = kdf.derive(password.encode('utf-8'))

        return {
            "hash": base64.b64encode(password_hash).decode('utf-8'),
            "salt": base64.b64encode(salt).decode('utf-8'),
            "params": {
                "n": self.n,
                "r": self.r,
                "p": self.p,
                "length": self.length
            }
        }

    def verify_password(self, password: str, stored_info: dict) -> bool:
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
    """
    文件哈希工具类
    """

    def get_file_hash(self, file_path: str) -> tuple[bytes, bytes]:
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

    def verify_file_hash(self, file_path: str, hash256: bytes) -> bool:
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


