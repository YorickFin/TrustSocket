from pymongo import MongoClient
from gridfs import GridFS

class DBTool:

    # 类变量共享连接
    _mongo_client = None

    def __init__(self, host='localhost', port=27017):
        # 共享连接，避免创建多个客户端实例
        if DBTool._mongo_client is None:
            try:
                DBTool._mongo_client = MongoClient(host, port)
                print('成功连接到 MongoDB 服务器')
            except Exception as e:
                print('连接 MongoDB 服务器失败：', e)
                raise e

        self.mongo_client = DBTool._mongo_client

# 文档操作
class DocTool(DBTool):

    # 类变量共享连接
    def __init__(self, db_name: str=None, collection_name: str=None):
        if db_name is None:
            raise ValueError('数据库名称不能为空')
        if collection_name is None:
            raise ValueError('集合名称不能为空')

        super().__init__()
        self.db = self.mongo_client[db_name]
        self.collection = self.db[collection_name]


class FileTool(DBTool):
    def __init__(self, db_name: str=None, collection_name: str=None):
        if db_name is None:
            raise ValueError('数据库名称不能为空')
        if collection_name is None:
            raise ValueError('集合名称不能为空')

        super().__init__()
        self.db = self.mongo_client[db_name]
        self.fs = GridFS(self.db, collection_name)

    def upload_file(self, file_data, filename, user_id):
        """上传文件"""
        file_info = self.fs.find_one({'filename': filename, 'user_id': user_id})
        if file_info:
            self.fs.delete(file_info._id)
        self.fs.put(
            file_data,
            filename=filename,
            user_id=user_id
        )

    def download_file(self, filename, user_id) -> bytes:
        """下载文件"""
        file_info = self.fs.find_one({'filename': filename, 'user_id': user_id})
        if file_info:
            return self.fs.get(file_info._id).read()
        else:
            return None

    def delete_file(self, filename, user_id) -> bool:
        """删除文件"""
        file_info = self.fs.find_one({'filename': filename, 'user_id': user_id})
        if file_info:
            self.fs.delete(file_info._id)
            return True
        else:
            return False

    def get_file_list(self, user_id) -> list:
        """获取文件列表"""
        file_list = []
        files = self.fs.find({'user_id': user_id})
        if files:
            for file_info in files:
                file_list.append(file_info.filename)
        return file_list

