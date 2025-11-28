# database.py
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from sqlalchemy.exc import DisconnectionError, OperationalError
import time
import logging

db = SQLAlchemy()


class PortStatus(db.Model):
    __tablename__ = 'port_status'

    id = db.Column(db.Integer, primary_key=True)
    port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), nullable=False)
    state = db.Column(db.String(20), nullable=False)
    process_name = db.Column(db.String(100))
    pid = db.Column(db.Integer)
    user = db.Column(db.String(50))
    cmdline = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'port': self.port,
            'protocol': self.protocol,
            'state': self.state,
            'process_name': self.process_name,
            'pid': self.pid,
            'user': self.user,
            'cmdline': self.cmdline,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        }


class Alert(db.Model):
    __tablename__ = 'alerts'

    id = db.Column(db.Integer, primary_key=True)
    level = db.Column(db.String(20), nullable=False)  # INFO, WARNING, ERROR
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text)
    port = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    resolved = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'level': self.level,
            'title': self.title,
            'message': self.message,
            'port': self.port,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'resolved': self.resolved
        }


# 数据库连接管理类
class DatabaseManager:
    def __init__(self, app):
        self.app = app
        self.max_retries = 3
        self.retry_delay = 2

    def execute_with_retry(self, operation, *args, **kwargs):
        """带重试机制的数据库操作"""
        for attempt in range(self.max_retries):
            try:
                with self.app.app_context():
                    return operation(*args, **kwargs)
            except (OperationalError, DisconnectionError) as e:
                if attempt < self.max_retries - 1:
                    logging.warning(f"数据库操作失败 (尝试 {attempt + 1}/{self.max_retries}): {e}")
                    time.sleep(self.retry_delay)
                    # 尝试重新连接
                    db.session.rollback()
                else:
                    logging.error(f"数据库操作最终失败: {e}")
                    raise

    def add_with_retry(self, obj):
        """带重试的添加操作"""

        def _add():
            db.session.add(obj)
            db.session.commit()
            return obj

        return self.execute_with_retry(_add)

    def query_with_retry(self, query_func, *args, **kwargs):
        """带重试的查询操作"""
        return self.execute_with_retry(query_func, *args, **kwargs)


# 配置数据库连接池
def configure_database(app):
    # 设置连接池参数
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': 10,
        'max_overflow': 20,
        'pool_recycle': 3600,  # 1小时回收连接
        'pool_pre_ping': True,  # 重要：每次连接前检查连接是否有效
        'pool_timeout': 30,
        'pool_reset_on_return': 'rollback'
    }

    # 初始化数据库管理器
    db_manager = DatabaseManager(app)

    return db_manager