import os

class Config:
    # 基础配置
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'portsentry-secret-key'
    
    # MySQL数据库配置
    MYSQL_HOST = os.environ.get('MYSQL_HOST') or 'infinitylog.top'
    MYSQL_PORT = os.environ.get('MYSQL_PORT') or '3306'
    MYSQL_USER = os.environ.get('MYSQL_USER') or 'binfinity'
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD') or 'Cb050328_password'
    MYSQL_DB = os.environ.get('MYSQL_DB') or 'portsentry'
    
    # SQLAlchemy配置
    SQLALCHEMY_DATABASE_URI = f'mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 300,
        'pool_pre_ping': True
    }
    
    # 扫描配置
    SCAN_INTERVAL_IDLE = 30  # 空闲期扫描间隔(秒)
    SCAN_INTERVAL_BUSY = 2   # 繁忙期扫描间隔(秒)
    
    # 告警配置
    ALERT_THRESHOLD = 5      # 异常次数阈值
    ALERT_EMAIL = os.environ.get('ALERT_EMAIL')
    
    # 端口配置
    # IGNORE_PORTS = [22, 80, 443, 3306, 5432]  # 忽略的常用端口
    IGNORE_PORTS = [5432]  # 忽略的常用端口

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False

config = DevelopmentConfig()