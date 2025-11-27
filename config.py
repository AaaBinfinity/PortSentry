import os

class Config:
    # 基础配置
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'portsentry-secret-key'
    
    # 数据库配置
    DATABASE_URL = os.environ.get('DATABASE_URL') or 'sqlite:///portsentry.db'
    
    # 扫描配置
    SCAN_INTERVAL_IDLE = 30  # 空闲期扫描间隔(秒)
    SCAN_INTERVAL_BUSY = 2   # 繁忙期扫描间隔(秒)
    
    # 告警配置
    ALERT_THRESHOLD = 5      # 异常次数阈值
    ALERT_EMAIL = os.environ.get('ALERT_EMAIL')
    
    # 端口配置
    IGNORE_PORTS = [22, 80, 443]  # 忽略的常用端口

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False

config = DevelopmentConfig()