#!/usr/bin/env python3
"""
测试告警生成
"""

import sys
import os

# 添加项目根目录到Python路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from flask import Flask
from config import config
from core.alert_manager import AlertManager


def test_alert_generation():
    """测试告警生成功能"""
    app = Flask(__name__)
    app.config.from_object(config)

    with app.app_context():
        from core.database import db
        db.init_app(app)

        # 创建表
        db.create_all()

        alert_manager = AlertManager(config)

        # 模拟端口变化数据
        test_changes = {
            'new_ports': [
                {
                    'port': 22,  # SSH端口，高风险
                    'protocol': 'TCP',
                    'state': 'LISTEN',
                    'process_name': 'sshd',
                    'pid': 1234
                },
                {
                    'port': 8080,  # 普通HTTP端口
                    'protocol': 'TCP',
                    'state': 'LISTEN',
                    'process_name': 'python',
                    'pid': 5678
                }
            ],
            'closed_ports': [
                {
                    'port': 3306,  # MySQL端口，高风险
                    'protocol': 'TCP',
                    'state': 'LISTEN',
                    'process_name': 'mysqld',
                    'pid': 9999
                }
            ]
        }

        print("开始测试告警生成...")
        alerts = alert_manager.check_port_changes(test_changes)

        if alerts:
            print(f"成功生成 {len(alerts)} 个告警:")
            for alert in alerts:
                print(f"  - [{alert.level}] {alert.message}")
        else:
            print("未生成任何告警，请检查告警规则")

        # 检查数据库中的告警
        from core.database import Alert
        db_alerts = Alert.query.all()
        print(f"数据库中共有 {len(db_alerts)} 个告警")


if __name__ == '__main__':
    test_alert_generation()