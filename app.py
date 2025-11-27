from flask import Flask, render_template, jsonify, request
from config import config
from core.database import db
from core.port_scanner import PortScanner
from core.alert_manager import AlertManager
from utils.system_info import get_system_info, get_system_load
import threading
import time
import json

def create_app():
    app = Flask(__name__)
    app.config.from_object(config)
    
    # 初始化数据库
    db.init_app(app)
    
    # 初始化组件
    scanner = PortScanner(config)
    alert_manager = AlertManager(config)
    
    # 全局状态
    app_state = {
        'last_scan': {},
        'alerts': [],
        'is_scanning': False
    }
    
    def background_scanner():
        """后台扫描线程"""
        with app.app_context():
            while True:
                try:
                    app_state['is_scanning'] = True
                    scan_result = scanner.scan_ports()
                    app_state['last_scan'] = scan_result
                    
                    # 检查变化并生成告警
                    alerts = alert_manager.check_port_changes(scan_result['changes'])
                    if alerts:
                        app_state['alerts'].extend([alert.to_dict() for alert in alerts])
                    
                    app_state['is_scanning'] = False
                    
                    # 自适应扫描间隔
                    interval = config.SCAN_INTERVAL_IDLE
                    if scan_result['changes']:
                        interval = config.SCAN_INTERVAL_BUSY
                    
                    time.sleep(interval)
                    
                except Exception as e:
                    print(f"Scanner error: {e}")
                    time.sleep(10)
    
    # 启动后台扫描线程
    scanner_thread = threading.Thread(target=background_scanner, daemon=True)
    scanner_thread.start()
    
    # 路由定义
    @app.route('/')
    def dashboard():
        return render_template('dashboard.html')
    
    @app.route('/api/port-status')
    def get_port_status():
        return jsonify(app_state['last_scan'])
    
    @app.route('/api/alerts')
    def get_alerts():
        resolved = request.args.get('resolved', 'false').lower() == 'true'
        alerts = alert_manager.get_recent_alerts(resolved=resolved)
        return jsonify([alert.to_dict() for alert in alerts])
    
    @app.route('/api/system-info')
    def system_info():
        return jsonify({
            'system': get_system_info(),
            'load': get_system_load()
        })
    
    @app.route('/api/resolve-alert/<int:alert_id>', methods=['POST'])
    def resolve_alert(alert_id):
        if alert_manager.resolve_alert(alert_id):
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Alert not found'})
    
    @app.route('/alerts')
    def alerts_page():
        return render_template('alerts.html')
    
    @app.route('/details')
    def details_page():
        return render_template('details.html')
    
    return app

if __name__ == '__main__':
    app = create_app()
    
    # 创建数据库表
    with app.app_context():
        db.create_all()
    
    app.run(debug=True, host='0.0.0.0', port=5000)