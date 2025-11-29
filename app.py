from flask import Flask, render_template, jsonify, request
from config import config
from core.database import db
from core.port_scanner import PortScanner
from core.alert_manager import AlertManager
from utils.system_info import get_system_info, get_system_load
import threading
import time
import json
import logging
from datetime import datetime, timedelta
from functools import wraps
import psutil

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


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
        'last_scan': {'current_ports': [], 'changes': []},
        'alerts': [],
        'is_scanning': False,
        'scan_stats': {
            'total_scans': 0,
            'last_scan_time': None,
            'avg_scan_duration': 0
        }
    }

    # 缓存配置
    cache = {
        'port_status': {'data': None, 'timestamp': None},
        'system_info': {'data': None, 'timestamp': None}
    }

    CACHE_TIMEOUT = 2  # 缓存2秒

    def cache_view(timeout):
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                cache_key = f"{f.__name__}_{request.args}"
                now = time.time()

                if (cache_key in cache and
                        now - cache[cache_key]['timestamp'] < timeout):
                    return cache[cache_key]['data']

                result = f(*args, **kwargs)
                cache[cache_key] = {
                    'data': result,
                    'timestamp': now
                }
                return result

            return decorated_function

        return decorator

    def background_scanner():
        """后台扫描线程"""
        with app.app_context():
            scan_count = 0
            total_duration = 0

            while True:
                try:
                    start_time = time.time()
                    app_state['is_scanning'] = True

                    # 执行扫描
                    scan_result = scanner.scan_ports()
                    app_state['last_scan'] = scan_result

                    # 更新扫描统计
                    scan_duration = time.time() - start_time
                    scan_count += 1
                    total_duration += scan_duration

                    app_state['scan_stats'].update({
                        'total_scans': scan_count,
                        'last_scan_time': datetime.now(),
                        'avg_scan_duration': total_duration / scan_count,
                        'last_scan_duration': scan_duration
                    })

                    # 检查变化并生成告警
                    if scan_result['changes']:
                        alerts = alert_manager.check_port_changes(scan_result['changes'])
                        if alerts:
                            new_alerts = [alert.to_dict() for alert in alerts]
                            app_state['alerts'].extend(new_alerts)
                            # 只保留最近100条告警
                            app_state['alerts'] = app_state['alerts'][-100:]

                            logger.info(f"Generated {len(alerts)} new alerts")

                    app_state['is_scanning'] = False

                    # 自适应扫描间隔
                    interval = config.SCAN_INTERVAL_IDLE
                    if scan_result['changes']:
                        interval = config.SCAN_INTERVAL_BUSY

                    # 清理缓存
                    cache.clear()

                    logger.info(f"Scan completed in {scan_duration:.2f}s, next scan in {interval}s")
                    time.sleep(interval)

                except Exception as e:
                    logger.error(f"Scanner error: {e}")
                    app_state['is_scanning'] = False
                    time.sleep(10)

    # 启动后台扫描线程
    scanner_thread = threading.Thread(target=background_scanner, daemon=True)
    scanner_thread.start()

    # 路由定义
    @app.route('/')
    def dashboard():
        return render_template('dashboard.html')

    @app.route('/api/port-status')
    @cache_view(CACHE_TIMEOUT)
    def get_port_status():
        """获取端口状态"""
        try:
            scan_data = app_state['last_scan'].copy()

            # 添加扫描统计信息
            scan_data.update({
                'scan_stats': app_state['scan_stats'],
                'is_scanning': app_state['is_scanning']
            })

            return jsonify(scan_data)
        except Exception as e:
            logger.error(f"Error getting port status: {e}")
            return jsonify({'error': 'Internal server error'}), 500

    @app.route('/api/alerts')
    def get_alerts():
        """获取告警信息"""
        try:
            resolved = request.args.get('resolved', 'false').lower() == 'true'
            limit = request.args.get('limit', type=int)

            # 使用修复后的方法
            alerts = alert_manager.get_alerts(resolved=resolved, limit=limit)

            return jsonify([{
                'id': alert.id,
                'title': alert.title,
                'message': alert.message,
                'level': alert.level.lower(),  # 统一转为小写
                'alert_type': 'port_change',  # 根据标题推断类型
                'port': alert.port,
                'timestamp': alert.timestamp.isoformat() if alert.timestamp else None,
                'resolved': alert.resolved
            } for alert in alerts])

        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
            return jsonify({'error': 'Internal server error'}), 500

    @app.route('/api/system-info')
    @cache_view(CACHE_TIMEOUT)
    def system_info():
        """获取系统信息"""
        try:
            # 导入必要的系统信息获取函数
            from utils.system_info import get_system_info, get_system_load

            system_data = get_system_info()
            load_data = get_system_load()

            # 添加更多系统信息
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')

            return jsonify({
                'system': system_data,
                'load': load_data,
                'memory': {
                    'total': memory.total,
                    'available': memory.available,
                    'percent': memory.percent,
                    'used': memory.used
                },
                'disk': {
                    'total': disk.total,
                    'used': disk.used,
                    'free': disk.free,
                    'percent': disk.percent
                },
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            # 返回基本系统信息
            return jsonify({
                'system': {'platform': 'unknown'},
                'load': {'1min': 0.0, '5min': 0.0, '15min': 0.0},
                'memory': {'percent': 0},
                'disk': {'percent': 0},
                'timestamp': datetime.now().isoformat()
            })

    @app.route('/api/port-detail/<int:port>')
    def get_port_detail(port):
        """获取端口详细信息"""
        try:
            # 获取端口详细信息
            port_detail = scanner.get_port_detail(port)

            # 获取相关连接信息
            connections = []
            for conn in psutil.net_connections():
                if conn.laddr.port == port:
                    connections.append({
                        'local_address': conn.laddr.ip,
                        'local_port': conn.laddr.port,
                        'remote_address': conn.raddr.ip if conn.raddr else '',
                        'remote_port': conn.raddr.port if conn.raddr else '',
                        'state': conn.status
                    })

            port_detail['connections'] = connections
            return jsonify(port_detail)

        except Exception as e:
            logger.error(f"Error getting port detail for {port}: {e}")
            return jsonify({'error': 'Port not found'}), 404

    @app.route('/api/resolve-alert/<int:alert_id>', methods=['POST'])
    def resolve_alert(alert_id):
        """解决告警"""
        try:
            if alert_manager.resolve_alert(alert_id):
                return jsonify({'success': True})
            return jsonify({'success': False, 'error': 'Alert not found'}), 404
        except Exception as e:
            logger.error(f"Error resolving alert {alert_id}: {e}")
            return jsonify({'success': False, 'error': 'Internal server error'}), 500

    @app.route('/api/scan-now', methods=['POST'])
    def trigger_scan():
        """立即触发扫描"""
        try:
            if app_state['is_scanning']:
                return jsonify({'success': False, 'error': 'Scan already in progress'}), 409

            # 在单独的线程中执行扫描
            def quick_scan():
                with app.app_context():
                    scanner.scan_ports()

            scan_thread = threading.Thread(target=quick_scan, daemon=True)
            scan_thread.start()

            return jsonify({'success': True, 'message': 'Scan started'})
        except Exception as e:
            logger.error(f"Error triggering scan: {e}")
            return jsonify({'success': False, 'error': 'Internal server error'}), 500

    @app.route('/api/stats')
    def get_stats():
        """获取统计信息"""
        try:
            # 端口统计
            ports = app_state['last_scan'].get('current_ports', [])
            port_stats = {
                'total': len(ports),
                'by_protocol': {},
                'by_state': {},
                'top_processes': {}
            }

            for port in ports:
                # 按协议统计
                protocol = port.get('protocol', 'unknown')
                port_stats['by_protocol'][protocol] = port_stats['by_protocol'].get(protocol, 0) + 1

                # 按状态统计
                state = port.get('state', 'unknown')
                port_stats['by_state'][state] = port_stats['by_state'].get(state, 0) + 1

                # 按进程统计
                process = port.get('process_name', 'unknown')
                port_stats['top_processes'][process] = port_stats['top_processes'].get(process, 0) + 1

            # 告警统计 - 使用修复后的方法
            alert_stats = alert_manager.get_alert_stats(hours=24)

            return jsonify({
                'port_stats': port_stats,
                'alert_stats': alert_stats,
                'scan_stats': app_state['scan_stats'],
                'system_uptime': time.time() - psutil.boot_time()
            })

        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return jsonify({'error': 'Internal server error'}), 500

    # 修复后台扫描线程中的告警检查
    def background_scanner():
        """后台扫描线程"""
        with app.app_context():
            scan_count = 0
            total_duration = 0

            # 初始化数据库管理器
            from core.database import configure_database
            db_manager = configure_database(app)

            while True:
                try:
                    start_time = time.time()
                    app_state['is_scanning'] = True

                    # 执行扫描
                    scan_result = scanner.scan_ports()
                    app_state['last_scan'] = scan_result

                    # 更新扫描统计
                    scan_duration = time.time() - start_time
                    scan_count += 1
                    total_duration += scan_duration

                    app_state['scan_stats'].update({
                        'total_scans': scan_count,
                        'last_scan_time': datetime.now(),
                        'avg_scan_duration': total_duration / scan_count,
                        'last_scan_duration': scan_duration
                    })

                    # 检查变化并生成告警 - 使用带重试的数据库操作
                    if scan_result.get('changes'):
                        try:
                            alerts = db_manager.execute_with_retry(
                                alert_manager.check_port_changes,
                                scan_result['changes']
                            )
                            if alerts:
                                # 转换为字典格式存储
                                alert_dicts = [{
                                    'id': alert.id,
                                    'title': alert.title,
                                    'message': alert.message,
                                    'level': alert.level,
                                    'timestamp': alert.timestamp.isoformat() if alert.timestamp else None,
                                    'resolved': alert.resolved
                                } for alert in alerts]

                                app_state['alerts'].extend(alert_dicts)
                                # 只保留最近100条告警
                                app_state['alerts'] = app_state['alerts'][-100:]

                                logger.info(f"Generated {len(alerts)} new alerts")
                        except Exception as alert_error:
                            logger.error(f"处理告警时出错: {alert_error}")
                            # 继续执行，不中断扫描

                    app_state['is_scanning'] = False

                    # 自适应扫描间隔
                    interval = config.SCAN_INTERVAL_IDLE
                    if scan_result.get('changes'):
                        interval = config.SCAN_INTERVAL_BUSY

                    # 清理缓存
                    cache.clear()

                    logger.info(f"Scan completed in {scan_duration:.2f}s, next scan in {interval}s")
                    time.sleep(interval)

                except Exception as e:
                    logger.error(f"Scanner error: {e}")
                    app_state['is_scanning'] = False
                    # 发生错误时等待更长时间
                    time.sleep(10)

    @app.route('/alerts')
    def alerts_page():
        return render_template('alerts.html')

    @app.route('/details')
    def details_page():
        return render_template('details.html')

    # 错误处理
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Resource not found'}), 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal server error: {error}")
        return jsonify({'error': 'Internal server error'}), 500

    # 健康检查端点
    @app.route('/health')
    def health_check():
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'scanning': app_state['is_scanning'],
            'last_scan': app_state['scan_stats']['last_scan_time'].isoformat() if app_state['scan_stats'][
                'last_scan_time'] else None
        })

    return app


if __name__ == '__main__':
    app = create_app()

    # 创建数据库表
    with app.app_context():
        db.create_all()

    # 启动前的系统检查
    logger.info("Starting Port Monitoring System...")
    logger.info(f"Database: {app.config['SQLALCHEMY_DATABASE_URI']}")
    logger.info(
        f"Scan Interval: {app.config['SCAN_INTERVAL_IDLE']}s (idle) / {app.config['SCAN_INTERVAL_BUSY']}s (busy)")

    app.run(debug=True, host='0.0.0.0', port=5739)