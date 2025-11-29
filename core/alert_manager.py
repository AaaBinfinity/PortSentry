import time
import logging
from datetime import datetime
from sqlalchemy.exc import OperationalError, DisconnectionError

# 尝试不同的导入方式
try:
    from core.database import Alert
except ImportError:
    try:
        from models.alert import Alert
    except ImportError:
        # 如果都找不到，可能需要定义 Alert 模型
        from core.database import db


        class Alert(db.Model):
            __tablename__ = 'alerts'

            id = db.Column(db.Integer, primary_key=True)
            level = db.Column(db.String(20), nullable=False)  # ERROR, WARNING, INFO
            title = db.Column(db.String(200), nullable=False)
            message = db.Column(db.Text, nullable=False)
            port = db.Column(db.Integer, nullable=True)
            timestamp = db.Column(db.DateTime, default=datetime.now)
            resolved = db.Column(db.Boolean, default=False)

            def to_dict(self):
                return {
                    'id': self.id,
                    'level': self.level,
                    'title': self.title,
                    'message': self.message,
                    'port': self.port,
                    'timestamp': self.timestamp.isoformat() if self.timestamp else None,
                    'resolved': self.resolved
                }


class AlertManager:
    def __init__(self, config):
        self.config = config
        self.max_retries = 3
        self.retry_delay = 2

        # 定义端口风险等级
        self.high_risk_ports = {
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995,
            1433, 1434, 1723, 3306, 3389, 5432, 5900, 6379, 27017
        }

        self.medium_risk_ports = {
            161, 389, 636, 873, 2049, 3128, 3690, 4848, 5000, 5432, 5901,
            5984, 6379, 7001, 8000, 8080, 8081, 8443, 9000, 9200, 9300
        }


    def _db_operation_with_retry(self, operation, *args, **kwargs):
        """带重试的数据库操作"""
        for attempt in range(self.max_retries):
            try:
                return operation(*args, **kwargs)
            except (OperationalError, DisconnectionError) as e:
                if attempt < self.max_retries - 1:
                    logging.warning(f"数据库操作失败 (尝试 {attempt + 1}/{self.max_retries}): {e}")
                    time.sleep(self.retry_delay)
                    # 回滚会话
                    from core.database import db
                    db.session.rollback()
                else:
                    logging.error(f"数据库操作最终失败: {e}")
                    # 最后一次尝试仍然失败，返回空结果而不是抛出异常anomalies
                    return []
            except Exception as e:
                logging.error(f"未知错误: {e}")
                return []

    def get_all_alerts(self, limit=None):
        """获取所有告警（包括已解决和未解决的）- 带重试机制"""
        from core.database import db, Alert

        def _query_all_alerts():
            query = Alert.query.order_by(Alert.timestamp.desc())
            if limit:
                query = query.limit(limit)
            return query.all()

        return self._db_operation_with_retry(_query_all_alerts)


    def _determine_alert_level(self, port_data, change_type):
        """根据端口和变化类型确定告警级别"""
        port = port_data.get('port', 0)
        process_name = port_data.get('process_name', 'unknown').lower()
        state = port_data.get('state', '')

        # 高风险进程检测
        high_risk_processes = {'nc', 'ncat', 'telnet', 'ftp', 'tftp', 'ssh', 'rsh', 'rexec'}

        # 检测可疑连接状态
        suspicious_states = {'syn-sent', 'syn-recv', 'fin-wait-1', 'fin-wait-2', 'close-wait'}

        # 规则1: 高风险端口 + 新开启 = 严重告警
        if change_type == 'new' and port in self.high_risk_ports:
            return 'ERROR'

        # 规则2: 高风险进程 + 新开启 = 严重告警
        if change_type == 'new' and any(proc in process_name for proc in high_risk_processes):
            return 'ERROR'

        # 规则3: 可疑连接状态 = 警告
        if state in suspicious_states:
            return 'WARNING'

        # 规则4: 中风险端口 + 新开启 = 警告
        if change_type == 'new' and port in self.medium_risk_ports:
            return 'WARNING'

        # 规则5: 系统关键端口关闭 = 警告
        if change_type == 'closed' and port in self.high_risk_ports:
            return 'WARNING'

        # 默认规则
        if change_type == 'new':
            return 'INFO'
        else:  # closed
            return 'INFO'

    def _generate_alert_message(self, port_data, change_type, level):
        """生成详细的告警消息"""
        port = port_data.get('port', 0)
        process_name = port_data.get('process_name', 'unknown')
        state = port_data.get('state', '')
        protocol = port_data.get('protocol', 'tcp')

        base_messages = {
            'new': {
                'ERROR': f"🚨 高风险端口开启 - 端口 {port}/{protocol} 被进程 {process_name} 打开",
                'WARNING': f"⚠️ 端口异常开启 - 端口 {port}/{protocol} 被进程 {process_name} 打开",
                'INFO': f"📝 端口开启 - 端口 {port}/{protocol} 被进程 {process_name} 打开"
            },
            'closed': {
                'ERROR': f"🚨 关键端口关闭 - 端口 {port}/{protocol} 已关闭",
                'WARNING': f"⚠️ 端口异常关闭 - 端口 {port}/{protocol} 已关闭",
                'INFO': f"📝 端口关闭 - 端口 {port}/{protocol} 已关闭"
            }
        }

        message = base_messages[change_type][level]

        # 添加额外信息
        if state and state != 'listening':
            message += f" (状态: {state})"

        # 添加风险说明
        if level == 'ERROR':
            if port in self.high_risk_ports:
                message += f" - 此端口({port})通常用于敏感服务"
            elif any(proc in process_name.lower() for proc in {'nc', 'ncat', 'telnet'}):
                message += f" - 检测到可疑网络工具({process_name})"

        return message

    def check_port_changes(self, changes):
        """检查端口变化并生成分级告警 - 带重试机制"""
        from core.database import db, Alert

        def _create_alerts():
            alerts = []

            # 处理新端口
            for port_data in changes.get('new_ports', []):
                level = self._determine_alert_level(port_data, 'new')
                message = self._generate_alert_message(port_data, 'new', level)

                alert = Alert(
                    level=level,
                    title='端口状态变化',
                    message=message,
                    port=port_data['port'],
                    timestamp=datetime.now(),
                    resolved=False
                )
                db.session.add(alert)
                alerts.append(alert)

            # 处理关闭端口
            for port_data in changes.get('closed_ports', []):
                level = self._determine_alert_level(port_data, 'closed')
                message = self._generate_alert_message(port_data, 'closed', level)

                alert = Alert(
                    level=level,
                    title='端口状态变化',
                    message=message,
                    port=port_data['port'],
                    timestamp=datetime.now(),
                    resolved=False
                )
                db.session.add(alert)
                alerts.append(alert)

            if alerts:
                db.session.commit()
                logging.info(f"生成 {len(alerts)} 个告警，级别分布: "
                             f"ERROR: {sum(1 for a in alerts if a.level == 'ERROR')}, "
                             f"WARNING: {sum(1 for a in alerts if a.level == 'WARNING')}, "
                             f"INFO: {sum(1 for a in alerts if a.level == 'INFO')}")

            return alerts

        return self._db_operation_with_retry(_create_alerts)

    def get_alerts(self, resolved=False, limit=None):
        """获取告警 - 带重试机制"""
        from core.database import db, Alert

        def _query_alerts():
            query = Alert.query.filter_by(resolved=resolved).order_by(Alert.timestamp.desc())
            if limit:
                query = query.limit(limit)
            return query.all()

        return self._db_operation_with_retry(_query_alerts)

    def resolve_alert(self, alert_id):
        """解决告警 - 带重试机制"""
        from core.database import db, Alert

        def _resolve_alert():
            alert = Alert.query.get(alert_id)
            if alert:
                alert.resolved = True
                db.session.commit()
                return True
            return False

        return self._db_operation_with_retry(_resolve_alert)

    def get_alert_stats(self, hours=24):
        """获取告警统计 - 带重试机制"""
        from core.database import db, Alert
        from datetime import datetime, timedelta

        def _get_stats():
            since_time = datetime.now() - timedelta(hours=hours)

            total = Alert.query.filter(Alert.timestamp >= since_time).count()
            resolved = Alert.query.filter(Alert.timestamp >= since_time, Alert.resolved == True).count()
            by_level = db.session.query(
                Alert.level,
                db.func.count(Alert.id)
            ).filter(Alert.timestamp >= since_time).group_by(Alert.level).all()

            return {
                'total': total,
                'resolved': resolved,
                'unresolved': total - resolved,
                'by_level': dict(by_level)
            }

        return self._db_operation_with_retry(_get_stats) or {
            'total': 0,
            'resolved': 0,
            'unresolved': 0,
            'by_level': {}
        }

    def add_custom_alert(self, level, title, message, port=None):
        """添加自定义告警"""
        from core.database import db, Alert

        def _create_custom_alert():
            alert = Alert(
                level=level,
                title=title,
                message=message,
                port=port,
                timestamp=datetime.now(),
                resolved=False
            )
            db.session.add(alert)
            db.session.commit()
            return alert

        return self._db_operation_with_retry(_create_custom_alert)

