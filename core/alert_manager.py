# alert_manager.py - 在现有的 AlertManager 类中添加重试机制
import time
import logging
from datetime import datetime
from sqlalchemy.exc import OperationalError, DisconnectionError


class AlertManager:
    def __init__(self, config):
        self.config = config
        self.max_retries = 3
        self.retry_delay = 2

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
                    # 最后一次尝试仍然失败，返回空结果而不是抛出异常
                    return []
            except Exception as e:
                logging.error(f"未知错误: {e}")
                return []

    def check_port_changes(self, changes):
        """检查端口变化并生成告警 - 带重试机制"""
        from core.database import db, Alert

        def _create_alerts():
            alerts = []

            # 处理新端口
            for port_data in changes.get('new_ports', []):
                alert = Alert(
                    level='INFO',
                    title='端口开启',
                    message=f"端口 {port_data['port']} 已开启 - 进程: {port_data.get('process_name', 'unknown')}",
                    port=port_data['port'],
                    timestamp=datetime.now(),
                    resolved=False
                )
                db.session.add(alert)
                alerts.append(alert)

            # 处理关闭端口
            for port_data in changes.get('closed_ports', []):
                alert = Alert(
                    level='INFO',
                    title='端口关闭',
                    message=f"端口 {port_data['port']} 已关闭 - 进程: {port_data.get('process_name', 'unknown')}",
                    port=port_data['port'],
                    timestamp=datetime.now(),
                    resolved=False
                )
                db.session.add(alert)
                alerts.append(alert)

            if alerts:
                db.session.commit()

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