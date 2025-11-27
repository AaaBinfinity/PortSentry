from datetime import datetime, timedelta
from .database import db, Alert

class AlertManager:
    def __init__(self, config):
        self.config = config
        self.alert_history = {}
    
    def create_alert(self, level, title, message, port=None):
        """创建告警"""
        alert = Alert(
            level=level,
            title=title,
            message=message,
            port=port
        )
        
        db.session.add(alert)
        db.session.commit()
        
        return alert
    
    def check_port_changes(self, changes):
        """检查端口变化并生成告警"""
        alerts = []
        
        # 新端口告警
        for port_data in changes.get('new_ports', []):
            if port_data['port'] not in self.config.IGNORE_PORTS:
                alert = self.create_alert(
                    level='WARNING',
                    title=f'新端口监听检测',
                    message=f'端口 {port_data["port"]} 被进程 {port_data["process_name"]}(PID: {port_data["pid"]}) 开启',
                    port=port_data['port']
                )
                alerts.append(alert)
        
        # 端口关闭告警
        for port_data in changes.get('closed_ports', []):
            if port_data['port'] not in self.config.IGNORE_PORTS:
                alert = self.create_alert(
                    level='INFO',
                    title=f'端口关闭',
                    message=f'端口 {port_data["port"]} 已关闭',
                    port=port_data['port']
                )
                alerts.append(alert)
        
        return alerts
    
    def get_recent_alerts(self, hours=24, resolved=False):
        """获取最近告警"""
        since = datetime.utcnow() - timedelta(hours=hours)
        return Alert.query.filter(
            Alert.timestamp >= since,
            Alert.resolved == resolved
        ).order_by(Alert.timestamp.desc()).all()
    
    def resolve_alert(self, alert_id):
        """解决告警"""
        alert = Alert.query.get(alert_id)
        if alert:
            alert.resolved = True
            db.session.commit()
            return True
        return False