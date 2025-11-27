from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

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