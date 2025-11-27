import psutil
import subprocess
import json
from datetime import datetime, timedelta
import socket
import os
import logging
from typing import Dict, List, Optional, Any

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SystemHelper:
    """系统助手类"""
    
    @staticmethod
    def get_host_info() -> Dict[str, Any]:
        """获取主机信息"""
        try:
            hostname = socket.gethostname()
            return {
                'hostname': hostname,
                'ip_address': socket.gethostbyname(hostname),
                'platform': os.uname().sysname,
                'release': os.uname().release,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"获取主机信息失败: {e}")
            return {}
    
    @staticmethod
    def is_port_in_use(port: int, protocol: str = 'tcp') -> bool:
        """检查端口是否被占用"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex(('localhost', port))
                return result == 0
        except Exception as e:
            logger.error(f"检查端口 {port} 失败: {e}")
            return False
    
    @staticmethod
    def get_process_tree(pid: int) -> Dict[str, Any]:
        """获取进程树信息"""
        try:
            process = psutil.Process(pid)
            parent = process.parent()
            
            return {
                'pid': pid,
                'name': process.name(),
                'parent_pid': parent.pid if parent else None,
                'parent_name': parent.name() if parent else None,
                'children': [child.pid for child in process.children()]
            }
        except psutil.NoSuchProcess:
            return {}
    
    @staticmethod
    def get_network_connections() -> List[Dict[str, Any]]:
        """获取网络连接信息"""
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr:
                    conn_info = {
                        'fd': conn.fd,
                        'family': conn.family.name,
                        'type': conn.type.name,
                        'laddr': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    }
                    connections.append(conn_info)
        except Exception as e:
            logger.error(f"获取网络连接失败: {e}")
        
        return connections

class PortAnalyzer:
    """端口分析器"""
    
    @staticmethod
    def analyze_port_risk(port_data: Dict[str, Any]) -> Dict[str, Any]:
        """分析端口风险"""
        risk_level = "low"
        warnings = []
        
        port = port_data.get('port', 0)
        process_name = port_data.get('process_name', '').lower()
        user = port_data.get('user', '')
        
        # 高风险端口检测
        high_risk_ports = [21, 23, 135, 139, 445, 1433, 3306, 3389, 5432]
        if port in high_risk_ports:
            risk_level = "high"
            warnings.append(f"端口 {port} 是常见服务端口，需关注安全性")
        
        # 高权限用户检测
        if user in ['root', 'Administrator']:
            risk_level = "high" if risk_level != "high" else risk_level
            warnings.append(f"进程以高权限用户 {user} 运行")
        
        # 未知进程检测
        if not process_name or process_name in ['unknown', '']:
            risk_level = "high"
            warnings.append("未知进程监听端口")
        
        # 非标准端口检测
        if port > 10000 and port not in [27017, 28017]:  # MongoDB 端口例外
            risk_level = "medium" if risk_level == "low" else risk_level
            warnings.append(f"端口 {port} 是非标准端口")
        
        return {
            'risk_level': risk_level,
            'warnings': warnings,
            'score': PortAnalyzer._calculate_risk_score(risk_level, len(warnings))
        }
    
    @staticmethod
    def _calculate_risk_score(risk_level: str, warning_count: int) -> int:
        """计算风险分数"""
        base_scores = {'low': 0, 'medium': 50, 'high': 80}
        return min(100, base_scores.get(risk_level, 0) + (warning_count * 10))
    
    @staticmethod
    def get_port_statistics(ports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """获取端口统计信息"""
        if not ports:
            return {}
        
        total_ports = len(ports)
        tcp_ports = len([p for p in ports if p.get('protocol') == 'TCP'])
        udp_ports = len([p for p in ports if p.get('protocol') == 'UDP'])
        listening_ports = len([p for p in ports if p.get('state') == 'LISTEN'])
        
        # 按进程统计
        process_stats = {}
        for port in ports:
            process_name = port.get('process_name', 'unknown')
            if process_name not in process_stats:
                process_stats[process_name] = 0
            process_stats[process_name] += 1
        
        # 按用户统计
        user_stats = {}
        for port in ports:
            user = port.get('user', 'unknown')
            if user not in user_stats:
                user_stats[user] = 0
            user_stats[user] += 1
        
        return {
            'total_ports': total_ports,
            'tcp_ports': tcp_ports,
            'udp_ports': udp_ports,
            'listening_ports': listening_ports,
            'process_distribution': process_stats,
            'user_distribution': user_stats,
            'common_ports': len([p for p in ports if p.get('port', 0) in [22, 80, 443, 3306, 5432]])
        }

class DataFormatter:
    """数据格式化工具"""
    
    @staticmethod
    def format_timestamp(timestamp: str) -> str:
        """格式化时间戳"""
        try:
            if isinstance(timestamp, str):
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            else:
                dt = timestamp
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return str(timestamp)
    
    @staticmethod
    def format_bytes(size: int) -> str:
        """格式化字节大小"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"
    
    @staticmethod
    def format_duration(seconds: int) -> str:
        """格式化时间间隔"""
        if seconds < 60:
            return f"{seconds}秒"
        elif seconds < 3600:
            return f"{seconds // 60}分{seconds % 60}秒"
        else:
            return f"{seconds // 3600}时{(seconds % 3600) // 60}分"

class SecurityChecker:
    """安全检查器"""
    
    @staticmethod
    def check_suspicious_processes() -> List[Dict[str, Any]]:
        """检查可疑进程"""
        suspicious_keywords = ['miner', 'backdoor', 'trojan', 'malware', 'exploit']
        suspicious_processes = []
        
        try:
            for process in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    process_info = process.info
                    cmdline = ' '.join(process_info.get('cmdline', [])).lower()
                    name = process_info.get('name', '').lower()
                    
                    for keyword in suspicious_keywords:
                        if keyword in cmdline or keyword in name:
                            suspicious_processes.append({
                                'pid': process_info['pid'],
                                'name': process_info['name'],
                                'cmdline': process_info.get('cmdline', []),
                                'reason': f"检测到可疑关键词: {keyword}"
                            })
                            break
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            logger.error(f"检查可疑进程失败: {e}")
        
        return suspicious_processes
    
    @staticmethod
    def check_unauthorized_ports(known_ports: List[int]) -> List[Dict[str, Any]]:
        """检查未授权端口"""
        unauthorized_ports = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' and conn.laddr:
                    port = conn.laddr.port
                    if port not in known_ports and port > 1024:  # 忽略特权端口
                        try:
                            process = psutil.Process(conn.pid)
                            unauthorized_ports.append({
                                'port': port,
                                'pid': conn.pid,
                                'process_name': process.name(),
                                'protocol': 'TCP',
                                'user': process.username()
                            })
                        except psutil.NoSuchProcess:
                            unauthorized_ports.append({
                                'port': port,
                                'pid': conn.pid,
                                'process_name': 'unknown',
                                'protocol': 'TCP',
                                'user': 'unknown'
                            })
        except Exception as e:
            logger.error(f"检查未授权端口失败: {e}")
        
        return unauthorized_ports

def get_system_health() -> Dict[str, Any]:
    """获取系统健康状态"""
    try:
        # CPU 使用率
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # 内存使用率
        memory = psutil.virtual_memory()
        
        # 磁盘使用率
        disk = psutil.disk_usage('/')
        
        # 系统负载
        load_avg = psutil.getloadavg()
        
        # 网络IO
        net_io = psutil.net_io_counters()
        
        return {
            'cpu': {
                'percent': cpu_percent,
                'cores': psutil.cpu_count(),
                'load_avg': load_avg
            },
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
            'network': {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            },
            'boot_time': psutil.boot_time(),
            'users': [user.name for user in psutil.users()]
        }
    except Exception as e:
        logger.error(f"获取系统健康状态失败: {e}")
        return {}

def export_data(data: Any, format_type: str = 'json') -> str:
    """导出数据"""
    try:
        if format_type == 'json':
            return json.dumps(data, indent=2, ensure_ascii=False, default=str)
        elif format_type == 'csv':
            # 简化的 CSV 导出
            if isinstance(data, list) and data:
                headers = data[0].keys()
                csv_lines = [','.join(headers)]
                for item in data:
                    csv_lines.append(','.join(str(item.get(h, '')) for h in headers))
                return '\n'.join(csv_lines)
        return str(data)
    except Exception as e:
        logger.error(f"导出数据失败: {e}")
        return ""

if __name__ == "__main__":
    # 测试功能
    print("=== 系统信息 ===")
    print(json.dumps(SystemHelper.get_host_info(), indent=2))
    
    print("\n=== 端口 80 使用情况 ===")
    print(f"Port 80 in use: {SystemHelper.is_port_in_use(80)}")
    
    print("\n=== 系统健康状态 ===")
    health = get_system_health()
    print(f"CPU: {health.get('cpu', {}).get('percent')}%")
    print(f"Memory: {health.get('memory', {}).get('percent')}%")