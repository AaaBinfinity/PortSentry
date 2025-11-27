import subprocess
import json
import psutil
from datetime import datetime
import socket

class PortScanner:
    def __init__(self, config):
        self.config = config
        self.last_scan_result = {}
    
    def get_netstat_info(self):
        """获取网络连接信息"""
        try:
            # 使用 netstat 命令获取端口信息
            result = subprocess.run([
                'netstat', '-tulnp'
            ], capture_output=True, text=True)
            
            return result.stdout
        except Exception as e:
            print(f"Netstat error: {e}")
            return ""
    
    def get_ss_info(self):
        """使用 ss 命令获取更详细的端口信息"""
        try:
            result = subprocess.run([
                'ss', '-tulnp', '-H'
            ], capture_output=True, text=True)
            
            return result.stdout
        except Exception as e:
            print(f"SS error: {e}")
            return ""
    
    def parse_port_info(self):
        """解析端口信息"""
        port_info = []
        
        # 方法1: 使用 psutil 获取网络连接
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' and conn.laddr:
                    port = conn.laddr.port
                    pid = conn.pid
                    
                    process_info = self.get_process_info(pid)
                    
                    port_data = {
                        'port': port,
                        'protocol': 'TCP',  # 简化处理
                        'state': conn.status,
                        'pid': pid,
                        'process_name': process_info.get('name', 'unknown'),
                        'user': process_info.get('username', 'unknown'),
                        'cmdline': process_info.get('cmdline', ''),
                        'exec_path': process_info.get('exe', ''),
                        'start_time': process_info.get('create_time', ''),
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                    
                    port_info.append(port_data)
        except Exception as e:
            print(f"Psutil error: {e}")
        
        return port_info
    
    def get_process_info(self, pid):
        """获取进程详细信息"""
        try:
            process = psutil.Process(pid)
            return {
                'name': process.name(),
                'username': process.username(),
                'cmdline': ' '.join(process.cmdline()),
                'exe': process.exe(),
                'create_time': datetime.fromtimestamp(
                    process.create_time()
                ).strftime('%Y-%m-%d %H:%M:%S') if process.create_time() else ''
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {}
    
    def scan_ports(self):
        """执行端口扫描"""
        current_scan = self.parse_port_info()
        changes = self.detect_changes(current_scan)
        self.last_scan_result = {f"{p['port']}-{p['protocol']}": p for p in current_scan}
        
        return {
            'current_ports': current_scan,
            'changes': changes,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def detect_changes(self, current_scan):
        """检测端口变化"""
        changes = {
            'new_ports': [],
            'closed_ports': [],
            'changed_ports': []
        }
        
        current_dict = {f"{p['port']}-{p['protocol']}": p for p in current_scan}
        last_dict = self.last_scan_result
        
        # 检测新端口
        for key, port_data in current_dict.items():
            if key not in last_dict:
                changes['new_ports'].append(port_data)
        
        # 检测关闭的端口
        for key, port_data in last_dict.items():
            if key not in current_dict:
                changes['closed_ports'].append(port_data)
        
        # 检测状态变化的端口
        for key, current_data in current_dict.items():
            if key in last_dict:
                last_data = last_dict[key]
                if (current_data['state'] != last_data['state'] or 
                    current_data['pid'] != last_data['pid']):
                    changes['changed_ports'].append({
                        'port_data': current_data,
                        'previous_state': last_data
                    })
        
        return changes