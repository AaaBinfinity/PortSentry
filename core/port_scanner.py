import subprocess
import json
import psutil
from datetime import datetime
import socket


class PortScanner:
    """
    端口扫描器类
    用于监控系统端口状态、检测端口变化，并收集相关进程信息
    """

    def __init__(self, config):
        """
        初始化端口扫描器

        Args:
            config (dict): 配置参数字典，包含扫描器的各种配置选项
        """
        self.config = config  # 存储配置信息
        self.last_scan_result = {}  # 存储上一次扫描结果，用于比较变化

    def get_netstat_info(self):
        """
        使用netstat命令获取网络连接信息

        Returns:
            str: netstat命令输出的字符串结果，包含TCP/UDP连接信息
        """
        try:
            # 执行netstat命令，参数说明：
            # -t: 显示TCP连接
            # -u: 显示UDP连接
            # -l: 仅显示监听状态的连接
            # -n: 以数字形式显示地址和端口号
            # -p: 显示进程ID和程序名称
            result = subprocess.run([
                'netstat', '-tulnp'
            ], capture_output=True, text=True)

            return result.stdout  # 返回命令标准输出
        except Exception as e:
            print(f"Netstat error: {e}")
            return ""  # 发生异常时返回空字符串

    def get_port_detail(self, port):
        """
        获取指定端口的详细信息

        Args:
            port (int): 要查询的端口号

        Returns:
            dict: 包含端口详细信息的字典，如果端口不存在则返回空字典
        """
        try:
            # 获取当前所有端口信息
            current_ports = self.parse_port_info()

            # 查找指定端口的信息
            port_details = []
            for port_data in current_ports:
                if port_data['port'] == port:
                    port_details.append(port_data)

            if not port_details:
                return {}

            # 返回第一个匹配的端口信息（通常一个端口只有一个进程在使用）
            return port_details[0]

        except Exception as e:
            print(f"Error getting port detail for {port}: {e}")
            return {}
    def get_ss_info(self):
        """
        使用ss命令获取更详细的端口信息（ss是netstat的现代替代工具）

        Returns:
            str: ss命令输出的字符串结果
        """
        try:
            # 执行ss命令，参数说明：
            # -t: TCP连接
            # -u: UDP连接
            # -l: 监听状态连接
            # -n: 数字格式
            # -p: 进程信息
            # # -H: 隐藏表头，便于解析


            # result = subprocess.run([
            #     'ss', '-tulnp', '-H'
            # ], capture_output=True, text=True)


            result = subprocess.run([
                'ss', '-tulnpa', '-H'
            ], capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            print(f"SS error: {e}")
            return ""

    def parse_port_info(self):
        """
        解析端口信息，使用psutil库获取详细的连接和进程信息
        过滤掉进程名未知的进程，只返回有效的信息

        Returns:
            list: 包含端口详细信息的字典列表
        """
        port_info = []  # 存储解析后的端口信息

        # 方法1: 使用psutil库获取网络连接信息（跨平台兼容性更好）
        try:
            # 获取所有inet类型的网络连接（IPv4和IPv6）
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr:  # 只处理有本地地址的连接（过滤掉只有远程地址的连接）
                    port = conn.laddr.port  # 本地端口号
                    pid = conn.pid  # 进程ID

                    # 如果存在进程ID，则获取进程详细信息
                    process_info = self.get_process_info(pid) if pid else {}

                    # 过滤掉进程名未知的进程，避免显示无效信息
                    process_name = process_info.get('name', 'unknown')
                    if process_name == 'unknown':
                        continue  # 跳过未知进程

                    # 根据socket类型确定协议类型
                    if conn.type == socket.SOCK_STREAM:
                        protocol = 'TCP'  # 面向连接的TCP协议
                    elif conn.type == socket.SOCK_DGRAM:
                        protocol = 'UDP'  # 无连接的UDP协议
                    else:
                        protocol = 'UNKNOWN'  # 其他未知协议类型

                    # 构建端口信息字典
                    port_data = {
                        'port': port,  # 端口号
                        'protocol': protocol,  # 协议类型（TCP/UDP）
                        'state': conn.status,  # 连接状态（LISTEN, ESTABLISHED等）
                        'pid': pid,  # 进程ID
                        'process_name': process_name,  # 进程名称
                        'user': process_info.get('username', 'unknown'),  # 进程所属用户
                        'cmdline': process_info.get('cmdline', ''),  # 进程启动命令
                        'exec_path': process_info.get('exe', ''),  # 进程可执行文件路径
                        'start_time': process_info.get('create_time', ''),  # 进程启动时间
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),  # 当前扫描时间戳
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",  # 本地地址:端口
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""  # 远程地址:端口（如果有）
                    }

                    port_info.append(port_data)  # 添加到结果列表
        except Exception as e:
            print(f"Psutil error: {e}")  # 输出psutil相关错误

        return port_info

    def get_process_info(self, pid):
        """
        根据进程ID获取进程的详细信息

        Args:
            pid (int): 进程ID

        Returns:
            dict: 包含进程详细信息的字典，如果进程不存在或无法访问则返回空字典
        """
        try:
            # 通过psutil获取进程对象
            process = psutil.Process(pid)
            return {
                'name': process.name(),  # 进程名称
                'username': process.username(),  # 进程所属用户名
                'cmdline': ' '.join(process.cmdline()),  # 进程启动命令（合并为字符串）
                'exe': process.exe(),  # 进程可执行文件完整路径
                'create_time': datetime.fromtimestamp(
                    process.create_time()
                ).strftime('%Y-%m-%d %H:%M:%S') if process.create_time() else ''  # 进程启动时间（格式化）
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # 处理进程不存在或无权限访问的情况
            return {}

    def scan_ports(self):
        """
        执行完整的端口扫描流程

        Returns:
            dict: 包含当前端口信息、变化信息和时间戳的字典
        """
        # 获取当前端口信息
        current_scan = self.parse_port_info()
        # 检测与上一次扫描的变化
        changes = self.detect_changes(current_scan)
        # 更新上一次扫描结果，使用端口-协议作为唯一键
        self.last_scan_result = {f"{p['port']}-{p['protocol']}": p for p in current_scan}

        return {
            'current_ports': current_scan,  # 当前所有端口信息
            'changes': changes,  # 端口变化信息
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # 扫描完成时间戳
        }

    def detect_changes(self, current_scan):
        """
        检测端口状态的变化，包括新增端口、关闭端口和状态变化的端口

        Args:
            current_scan (list): 当前扫描到的端口信息列表

        Returns:
            dict: 包含三类变化的字典：
                - new_ports: 新增端口列表
                - closed_ports: 关闭端口列表
                - changed_ports: 状态变化端口列表
        """
        changes = {
            'new_ports': [],  # 新增的端口
            'closed_ports': [],  # 关闭的端口
            'changed_ports': []  # 状态发生变化的端口
        }

        # 将当前扫描结果转换为字典格式，键为"端口-协议"
        current_dict = {f"{p['port']}-{p['protocol']}": p for p in current_scan}
        # 上一次扫描结果字典
        last_dict = self.last_scan_result

        # 检测新端口：在当前扫描中存在但在上一次扫描中不存在的端口
        for key, port_data in current_dict.items():
            if key not in last_dict:
                changes['new_ports'].append(port_data)

        # 检测关闭的端口：在上一次扫描中存在但在当前扫描中不存在的端口
        for key, port_data in last_dict.items():
            if key not in current_dict:
                changes['closed_ports'].append(port_data)

        # 检测状态变化的端口：端口存在但状态或进程ID发生变化
        for key, current_data in current_dict.items():
            if key in last_dict:
                last_data = last_dict[key]
                # 检查连接状态或进程ID是否发生变化
                if (current_data['state'] != last_data['state'] or
                        current_data['pid'] != last_data['pid']):
                    changes['changed_ports'].append({
                        'port_data': current_data,  # 当前端口数据
                        'previous_state': last_data  # 上一次的端口数据
                    })

        return changes