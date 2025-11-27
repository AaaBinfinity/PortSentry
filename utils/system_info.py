import psutil
import datetime

def get_system_info():
    """获取系统信息"""
    return {
        'cpu_percent': psutil.cpu_percent(interval=1),
        'memory_percent': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent,
        'boot_time': datetime.datetime.fromtimestamp(
            psutil.boot_time()
        ).strftime('%Y-%m-%d %H:%M:%S'),
        'users': [user.name for user in psutil.users()]
    }

def get_system_load():
    """获取系统负载"""
    load = psutil.getloadavg()
    return {
        '1min': load[0],
        '5min': load[1],
        '15min': load[2]
    }