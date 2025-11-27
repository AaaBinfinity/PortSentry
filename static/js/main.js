// PortSentry 主JavaScript文件
class PortSentryApp {
    constructor() {
        this.config = {
            refreshInterval: 3000,
            apiEndpoints: {
                portStatus: '/api/port-status',
                alerts: '/api/alerts',
                systemInfo: '/api/system-info',
                resolveAlert: '/api/resolve-alert'
            }
        };
        this.charts = {};
        this.init();
    }

    init() {
        console.log('PortSentry 应用初始化');
        this.setupEventListeners();
        this.setupAutoRefresh();
        this.loadInitialData();
    }

    setupEventListeners() {
        // 全局键盘快捷键
        document.addEventListener('keydown', (e) => {
            // F5 刷新
            if (e.key === 'F5') {
                e.preventDefault();
                this.refreshAllData();
            }
            // Ctrl+R 刷新
            if (e.ctrlKey && e.key === 'r') {
                e.preventDefault();
                this.refreshAllData();
            }
        });

        // 页面可见性变化时刷新数据
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden) {
                this.refreshAllData();
            }
        });
    }

    setupAutoRefresh() {
        // 根据页面活动状态调整刷新频率
        setInterval(() => {
            if (!document.hidden) {
                this.refreshAllData();
            }
        }, this.config.refreshInterval);
    }

    async loadInitialData() {
        try {
            await Promise.all([
                this.loadPortStatus(),
                this.loadAlerts(),
                this.loadSystemInfo()
            ]);
        } catch (error) {
            this.showError('初始化数据加载失败', error);
        }
    }

    async refreshAllData() {
        try {
            const promises = [
                this.loadPortStatus(),
                this.loadAlerts(),
                this.loadSystemInfo()
            ];
            await Promise.all(promises);
            // this.showToast('数据已刷新', 'success');
        } catch (error) {
            this.showError('数据刷新失败', error);
        }
    }

    async loadPortStatus() {
        try {
            const response = await fetch(this.config.apiEndpoints.portStatus);
            if (!response.ok) throw new Error('网络响应不正常');
            
            const data = await response.json();
            this.updatePortDisplay(data);
            return data;
        } catch (error) {
            throw new Error(`加载端口状态失败: ${error.message}`);
        }
    }

    async loadAlerts() {
        try {
            const response = await fetch(this.config.apiEndpoints.alerts);
            if (!response.ok) throw new Error('网络响应不正常');
            
            const data = await response.json();
            this.updateAlertsDisplay(data);
            return data;
        } catch (error) {
            throw new Error(`加载告警失败: ${error.message}`);
        }
    }

    async loadSystemInfo() {
        try {
            const response = await fetch(this.config.apiEndpoints.systemInfo);
            if (!response.ok) throw new Error('网络响应不正常');
            
            const data = await response.json();
            this.updateSystemInfoDisplay(data);
            return data;
        } catch (error) {
            throw new Error(`加载系统信息失败: ${error.message}`);
        }
    }

    updatePortDisplay(data) {
        // 更新端口数量显示
        const portCount = data.current_ports ? data.current_ports.length : 0;
        this.updateElementText('#listening-ports', portCount);
        
        // 更新端口表格
        this.updatePortTable(data.current_ports);
        
        // 更新端口图表
        this.updatePortCharts(data.current_ports);
        
        // 显示变化信息
        this.showPortChanges(data.changes);
    }

    updatePortTable(ports) {
        const tbody = document.getElementById('port-table');
        if (!tbody) return;

        if (!ports || ports.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">暂无端口数据</td></tr>';
            return;
        }

        tbody.innerHTML = ports.map(port => `
            <tr class="fade-in">
                <td><span class="badge bg-primary">${port.port}</span></td>
                <td>${port.protocol}</td>
                <td><span class="badge bg-${this.getStateClass(port.state)}">${port.state}</span></td>
                <td>${this.escapeHtml(port.process_name || 'unknown')}</td>
                <td>${port.pid || 'N/A'}</td>
                <td>${this.escapeHtml(port.user || 'unknown')}</td>
                <td>${this.formatTimestamp(port.timestamp)}</td>
            </tr>
        `).join('');
    }

    updatePortCharts(ports) {
        // 更新ECharts图表
        if (typeof echarts !== 'undefined' && ports) {
            this.updatePortDistributionChart(ports);
            this.updateProtocolChart(ports);
        }
    }

    updatePortDistributionChart(ports) {
        const chartDom = document.getElementById('port-chart');
        if (!chartDom) return;

        if (!this.charts.portDistribution) {
            this.charts.portDistribution = echarts.init(chartDom);
        }

        const processCount = {};
        ports.forEach(port => {
            const name = port.process_name || 'unknown';
            processCount[name] = (processCount[name] || 0) + 1;
        });

        const option = {
            tooltip: {
                trigger: 'item',
                formatter: '{a} <br/>{b}: {c} ({d}%)'
            },
            legend: {
                orient: 'vertical',
                left: 'left',
                type: 'scroll'
            },
            series: [{
                name: '端口分布',
                type: 'pie',
                radius: '50%',
                data: Object.entries(processCount).map(([name, value]) => ({
                    name: name,
                    value: value
                })),
                emphasis: {
                    itemStyle: {
                        shadowBlur: 10,
                        shadowOffsetX: 0,
                        shadowColor: 'rgba(0, 0, 0, 0.5)'
                    }
                }
            }]
        };

        this.charts.portDistribution.setOption(option);
    }

    updateProtocolChart(ports) {
        // 协议分布图表
        const protocolCount = { TCP: 0, UDP: 0 };
        ports.forEach(port => {
            const protocol = port.protocol || 'TCP';
            protocolCount[protocol] = (protocolCount[protocol] || 0) + 1;
        });

        // 可以在详情页面使用这个数据
    }

    updateAlertsDisplay(alerts) {
        // 更新告警数量
        const unresolvedAlerts = alerts.filter(alert => !alert.resolved);
        this.updateElementText('#alert-count', unresolvedAlerts.length);
        
        // 更新告警列表
        this.updateAlertsList(unresolvedAlerts.slice(0, 5));
    }

    updateAlertsList(alerts) {
        const container = document.getElementById('alerts-list');
        if (!container) return;

        if (alerts.length === 0) {
            container.innerHTML = '<div class="text-center text-muted py-3">暂无告警</div>';
            return;
        }

        container.innerHTML = alerts.map(alert => `
            <div class="alert alert-${this.getAlertClass(alert.level)} mb-2 fade-in">
                <div class="d-flex justify-content-between align-items-start">
                    <div class="flex-grow-1">
                        <h6 class="mb-1">${this.escapeHtml(alert.title)}</h6>
                        <p class="mb-1 small">${this.escapeHtml(alert.message)}</p>
                        <small class="text-muted">${this.formatTimestamp(alert.timestamp)}</small>
                    </div>
                    ${!alert.resolved ? `
                        <button class="btn btn-sm btn-outline-success ms-2" 
                                onclick="app.resolveAlert(${alert.id})">
                            解决
                        </button>
                    ` : ''}
                </div>
            </div>
        `).join('');
    }

    updateSystemInfoDisplay(systemInfo) {
        // 更新系统信息显示
        this.updateElementText('#system-load', systemInfo.load ? systemInfo.load['1min'].toFixed(2) : '0.00');
        
        // 更新系统健康指示器
        this.updateSystemHealthIndicator(systemInfo.system);
    }

    updateSystemHealthIndicator(systemInfo) {
        // 根据系统负载更新健康状态
        const cpuPercent = systemInfo?.cpu_percent || 0;
        const memoryPercent = systemInfo?.memory_percent || 0;
        
        let healthStatus = 'healthy';
        if (cpuPercent > 80 || memoryPercent > 80) {
            healthStatus = 'warning';
        }
        if (cpuPercent > 90 || memoryPercent > 90) {
            healthStatus = 'critical';
        }
        
        // 更新健康状态指示器
        const indicator = document.getElementById('system-health-indicator');
        if (indicator) {
            indicator.className = `status-indicator status-${healthStatus}`;
        }
    }

    showPortChanges(changes) {
        // 显示端口变化通知
        if (changes && (changes.new_ports.length > 0 || changes.closed_ports.length > 0)) {
            const newCount = changes.new_ports.length;
            const closedCount = changes.closed_ports.length;
            
            if (newCount > 0 || closedCount > 0) {
                this.showToast(
                    `检测到端口变化: ${newCount}个新端口, ${closedCount}个端口关闭`, 
                    'info'
                );
            }
        }
    }

    async resolveAlert(alertId) {
        try {
            const response = await fetch(`/api/resolve-alert/${alertId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) throw new Error('网络响应不正常');
            
            const result = await response.json();
            if (result.success) {
                this.showToast('告警已标记为解决', 'success');
                this.loadAlerts(); // 重新加载告警列表
            } else {
                throw new Error(result.error || '操作失败');
            }
        } catch (error) {
            this.showError('解决告警失败', error);
        }
    }

    // 工具方法
    updateElementText(selector, text) {
        const element = document.querySelector(selector);
        if (element) {
            element.textContent = text;
        }
    }

    getStateClass(state) {
        const stateClasses = {
            'LISTEN': 'success',
            'ESTABLISHED': 'primary',
            'TIME_WAIT': 'warning',
            'CLOSE_WAIT': 'danger',
            'CLOSED': 'secondary'
        };
        return stateClasses[state] || 'secondary';
    }

    getAlertClass(level) {
        const alertClasses = {
            'ERROR': 'danger',
            'WARNING': 'warning',
            'INFO': 'info'
        };
        return alertClasses[level] || 'secondary';
    }

    formatTimestamp(timestamp) {
        if (!timestamp) return '未知时间';
        try {
            const date = new Date(timestamp);
            return date.toLocaleString('zh-CN');
        } catch {
            return timestamp;
        }
    }

    escapeHtml(unsafe) {
        if (typeof unsafe !== 'string') return unsafe;
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    showToast(message, type = 'info') {
        // 创建Toast元素
        const toast = document.createElement('div');
        toast.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        toast.style.cssText = `
            top: 20px;
            right: 20px;
            z-index: 1050;
            min-width: 250px;
        `;
        toast.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        document.body.appendChild(toast);

        // 3秒后自动移除
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 3000);
    }

    showError(title, error) {
        console.error(title, error);
        this.showToast(`${title}: ${error.message}`, 'danger');
    }

    // 数据导出功能
    exportData(data, filename, format = 'json') {
        try {
            let content, mimeType, ext;
            
            if (format === 'json') {
                content = JSON.stringify(data, null, 2);
                mimeType = 'application/json';
                ext = 'json';
            } else if (format === 'csv') {
                content = this.convertToCSV(data);
                mimeType = 'text/csv';
                ext = 'csv';
            } else {
                throw new Error('不支持的格式');
            }

            const blob = new Blob([content], { type: mimeType });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${filename}_${new Date().getTime()}.${ext}`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            this.showToast('导出成功', 'success');
        } catch (error) {
            this.showError('导出失败', error);
        }
    }

    convertToCSV(data) {
        if (!Array.isArray(data) || data.length === 0) return '';
        
        const headers = Object.keys(data[0]);
        const csvRows = [
            headers.join(','),
            ...data.map(row => 
                headers.map(header => {
                    const value = row[header] || '';
                    return `"${String(value).replace(/"/g, '""')}"`;
                }).join(',')
            )
        ];
        
        return csvRows.join('\n');
    }

    // 图表自适应调整
    handleResize() {
        Object.values(this.charts).forEach(chart => {
            if (chart && typeof chart.resize === 'function') {
                chart.resize();
            }
        });
    }
}

// 全局应用实例
let app;

// 页面加载完成后初始化应用
document.addEventListener('DOMContentLoaded', function() {
    app = new PortSentryApp();
    
    // 窗口大小变化时调整图表
    window.addEventListener('resize', () => {
        app.handleResize();
    });
});

// 全局工具函数
function formatNumber(num) {
    if (typeof num !== 'number') return '0';
    return num.toLocaleString('zh-CN');
}

function formatPercentage(num) {
    if (typeof num !== 'number') return '0%';
    return `${num.toFixed(1)}%`;
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// 为全局window对象添加应用引用
window.PortSentryApp = PortSentryApp;