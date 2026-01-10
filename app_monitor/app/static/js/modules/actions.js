import { state } from './state.js';
import { API } from './api.js';
import { UI } from './ui.js';
import { Dashboard } from './dashboard.js';

export const Actions = {
    // 点击“开启监控”
    handleMonitor: async (appName, bundleId) => {
        if (!state.socket) return UI.alert("错误", "Socket 未连接", "❌", "danger");

        // 切换或重启判断
        if (state.currentMonitoredApp) {
            if (state.currentMonitoredApp.bundleId !== bundleId) {
                if (!(await UI.confirm("切换应用", `停止 [${state.currentMonitoredApp.name}] 并启动 [${appName}]？`, "🔀", "primary", "切换"))) return;
            } else {
                if (!(await UI.confirm("重启监控", `是否重启 [${appName}]？`, "🔄", "warning", "重启"))) return;
            }
        }

        // 暂存并打开配置
        state.pendingApp = { name: appName, bundleId: bundleId };
        UI.showConfigModal();
    },

    // 确认配置并启动
    confirmConfig: async () => {
        const mode = document.getElementById('modeTweak').checked ? 'tweak' : 'frida';
        const deviceIp = document.getElementById('deviceIp').value;
        const serverIp = document.getElementById('serverIp').value;

        if (mode === 'tweak' && (!deviceIp || !serverIp)) {
            alert("Tweak 模式下必须填写 IP 地址");
            return;
        }

        UI.hideConfigModal();
        await Actions.startProcess(mode, state.pendingApp.name, state.pendingApp.bundleId, deviceIp, serverIp);
    },

    // 启动监控
    startProcess: async (mode, appName, bundleId, deviceIp, serverIp) => {
        // 初始化 UI
        UI.activateTab('#info-collection');
        UI.updateGlobalBar(true, appName, '正在部署'); 
        UI.clearAllLogs();
        Dashboard.clear();

        // 根据模式显示不同的 Loading 提示文案
        let loadingTitle, loadingMsg;
        
        if (mode === 'tweak') {
            loadingTitle = "正在部署插件";
            loadingMsg = "正在通过 SSH 传输文件并进行校验...\n请保持网络连接。";
        } else {
            loadingTitle = "正在启动 Frida";
            loadingMsg = "正在通过 USB 连接设备并注入脚本...\n请保持设备解锁。";
        }

        // 显示 Loading
        UI.showLoadingModal(loadingTitle, loadingMsg);
        // 定义强制关闭 Loading
        const forceHideLoading = () => {
            const el = document.getElementById('globalModal');
            if (el) {
                const modal = bootstrap.Modal.getInstance(el); 
                if (modal) setTimeout(() => modal.hide(), 300); // 延时关闭防止动画冲突
            }
        };

        try {
            // 准备请求
            let res;
            if (mode === 'tweak') {
                res = await API.startTweakMonitor(bundleId, deviceIp, serverIp);
            } else {
                res = await API.startMonitor(bundleId);
            }
            if (res.status === 'success') {
                // 关闭部署 Loading
                forceHideLoading();
                if (mode === 'tweak') {
                    // Tweak 模式：进入等待心跳阶段
                    await Actions.waitForTweakInjection(appName, bundleId, deviceIp);
                } else {
                    // Frida 模式：直接成功
                    UI.updateGlobalBar(true, appName, 'Frida');
                    state.currentMonitoredApp = { name: appName, bundleId, mode, deviceIp };
                }
            } else {
                throw new Error(res.message);
            }
        } catch (e) {
            // 统一错误处理
            forceHideLoading();
            UI.updateGlobalBar(false);
            // 启动失败，将 SDK 列表恢复到初始状态
            UI.resetSDKTable('default');
            state.currentMonitoredApp = null;
            // 优化错误提示
            let errMsg = e.message;
            if (e.message.includes("Failed to spawn")) {
                errMsg = "无法启动应用，请检查：\n1. 设备是否解锁\n2. 目标应用是否已安装\n3. 是否有其他 Frida 进程冲突";
            }
            
            UI.alert("启动失败", errMsg, "❌", "danger");
        }
    },

    // 等待 Tweak 心跳信号
    waitForTweakInjection: (appName, bundleId, deviceIp) => {
        return new Promise((resolve) => {
            const timeoutSeconds = 15;
            let isReceived = false;
            // 临时监听器
            const onHeartLog = (data) => {
                if (data.msg && (data.msg.includes("Heartbeat") || data.msg.includes("HeartBeat"))) {
                    isReceived = true;
                    cleanup();
                    // 成功逻辑
                    UI.updateGlobalBar(true, appName, 'Tweak');
                    state.currentMonitoredApp = { name: appName, bundleId, mode: 'tweak', deviceIp };
                    resolve(true);
                }
            };

            if (state.socket) state.socket.on('heart_log', onHeartLog);

            const cleanup = () => {
                if (state.socket) state.socket.off('heart_log', onHeartLog);
                clearInterval(timer);
            };

            // 倒计时
            let timeLeft = timeoutSeconds;
            const timer = setInterval(() => {
                timeLeft--;
                if (timeLeft <= 0) {
                    cleanup();
                    if (!isReceived) {
                        // 等待超时，提示用户进行修改
                        UI.updateGlobalBar(true, appName, 'Tweak 未激活'); 
                        state.currentMonitoredApp = { name: appName, bundleId, mode: 'tweak', deviceIp };
                        
                        UI.alert(
                            "等待超时", 
                            "Tweak插件已部署，但未收到加载成功的心跳信号！\n\n如不是目标App安全防护导致，可按以下方案尝试后重新开启监控：\n1. 检查“本地网络”权限\n操作：设置 (Settings) -> 目标App -> 查看“本地网络”开关是否开启。\n2. 检查“无线数据”权限\n操作：设置 -> 目标App -> 查看“无线与蜂窝移动网”开关是否开启。\n3. 检查VPN或代理软件\n操作：关闭所有VPN和代理软件，确保手机纯净的网络通信环境。", 
                            "⚠️", "warning"
                        );
                        resolve(false);
                        // 启动失败，将 SDK 列表恢复到初始状态
                        UI.resetSDKTable('default');
                    }
                }
            }, 1000);
        });
    },

    // 停止监控
    stopMonitor: async () => {
        if (!state.currentMonitoredApp) return;
        // 根据模式区分提示文案
        const msg = state.currentMonitoredApp.mode === 'tweak' 
            ? "确定停止当前监控任务吗？\n将关闭目标应用，请确保SSH连通，以便彻底清除注入插件！"
            : "确定停止当前监控任务吗？\n将关闭目标应用，以便清除注入脚本！";

        if (!(await UI.confirm("停止监控", msg, "🛑", "danger", "停止"))) return;
        
        const { mode, deviceIp, bundleId } = state.currentMonitoredApp;

        try {
            if (mode === 'tweak') {
                await API.stopTweakMonitor(deviceIp, bundleId);
            } else {
                await API.stopMonitor();
            }
        } catch (e) {
            console.error("[stopMonitor] 发生错误:", e.message);
            UI.alert("提示", "停止指令发送异常: " + e.message, "⚠️", "warning");
        } finally {
            // 无论成功失败，强制重置 UI
            state.currentMonitoredApp = null;
            UI.updateGlobalBar(false);
        }
    },

    // 刷新应用列表
    refreshApps: async () => {
        const btn = document.getElementById('refreshBtn');
        if (!btn) return;
        
        btn.disabled = true;
        // 显示加载占位
        const tbody = document.getElementById('appTableBody');
        tbody.innerHTML = `<tr><td colspan="5" class="p-0 border-0"><div class="d-flex flex-column align-items-center justify-content-center text-muted" style="height: calc(100vh - 200px);"><div class="spinner-border text-primary mb-3"></div><p>正在获取应用数据...</p></div></td></tr>`;

        try {
            const res = await API.fetchApps();
            if (res.status === 'error') throw new Error(res.message);
            UI.renderAppList(res.data);
        } catch (e) {
            UI.alert("获取应用失败", e.message, "❌", "danger");
            tbody.innerHTML = `<tr><td colspan="5" class="text-center py-5 text-danger">数据获取失败</td></tr>`;
        } finally {
            btn.disabled = false;
        }
    }
};