import frida
import os
import time
import logging
from pathlib import Path
from app import socketio

# 日志
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

class MonitorService:
    # 类属性存储状态
    session = None
    script = None
    pid = None
    bundle_id = None

    @staticmethod
    def _load_js_source():
        """读取并拼接所有的 JS 模块文件，并注入 SDK 规则"""
        files_order = ['bypass.js', 'network.js', 'file.js', 'privacy.js', 'antilock.js', 'sdk.js', 'loader.js']
        
        # 获取 frida_scripts 目录路径
        base_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frida_scripts')
        full_source = ""
        
        try:
            # 拼接所有 JS 文件
            for filename in files_order:
                file_path = os.path.join(base_path, filename)
                if os.path.exists(file_path):
                    with open(file_path, 'r', encoding='utf-8') as f:
                        full_source += f"\n// --- FILE: {filename} ---\n"
                        full_source += f.read() + "\n"
                else:
                    print(f"[!] Warning: JS Module not found: {filename}")

            # 读取 SDK 规则 JSON 文件
            rules_path = os.path.join(base_path, 'ios_sdk_rules.json')
            rules_content = "[]" # 默认空数组，防止文件不存在导致 JS 语法错误
            
            if os.path.exists(rules_path):
                with open(rules_path, 'r', encoding='utf-8') as f:
                    # 读取内容，去掉可能的换行符，保证是合法的 JSON 字符串
                    rules_content = f.read().strip()
            else:
                print("[!] Warning: ios_sdk_rules.json not found")

            # 使用SDK特征规则替换 JS 中的占位符
            full_source = full_source.replace('__SDK_RULES_JSON__', rules_content)

        except Exception as e:
            print(f"[!] JS Loading Error: {e}")
            return None
            
        return full_source

    @classmethod
    def _get_process(cls, device, bundle_id):
        """获取目标进程PID，优先Spawn，失败则查找现有进程"""
        try:
            # 尝试启动应用
            pid = device.spawn([bundle_id])
            logger.info(f"应用已启动 (Spawn)，PID: {pid}")
            device.resume(pid) # 早点调用resume防止卡死，视情况调整
            return pid
        except (frida.NotSupportedError, frida.ServerNotRunningError):
            logger.info("Spawn不支持或失败，尝试查找运行中的进程...")
        except Exception as e:
            logger.warning(f"Spawn尝试失败: {e}")
            
        raise Exception(f"无法定位应用 {bundle_id}，请确保应用已安装且设备已解锁。")

    @classmethod
    def _attach_with_retry(cls, device, target, max_retries=3):
        """带重试机制的附加进程"""
        for i in range(max_retries):
            try:
                session = device.attach(target)
                logger.info(f"成功附加到进程: {target}")
                return session
            except Exception as e:
                if i == max_retries - 1: raise e
                logger.warning(f"附加失败 ({i+1}/{max_retries})，1秒后重试: {e}")
                time.sleep(1)

    @classmethod
    def _on_message(cls, message, data):
        """Frida消息回调处理"""
        if message['type'] == 'send':
            payload = message['payload']
            msg_type = payload.get('type')
            # 消息类型映射
            event_map = {
                'network': 'network_log',
                'file': 'file_log',
                'info': 'info_log',
                'sdk': 'sdk_log',
                'heart': 'heart_log',
                'sys_log': 'sys_log'
            }
            if msg_type in event_map:
                socketio.emit(event_map[msg_type], payload)
        elif message['type'] == 'error':
            err_msg = message.get('description',str(message))
            if 'destroyed' not in str(err_msg):
                logger.error(f"Script Error: {err_msg}")
                socketio.emit('sys_log', {'msg': f"脚本错误: {err_msg}"})

    @classmethod
    def start_monitoring(cls, bundle_id):
        """启动监控流程"""
        cls.stop_monitoring() # 先清理旧会话
        cls.bundle_id = bundle_id

        try:
            device = frida.get_usb_device()
            logger.info(f"准备监控: {bundle_id}")

            # 获取PID (Spawn 或 Attach)
            cls.pid = cls._get_process(device, bundle_id)

            # 附加进程
            cls.session = cls._attach_with_retry(device, cls.pid)
            
            # 加载脚本
            js_source = cls._load_js_source()
            if not js_source: raise Exception("JS脚本加载为空")
            
            cls.script = cls.session.create_script(js_source)
            cls.script.on('message', cls._on_message)
            cls.script.load()

            # 如果是Spawn的应用，再次确保运行
            device.resume(cls.pid)

            msg = f"监控已成功启动 (PID: {cls.pid})"
            socketio.emit('sys_log', {'msg': msg})
            return True, "监控已启动"

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Start Error: {error_msg}")
            
            # 简化的错误提示逻辑
            tips = "未知错误"
            if "PermissionDenied" in error_msg: tips = "权限拒绝：请检查证书签名或设备信任设置"
            elif "process not found" in error_msg.lower(): tips = "未找到进程：请手动启动应用"
            elif "server" in error_msg.lower(): tips = "连接失败：请检查Frida-server版本"
            
            socketio.emit('sys_log', {'msg': f"启动失败: {tips}\nDetails: {error_msg}"})
            return False, error_msg

    @classmethod
    def stop_monitoring(cls):
        """停止监控并清理资源"""
        msg = "无运行任务"
        try:
            if cls.script:
                try: cls.script.unload()
                except: pass
            
            if cls.session:
                try: cls.session.detach()
                except: pass
                
            # 杀掉进程，
            if cls.pid:
                try:
                    frida.get_usb_device().kill(cls.pid)
                    msg = f"监控停止，进程已结束: {cls.bundle_id}"
                except:
                    msg = "监控停止 (进程已结束或无法访问)"
            
            socketio.emit('sys_log', {'msg': msg})

        except Exception as e:
            msg = f"停止时发生错误: {e}"
            logger.error(msg)
        finally:
            cls.session = None
            cls.script = None
            cls.pid = None
            cls.bundle_id = None
            
        return True, msg