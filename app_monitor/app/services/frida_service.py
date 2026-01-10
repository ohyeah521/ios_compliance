import frida
from app.utils.image_helper import bytes_to_base64
from config import Config

class IOSDeviceService:
    @staticmethod
    def get_device():
        try:
            # 尝试获取 USB 设备
            # 增加 timeout 防止连接卡死
            return frida.get_usb_device(timeout=5)
        except Exception as e:
            print(f"[ERROR] 获取设备失败: {e}")
            raise ConnectionError(f"无法连接到 USB 设备: {str(e)}")

    @staticmethod
    def get_installed_apps():
        try:
            print("[-] 正在尝试连接设备...")
            device = IOSDeviceService.get_device()
            print(f"[-] 成功连接设备: {device.name} (ID: {device.id})")

            print("[-] 正在枚举应用... 这可能需要几秒钟")
            # 注意：scope='full' 会读取图标，速度较慢
            raw_apps = device.enumerate_applications(scope='full')
            print(f"[-] Frida 共扫描到 {len(raw_apps)} 个进程/应用")

            clean_apps = []
            
            for app in raw_apps:
                # 获取路径，如果获取失败默认为空字符串
                path = app.parameters.get('path', '')
                name = app.name

                # 过滤逻辑
                is_user_app = any(path.startswith(prefix) for prefix in Config.APP_PATH_PREFIXES)
                
                if is_user_app:
                    #print(f"[+] 匹配到用户应用: {name}")
                    
                    # 处理图标
                    icon_b64 = None
                    icons = app.parameters.get('icons', [])
                    if icons:
                        try:
                            icon_blob = icons[-1].get('image')
                            icon_b64 = bytes_to_base64(icon_blob)
                        except Exception as e:
                            print(f"[!] 图标处理失败 {name}: {e}")

                    clean_apps.append({
                        "name": app.name,
                        "bundle_id": app.identifier,
                        "version": app.parameters.get('version', 'Unknown'),
                        "path": path,
                        "icon": icon_b64
                    })
            
            print(f"[-] 过滤后剩余用户应用: {len(clean_apps)} 个")
            
            # 按名称排序
            clean_apps.sort(key=lambda x: x['name'])
            return clean_apps

        except frida.ServerNotRunningError:
            print("[ERROR] frida-server 未运行")
            raise RuntimeError("iOS 设备未运行 Frida Server")
        except frida.InvalidArgumentError:
            print("[ERROR] 找不到 USB 设备")
            raise RuntimeError("未找到设备，请检查 USB 连接")
        except Exception as e:
            print(f"[ERROR] 未知错误: {str(e)}")
            raise RuntimeError(f"Frida 内部错误: {str(e)}")