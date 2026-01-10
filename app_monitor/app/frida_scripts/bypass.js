// =================================================================
// 反调试绕过模块 (Anti-Anti-Debug)
// =================================================================

function bypassAntiDebug() {
    console.log("[Anti-Anti-Debug] 加载模块: Anti-Debug Bypass");
    // 绕过 ptrace PT_DENY_ATTACH
    var ptracePtr = Module.findExportByName(null, "ptrace");
    if (ptracePtr) {
        Interceptor.replace(ptracePtr, new NativeCallback(function(request, pid, addr, data) {
            // PT_DENY_ATTACH 的值通常是 31
            if (request == 31) {
                console.log("[Anti-Anti-Debug] 拦截到 ptrace(PT_DENY_ATTACH)，已屏蔽！");
                return 0; // 返回成功，实际上什么都没做
            }
            // 其他 ptrace 调用放行
            return Function(ptracePtr)(request, pid, addr, data);
        }, 'int', ['int', 'int', 'pointer', 'pointer']));
    }

    // 绕过 sysctl 检测 P_TRACED
    var sysctlPtr = Module.findExportByName(null, "sysctl");
    if (sysctlPtr) {
        Interceptor.attach(sysctlPtr, {
            onEnter: function(args) {
                this.info = args[1]; 
                this.count = args[2].toInt32();
            },
            onLeave: function(retval) {
    
                // 这里可以实现更复杂的逻辑
            }
        });
    }
    
    console.log("[Anti-Anti-Debug] 反调试防护已激活");
}

// 立即执行
bypassAntiDebug();