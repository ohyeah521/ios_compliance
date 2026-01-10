#import "MonitorUtils.h"
#import <substrate.h>
#import <Security/Security.h>
#import <dlfcn.h>
#import "SDKDetector.h" 
// 定义 ptrace 函数原型
typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);
static ptrace_ptr_t orig_ptrace = NULL;

// 自己的 ptrace 实现反调试
int my_ptrace(int _request, pid_t _pid, caddr_t _addr, int _data) {
    // 31 == PT_DENY_ATTACH
    if (_request == 31) {
        NSLog(@"[MonitorTweak] 拦截到 ptrace(PT_DENY_ATTACH)，阻止应用自杀！");
        return 0; // 假装成功
    }
    // 其他调用放行
    return orig_ptrace(_request, _pid, _addr, _data);
}

// Keychain 原始函数指针
typedef OSStatus (*SecItemCopyMatchingType)(CFDictionaryRef query, CFTypeRef *result);
typedef OSStatus (*SecItemAddType)(CFDictionaryRef attributes, CFTypeRef *result);
typedef OSStatus (*SecItemUpdateType)(CFDictionaryRef query, CFDictionaryRef attributesToUpdate);
typedef OSStatus (*SecItemDeleteType)(CFDictionaryRef query);

static SecItemCopyMatchingType orig_SecItemCopyMatching = NULL;
static SecItemAddType orig_SecItemAdd = NULL;
static SecItemUpdateType orig_SecItemUpdate = NULL;
static SecItemDeleteType orig_SecItemDelete = NULL;


// 开始 Hook Keychain
#define CFDictToString(dict) (dict ? [NSString stringWithFormat:@"%@", (__bridge NSDictionary *)dict] : @"nil")

// 查询钥匙串项
OSStatus new_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    NSString *content = [NSString stringWithFormat:@"%@", CFDictToString(query)];
    
    [MonitorUtils reportLogWithCategory:@"Keychain" 
                                   func:@"SecItemCopyMatching" 
                                content:content 
                             methodDesc:@"查询Keychain"];
                             
    return orig_SecItemCopyMatching(query, result);
}

// 添加钥匙串项
OSStatus new_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    NSString *content = [NSString stringWithFormat:@"%@", CFDictToString(attributes)];
    
    [MonitorUtils reportLogWithCategory:@"Keychain" 
                                   func:@"SecItemAdd" 
                                content:content 
                             methodDesc:@"写入Keychain"];
                             
    return orig_SecItemAdd(attributes, result);
}

// 更新钥匙串
OSStatus new_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    NSString *content = [NSString stringWithFormat:@"查询: %@, 更新: %@", 
                         CFDictToString(query), CFDictToString(attributesToUpdate)];
    
    [MonitorUtils reportLogWithCategory:@"Keychain" 
                                   func:@"SecItemUpdate" 
                                content:content 
                             methodDesc:@"更新Keychain"];
                             
    return orig_SecItemUpdate(query, attributesToUpdate);
}

// 删除钥匙串
OSStatus new_SecItemDelete(CFDictionaryRef query) {
    NSString *content = [NSString stringWithFormat:@"%@", CFDictToString(query)];
    
    [MonitorUtils reportLogWithCategory:@"Keychain" 
                                   func:@"SecItemDelete" 
                                content:content 
                             methodDesc:@"删除Keychain"];
                             
    return orig_SecItemDelete(query);
}


// =======================================================
// 初始化入口
// =======================================================
%ctor {
    NSLog(@"--- [MonitorTweak] Loaded: %@ ---", [[NSBundle mainBundle] bundleIdentifier]);
    // 发送心跳
    [MonitorUtils sendHeartBeatLog];

    // Hook ptrace
    MSHookFunction((void *)MSFindSymbol(NULL, "_ptrace"), (void *)my_ptrace, (void **)&orig_ptrace);

    // 动态加载 Security 库并 Hook C 函数
    void *securityLib = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
    if (securityLib) {
        MSHookFunction((void *)SecItemCopyMatching, (void *)new_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching);
        MSHookFunction((void *)SecItemAdd, (void *)new_SecItemAdd, (void **)&orig_SecItemAdd);
        MSHookFunction((void *)SecItemUpdate, (void *)new_SecItemUpdate, (void **)&orig_SecItemUpdate);
        MSHookFunction((void *)SecItemDelete, (void *)new_SecItemDelete, (void **)&orig_SecItemDelete);
        dlclose(securityLib);
    } else {
        NSLog(@"[MonitorTweak] Failed to load!");
    }
    // 启动 SDK 检测
    startSDKDetection();
}