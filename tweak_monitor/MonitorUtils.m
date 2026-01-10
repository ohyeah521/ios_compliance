#import "MonitorUtils.h"

static NSString *SERVER_URL = @"http://192.168.31.158:8080/api/report_log";

@implementation MonitorUtils


+ (NSString *)getCallStack
{
    RestoreSymbol *symbol = [[RestoreSymbol alloc] init];
    NSArray *symbolInfo = [symbol outputCallStackSymbol];
    // 获取失败直接返回默认值
    if (!symbolInfo || ![symbolInfo isKindOfClass:[NSArray class]]) {
        return @"Unknown Stack";
    }
    NSMutableArray *filteredStack = [NSMutableArray array];
    // 过滤干扰数据关键字
    NSArray *blackList = @[
        @"MonitorTweak.dylib",
        @"libdispatch.dylib",
        @"TweakEx.dylib"
    ];
    for (id item in symbolInfo) 
    {
        // 排除Null 对象或 nil
        if (item == nil || [item isKindOfClass:[NSNull class]]) {
            continue;
        }
        // 确保是字符串类型
        if (![item isKindOfClass:[NSString class]]) {
            continue;
        }
        NSString *line = (NSString *)item;
        // 排除内容为 "null" 的字符串或长度为 0 的行
        if ([line.lowercaseString isEqualToString:@"null"] || line.length == 0) {
            continue;
        }
        // 关键字过滤
        BOOL isBlacklisted = NO;
        for (NSString *keyword in blackList) {
            if ([line rangeOfString:keyword options:NSCaseInsensitiveSearch].location != NSNotFound) {
                isBlacklisted = YES;
                break;
            }
        }
        // 清洗存入数组
        if (!isBlacklisted) {
            NSString *cleanLine = [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (cleanLine.length > 0) {
                [filteredStack addObject:cleanLine];
            }
        }
    } 
    // 将结果并返回
    if (filteredStack.count > 0) {
        return [filteredStack componentsJoinedByString:@"\n"];
    }
    return @"Unknown Stack"; // 默认字符串
}

+ (void)loadConfig {
    NSString *configPath = @"/var/mobile/monitor_config.json";
    if ([[NSFileManager defaultManager] fileExistsAtPath:configPath]) {
        NSData *data = [NSData dataWithContentsOfFile:configPath];
        if (data) {
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            if (json && json[@"server_url"]) {
                SERVER_URL = json[@"server_url"];
                NSLog(@"[MonitorTweak] Updated server url: %@", SERVER_URL);
            }
        }
    }
}

+ (void)sendLog:(NSDictionary *)data {
    // 加载配置
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ [self loadConfig]; });

    // 检查 URL
    NSURL *url = [NSURL URLWithString:SERVER_URL];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    [req setHTTPMethod:@"POST"];
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    
    // 忽略缓存策略
    [req setCachePolicy:NSURLRequestReloadIgnoringLocalCacheData];
    
    NSError *error;
    NSData *body = [NSJSONSerialization dataWithJSONObject:data options:0 error:&error];
    if (!body) return;
    [req setHTTPBody:body];
    
    // 使用自定义配置，强制允许各种网络环境
    NSURLSessionConfiguration *conf = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    conf.allowsCellularAccess = YES; // 允许蜂窝
    conf.waitsForConnectivity = NO;  // 不等待，直接发
    conf.timeoutIntervalForRequest = 5.0;
    
    NSURLSession *session = [NSURLSession sessionWithConfiguration:conf];
    
    NSURLSessionDataTask *task = [session dataTaskWithRequest:req completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable connectionError) {
        if (connectionError) {
            NSLog(@"[MonitorTweak] Send log Network Error: %@", connectionError);
        }
    }];
    
    [task resume];
}

+ (void)reportLogWithCategory:(NSString *)category func:(NSString *)func content:(id)content methodDesc:(NSString *)methodDesc {
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    dict[@"type"] = @"info";
    dict[@"category"] = category;
    
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"yyyy/MM/dd, HH:mm:ss"; 
    dict[@"timestamp"] = [formatter stringFromDate:[NSDate date]];
    
    dict[@"func"] = func;
    dict[@"method"] = methodDesc;
    dict[@"content"] = [NSString stringWithFormat:@"%@", content ?: @"nil"];
    
    // 获取函数调用堆栈
    dict[@"stack"] = [self getCallStack] ?: @""; 
    
    [self sendLog:dict];
}

+ (void)reportFileLog:(NSString *)funcName opType:(NSString *)opType pathInfo:(NSString *)pathInfo {

    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    dict[@"type"] = @"file";
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"yyyy/MM/dd, HH:mm:ss"; 
    dict[@"timestamp"] = [formatter stringFromDate:[NSDate date]];
    dict[@"func"] = funcName;
    dict[@"op"] = opType;
    dict[@"method"] = pathInfo;
    dict[@"stack"] = [self getCallStack] ?: @""; 

    [self sendLog:dict];

}

// 发送 SDK 日志
+ (void)reportSDKLog:(NSArray *)sdkList {
    if (!sdkList || sdkList.count == 0) {
        return;
    }

    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    
    // 设置类型为 sdk，与 Python 后端对应
    dict[@"type"] = @"sdk"; 
    dict[@"data"] = sdkList; // 这里直接放入 SDK 数组

    [self sendLog:dict];
    NSLog(@"[MonitorTweak] Sending SDK count: %lu", (unsigned long)sdkList.count);
}


+ (void)sendHeartBeatLog {
    // 构造心跳消息
    NSMutableDictionary *heartbeat = [NSMutableDictionary dictionary];
    heartbeat[@"type"] = @"heart"; // 系统日志类型
    heartbeat[@"msg"] = @"✅ Tweak 插件已成功注入并加载！(Heartbeat)";
    NSLog(@"[MonitorTweak] Sending heart beat log!");
    // 发送
    [self sendLog:heartbeat];
}

@end
