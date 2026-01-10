#import "Symbol/RestoreSymbol.h"
#import <Foundation/Foundation.h>

@interface MonitorUtils : NSObject
// 函数声明
+ (void)reportLogWithCategory:(NSString *)category 
                         func:(NSString *)func 
                      content:(id)content 
                   methodDesc:(NSString *)methodDesc;

+ (void)reportFileLog:(NSString *)funcName 
               opType:(NSString *)opType 
             pathInfo:(NSString *)pathInfo;
                        
// 发送 SDK 检测结果
+ (void)reportSDKLog:(NSArray *)sdkList;
// 发送 插件加载成功结果
+ (void)sendHeartBeatLog;

+ (void)sendLog:(NSDictionary *)data;

@end