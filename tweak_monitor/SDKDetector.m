#import "SDKDetector.h"
#import "MonitorUtils.h" 

static void checkSDKs() {
    NSLog(@"[MonitorTweak] Starting SDK Check...");
    
    NSString *rulesPath = @"/var/mobile/monitor_sdk_rules.json";
    if (![[NSFileManager defaultManager] fileExistsAtPath:rulesPath]) {
        NSLog(@"[MonitorTweak] Rules file not found at %@", rulesPath);
        return;
    }

    NSData *data = [NSData dataWithContentsOfFile:rulesPath];
    NSError *error = nil;
    NSArray *rules = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    
    if (error || !rules || ![rules isKindOfClass:[NSArray class]]) {
        NSLog(@"[MonitorTweak] Failed to parse SDK rules: %@", error);
        return;
    }

    NSMutableArray *results = [NSMutableArray array];
    NSMutableSet *foundSet = [NSMutableSet set];

    for (NSDictionary *item in rules) {
        NSString *name = item[@"name"];
        // 去重防止重复添加
        if ([foundSet containsObject:name]) continue;

        BOOL isMatch = NO;
        NSString *matchDetail = @"";

        // 策略: Class 检测
        NSArray *classes = item[@"class"];
        if (classes && [classes isKindOfClass:[NSArray class]]) {
            for (NSString *className in classes) {
                if (NSClassFromString(className) != nil) {
                    isMatch = YES;
                    matchDetail = [NSString stringWithFormat:@"Class: %@", className];
                    break;
                }
            }
        }

        if (isMatch) {
            [foundSet addObject:name];
            
            id rawCat = item[@"category"];
            NSString *catStr = @"其它";
            if ([rawCat isKindOfClass:[NSArray class]] && [rawCat count] > 0) {
                catStr = [rawCat componentsJoinedByString:@", "];
            }

            [results addObject:@{
                @"name": name,
                @"category": catStr,
                @"match": matchDetail
            }];
        }
    }

    // 发送日志
    if (results.count > 0) {
        // 调用封装好的静态方法
        [MonitorUtils reportSDKLog:results];
        
        NSLog(@"[MonitorTweak] SDK Check Finished. Found: %lu", (unsigned long)results.count);
    } else {
        NSLog(@"[MonitorTweak] No SDKs matched.");
    }
}

void startSDKDetection() {
    // 延迟 3 秒执行，给 App 加载动态库的时间
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        checkSDKs();
    });
}