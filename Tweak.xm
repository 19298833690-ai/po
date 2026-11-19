// Tweak.xm — 注入进 CodeV.app 的 小七验证 绕过 (无需 Frida)
// 编译: theos (iphoneos-arm64 rootless 亦可), 产物注入到
//       Payload/CodeV.app/Frameworks/ 下, 或在主二进制里加 LC_LOAD_DYLIB

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <substrate.h>
#import <sys/sysctl.h>

static const NSUInteger kNSUTF8 = 4;
static const long long kFarExpiry = 4070908799LL;

#pragma mark - 伪造数据

static NSDictionary *XQBInner(void) {
    long long t = (long long)[[NSDate date] timeIntervalSince1970];
    return @{
        @"verified": @YES, @"verify": @YES,
        @"expiry": @(kFarExpiry), @"expire": @(kFarExpiry), @"expire_time": @(kFarExpiry),
        @"server_time": @(t), @"server_expiry": @(kFarExpiry),
        @"token_expires_at": @(kFarExpiry), @"nonce": @"0",
        @"card_key": @"LOCAL-UNLOCK", @"card_hash": [@"" stringByPaddingToLength:64 withString:@"0" startingAtIndex:0],
        @"session_token": @"tweak-local-session", @"token": @"tweak-local-session",
        @"rsa_signature": @"LOCAL", @"signature": @"LOCAL",
        @"bound_grant": @"LOCAL", @"bound_signature": @"LOCAL",
        @"proto_ver": @1, @"offset_protocol": @1, @"offset_version": @1,
        @"client_key": @"LOCAL", @"request_proof": @"LOCAL",
        @"device_unique_id": @"LOCAL-DEVICE", @"device_id": @"LOCAL-DEVICE",
        @"device_info": @{@"model": @"iPhone", @"system": @"18.0", @"name": @"iPhone"},
        @"game": @"valorant", @"status": @"online", @"is_jailbroken": @0
    };
}

static NSData *XQBForge(NSString *body) {
    NSDictionary *inner = XQBInner();
    NSDictionary *root = @{
        @"success": @YES, @"code": @0, @"status": @1, @"message": @"ok", @"msg": @"ok",
        @"error": @"", @"debug_enabled": @NO, @"need_update": @NO, @"force_update": @NO,
        @"latest_version": @"1.25.0", @"version": @"1.25.0", @"update_message": @"",
        @"action": ([body rangeOfString:@"heartbeat" options:NSCaseInsensitiveSearch].location != NSNotFound)
                    ? @"heartbeat" : @"online",
        @"data": inner, @"result": inner
    };
    return [NSJSONSerialization dataWithJSONObject:root options:0 error:nil];
}

static BOOL XQBIsAuth(NSString *body) {
    if (!body) return NO;
    static NSArray *kws;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        kws = @[@"card_key", @"authorize", @"verify", @"heartbeat", @"action", @"device_unique_id", @"expiry"];
    });
    for (NSString *k in kws)
        if ([body rangeOfString:k options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
    return NO;
}

#pragma mark - 反调试 nerf

static int (*orig_ptrace)(int, pid_t, caddr_t, int);
static int fake_ptrace(int request, pid_t pid, caddr_t addr, int data) { return 0; }

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int fake_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    if (ret == 0 && oldp && name && namelen >= 2 && name[0] == CTL_KERN && name[1] == KERN_PROC) {
        struct kinfo_proc *kp = (struct kinfo_proc *)oldp;
        kp->kp_proc.p_flag &= ~P_TRACED;
    }
    return ret;
}

static BOOL xqb_yes(id self, SEL _cmd) { return YES; }

static IMP (*orig_class_addMethod)(Class, SEL, IMP, const char *);
static IMP my_class_addMethod(Class cls, SEL sel, IMP imp, const char *types) {
    const char *name = sel_getName(sel);
    const char *cn = class_getName(cls);
    if (strcmp(cn, "xqbsphp") == 0) {
        NSLog(@"[xqbsphp] addMethod %s", name);
        if (strcmp(name, "verifyRSASignature:signature:") == 0 ||
            strcmp(name, "verify:") == 0 ||
            strcmp(name, "isVerified") == 0 ||
            strcmp(name, "verified") == 0) {
            return orig_class_addMethod(cls, sel, (IMP)xqb_yes, types);
        }
    }
    return orig_class_addMethod(cls, sel, imp, types);
}

__attribute__((constructor)) static void XQBInit(void) {
    MSHookFunction((void *)ptrace, (void *)fake_ptrace, (void **)&orig_ptrace);
    MSHookFunction((void *)sysctl, (void *)fake_sysctl, (void **)&orig_sysctl);
    MSHookFunction((void *)class_addMethod, (void *)my_class_addMethod, (void **)&orig_class_addMethod);
}

#pragma mark - Hook

%hook NSURLSession

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request
                            completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))completionHandler {
    NSString *body = request.HTTPBody
        ? [[NSString alloc] initWithData:request.HTTPBody encoding:kNSUTF8] : @"";
    if (!XQBIsAuth(body)) return %orig;

    void (^orig)(NSData *, NSURLResponse *, NSError *) = completionHandler;
    void (^fake)(NSData *, NSURLResponse *, NSError *) = ^(NSData *d, NSURLResponse *r, NSError *e) {
        if (orig) orig(XQBForge(body), r, nil);
    };
    return %orig(request, fake);
}

%end

%hook xqbsphp

- (BOOL)verifyRSASignature:(id)a signature:(id)b { return YES; }
- (BOOL)verify:(id)a { return YES; }
- (BOOL)isVerified { return YES; }

%end