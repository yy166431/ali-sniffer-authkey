//
// AliSniffer.m  (safer boot; inject banner shown when app is ready)
// iOS 11+ / arm64 / -fobjc-arc
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <WebKit/WebKit.h>
#import <AVFoundation/AVFoundation.h>

#pragma mark - Utils

static UIViewController *AS_TopMostViewController(void) {
    __block UIViewController *top = nil;
    dispatch_block_t finder = ^{
        @try {
            // iOS 13+ 多 scene 适配
            if (@available(iOS 13.0, *)) {
                for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
                    if (scene.activationState != UISceneActivationStateForegroundActive) continue;
                    if (![scene isKindOfClass:[UIWindowScene class]]) continue;
                    UIWindowScene *ws = (UIWindowScene *)scene;
                    for (UIWindow *w in ws.windows) {
                        if (!w.isHidden && w.windowLevel == UIWindowLevelNormal) {
                            UIViewController *vc = w.rootViewController;
                            while (vc.presentedViewController) vc = vc.presentedViewController;
                            if (vc) { top = vc; return; }
                        }
                    }
                }
            }
            // 兜底（老系统）
            UIWindow *win = [UIApplication sharedApplication].keyWindow ?: [UIApplication sharedApplication].delegate.window;
            UIViewController *vc = win.rootViewController;
            while (vc.presentedViewController) vc = vc.presentedViewController;
            top = vc;
        } @catch (...) {}
    };
    if ([NSThread isMainThread]) finder(); else dispatch_sync(dispatch_get_main_queue(), finder);
    return top;
}

static void AS_PresentOK(NSString *title, NSString *message) {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            UIAlertController *ac = [UIAlertController alertControllerWithTitle:title
                                                                        message:message
                                                                 preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
            UIViewController *vc = AS_TopMostViewController();
            if (vc) {
                [vc presentViewController:ac animated:YES completion:nil];
            } else {
                // 再晚一点重试一次，避免冷启动太早
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                               dispatch_get_main_queue(), ^{
                    UIViewController *vc2 = AS_TopMostViewController();
                    if (vc2) [vc2 presentViewController:ac animated:YES completion:nil];
                });
            }
        } @catch (...) {}
    });
}

static void AS_CopyAlert(NSString *title, NSString *message, NSString *toCopy) {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            UIAlertController *ac = [UIAlertController alertControllerWithTitle:title
                                                                        message:message
                                                                 preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"复制"
                                                   style:UIAlertActionStyleDefault
                                                 handler:^(__unused UIAlertAction *a){
                UIPasteboard.generalPasteboard.string = toCopy;
            }]];
            [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
            UIViewController *vc = AS_TopMostViewController();
            if (vc) [vc presentViewController:ac animated:YES completion:nil];
        } @catch (...) {}
    });
}

#pragma mark - Matchers

static BOOL AS_urlContainsAuthKey(NSString *url) {
    if (!url) return NO;
    NSString *lower = url.lowercaseString;
    if ([lower containsString:@"auth_key="] || [lower containsString:@"auth_key%3d"] || [lower containsString:@"auth_key%3D"]) return YES;
    if ([lower containsString:@"authkey="] || [lower containsString:@"token="]) return YES;
    return NO;
}

static BOOL AS_urlLooksLikeStream(NSString *url) {
    if (!url) return NO;
    NSError *err = nil;
    NSRegularExpression *re =
    [NSRegularExpression regularExpressionWithPattern:@"(m3u8|\\.mpd(\\?|$)|\\.m4s(\\?|$)|\\.ts(\\?|$)|\\.mp4(\\?|$)|\\.flv(\\?|$)|^rtmps?:\\/\\/|^wss?:\\/\\/.*\\.flv)"
                                              options:NSRegularExpressionCaseInsensitive
                                                error:&err];
    if (!re) return NO;
    return [re firstMatchInString:url options:0 range:NSMakeRange(0, url.length)] != nil;
}

static BOOL AS_urlLooksLikeAliyunLogOrAlivc(NSURLRequest *req) {
    if (!req) return NO;
    NSURL *u = req.URL;
    if (u) {
        NSString *host = u.host.lowercaseString ?: @"";
        if ([host containsString:@"aliyuncs.com"] || [host containsString:@"alivc"] || [host containsString:@"alicdn"] || [host containsString:@"aliyun"]) return YES;
        NSString *s = u.absoluteString.lowercaseString ?: @"";
        if ([s containsString:@"alivc"] || [s containsString:@"aliplayer"] || [s containsString:@"alivc-aio"]) return YES;
    }
    NSDictionary *h = req.allHTTPHeaderFields;
    if (h) {
        for (NSString *k in h.allKeys) {
            NSString *lk = k.lowercaseString ?: @"";
            NSString *v = (h[k] ?: @"");
            if ([lk containsString:@"x-acs"] || [lk containsString:@"x-log"]) return YES;
            if ([lk isEqualToString:@"authorization"] && [v.uppercaseString containsString:@"LOG"]) return YES;
        }
    }
    return NO;
}

#pragma mark - Reporting

static void AS_ReportURLAndAlert(NSString *url) {
    if (!url.length) return;
    NSString *lower = url.lowercaseString ?: @"";
    if (!AS_urlContainsAuthKey(url) && !AS_urlLooksLikeStream(url) &&
        !([lower containsString:@"aliyun"] || [lower containsString:@"alivc"])) return;

    NSLog(@"[AS-Min] Found URL: %@", url);
    @try {
        [[NSNotificationCenter defaultCenter] postNotificationName:@"AliSnifferFoundURL"
                                                            object:nil
                                                          userInfo:@{@"url": url}];
    } @catch (...) {}
    AS_CopyAlert(@"抓到完整请求", [@"\n" stringByAppendingString:url], url);
}

#pragma mark - NSURLSession hooks

static id (*orig_NSURLSession_dataTaskWithRequest)(id, SEL, NSURLRequest *);
static id swz_NSURLSession_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *request) {
    id task = orig_NSURLSession_dataTaskWithRequest ? orig_NSURLSession_dataTaskWithRequest(self, _cmd, request) : nil;
    if (task && request) {
        @try {
            if (AS_urlContainsAuthKey(request.URL.absoluteString) || AS_urlLooksLikeAliyunLogOrAlivc(request)) {
                AS_ReportURLAndAlert(request.URL.absoluteString ?: @"(req-without-url)");
            }
            objc_setAssociatedObject(task, "as_task_req", request, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        } @catch(...) {}
    }
    return task;
}

static id (*orig_NSURLSession_dataTaskWithURL)(id, SEL, NSURL *);
static id swz_NSURLSession_dataTaskWithURL(id self, SEL _cmd, NSURL *url) {
    id task = orig_NSURLSession_dataTaskWithURL ? orig_NSURLSession_dataTaskWithURL(self, _cmd, url) : nil;
    if (task && url) {
        @try {
            NSMutableURLRequest *r = [NSMutableURLRequest requestWithURL:url];
            if (AS_urlContainsAuthKey(url.absoluteString) ||
                [url.absoluteString.lowercaseString containsString:@"aliyun"] ||
                [url.absoluteString.lowercaseString containsString:@"alivc"]) {
                AS_ReportURLAndAlert(url.absoluteString);
            }
            objc_setAssociatedObject(task, "as_task_req", r, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        } @catch(...) {}
    }
    return task;
}

static void (*orig_NSURLSessionTask_resume)(id, SEL);
static void swz_NSURLSessionTask_resume(id self, SEL _cmd) {
    @try {
        NSURLRequest *r = objc_getAssociatedObject(self, "as_task_req");
        if (!r && [self respondsToSelector:@selector(currentRequest)]) {
            @try { r = [self performSelector:@selector(currentRequest)]; } @catch(...) {}
        }
        NSString *u = r.URL.absoluteString;
        if (u.length) {
            if (AS_urlContainsAuthKey(u)) {
                AS_ReportURLAndAlert(u);
            } else if (AS_urlLooksLikeStream(u)) {
                AS_ReportURLAndAlert(u);
            } else if (AS_urlLooksLikeAliyunLogOrAlivc(r)) {
                AS_ReportURLAndAlert(u);
            }
            objc_setAssociatedObject(self, "as_task_reported", @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        }
    } @catch(...) {}
    if (orig_NSURLSessionTask_resume) orig_NSURLSessionTask_resume(self, _cmd);
}

static void AS_Swizzle(Class c, SEL sel, IMP newImp, IMP *origOut) {
    if (!c) return;
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    if (origOut) *origOut = (void *)method_getImplementation(m);
    method_setImplementation(m, newImp);
}

static void AS_Install_Session_Hooks(void) {
    @try {
        Class s = NSClassFromString(@"NSURLSession");
        if (s) {
            AS_Swizzle(s, @selector(dataTaskWithRequest:), (IMP)swz_NSURLSession_dataTaskWithRequest, (IMP *)&orig_NSURLSession_dataTaskWithRequest);
            AS_Swizzle(s, @selector(dataTaskWithURL:),     (IMP)swz_NSURLSession_dataTaskWithURL,     (IMP *)&orig_NSURLSession_dataTaskWithURL);
        }
        Class t = NSClassFromString(@"NSURLSessionTask");
        if (t) {
            AS_Swizzle(t, @selector(resume), (IMP)swz_NSURLSessionTask_resume, (IMP *)&orig_NSURLSessionTask_resume);
        }
        NSLog(@"[AS-Min] NSURLSession hooks installed.");
    } @catch (...) {
        NSLog(@"[AS-Min] NSURLSession hooks failed.");
    }
}

#pragma mark - AVPlayerItem (access log)

static void AS_Observe_AVItem(AVPlayerItem *item) {
    @try {
        [[NSNotificationCenter defaultCenter] addObserverForName:AVPlayerItemNewAccessLogEntryNotification
                                                          object:item
                                                           queue:[NSOperationQueue mainQueue]
                                                      usingBlock:^(__unused NSNotification *note) {
            @try {
                AVPlayerItemAccessLog *log = item.accessLog;
                if (!log) return;
                NSArray *events = [log events];
                if (![events isKindOfClass:[NSArray class]] || events.count == 0) return;
                id ev = events.lastObject;
                NSString *uri = nil;
                if ([ev respondsToSelector:NSSelectorFromString(@"URI")]) {
                    uri = [ev valueForKey:@"URI"];
                }
                if (uri.length) {
                    NSString *l = uri.lowercaseString;
                    if (AS_urlContainsAuthKey(uri) || AS_urlLooksLikeStream(uri) ||
                        [l containsString:@"aliyun"] || [l containsString:@"alivc"]) {
                        AS_ReportURLAndAlert(uri);
                    }
                }
            } @catch (...) {}
        }];
    } @catch (...) {}
}

static id (*orig_AVPlayerItem_initWithURL)(id, SEL, NSURL *);
static id swz_AVPlayerItem_initWithURL(id self, SEL _cmd, NSURL *URL) {
    id item = orig_AVPlayerItem_initWithURL ? orig_AVPlayerItem_initWithURL(self, _cmd, URL) : nil;
    if (item) AS_Observe_AVItem((AVPlayerItem *)item);
    return item;
}

static void AS_Install_AV_Hooks(void) {
    @try {
        Class c = NSClassFromString(@"AVPlayerItem");
        if (c) {
            Method m = class_getInstanceMethod(c, @selector(initWithURL:));
            if (m) {
                orig_AVPlayerItem_initWithURL = (void *)method_getImplementation(m);
                method_setImplementation(m, (IMP)swz_AVPlayerItem_initWithURL);
            }
        }
        NSLog(@"[AS-Min] AV hooks installed.");
    } @catch (...) {
        NSLog(@"[AS-Min] AV hooks failed.");
    }
}

#pragma mark - WKWebView (轻量注入)

@interface _AS_WKHandler : NSObject <WKScriptMessageHandler>
@end
@implementation _AS_WKHandler
- (void)userContentController:(WKUserContentController *)uc didReceiveScriptMessage:(WKScriptMessage *)m {
    if (![m.name isEqualToString:@"_S"]) return;
    NSString *s = nil;
    if ([m.body isKindOfClass:NSString.class]) s = (NSString *)m.body;
    else if ([m.body isKindOfClass:NSURL.class]) s = [(NSURL *)m.body absoluteString];
    if (s.length) {
        NSString *l = s.lowercaseString;
        if (AS_urlContainsAuthKey(s) || AS_urlLooksLikeStream(s) ||
            [l containsString:@"aliyun"] || [l containsString:@"alivc"]) {
            AS_ReportURLAndAlert(s);
        }
    }
}
@end

static void AS_AddWKScripts(WKWebViewConfiguration *cfg) {
    if (!cfg) return;
    static void *kKey = &kKey;
    if (objc_getAssociatedObject(cfg, kKey)) return;
    objc_setAssociatedObject(cfg, kKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    _AS_WKHandler *h = [_AS_WKHandler new];
    @try { [cfg.userContentController addScriptMessageHandler:h name:@"_S"]; } @catch (...) {}

    NSString *js =
    @"(function(){try{"
     "if(window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers._S)window.webkit.messageHandlers._S.postMessage('AS_JS_OK');"
     "function R(u){try{if(u&&/(auth_key=|m3u8|\\.mpd(\\?|$)|\\.m4s(\\?|$)|\\.ts(\\?|$)|\\.mp4(\\?|$)|\\.flv(\\?|$)|^rtmps?:\\/\\/|^wss?:\\/\\/.*\\.flv|alivc|aliyuncs)/i.test(u))window.webkit.messageHandlers._S.postMessage(u);}catch(e){}}"
     "if(window.fetch){var _f=window.fetch;window.fetch=function(){var u=arguments[0];try{if(typeof u==='string')R(u);}catch(e){}return _f.apply(this,arguments).then(function(r){try{if(r&&r.url)R(r.url);}catch(e){}return r;});};}"
     "if(window.XMLHttpRequest){var X=window.XMLHttpRequest;var o=X.prototype.open;X.prototype.open=function(m,u){try{R(u);}catch(e){}return o.apply(this,arguments);};}"
     "if(window.HTMLMediaElement){var d=Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype,'src');if(d&&d.set){Object.defineProperty(HTMLMediaElement.prototype,'src',{set:function(v){try{R(v);}catch(e){}return d.set.call(this,v);},get:d.get});}}"
     "}catch(e){}})();";

    WKUserScript *sc = [[WKUserScript alloc] initWithSource:js
                                              injectionTime:WKUserScriptInjectionTimeAtDocumentStart
                                           forMainFrameOnly:NO];
    @try { [cfg.userContentController addUserScript:sc]; } @catch (...) {}
}

static id (*orig_wk_init_frame)(id, SEL, CGRect, WKWebViewConfiguration *);
static id swz_wk_init_frame(id self, SEL _cmd, CGRect frame, WKWebViewConfiguration *cfg) {
    if (cfg) AS_AddWKScripts(cfg);
    return orig_wk_init_frame(self, _cmd, frame, cfg);
}

static id (*orig_wk_init_coder)(id, SEL, NSCoder *);
static id swz_wk_init_coder(id self, SEL _cmd, NSCoder *coder) {
    WKWebViewConfiguration *cfg = nil;
    @try { cfg = [coder decodeObjectForKey:@"configuration"]; } @catch (...) {}
    if (cfg) AS_AddWKScripts(cfg);
    return orig_wk_init_coder(self, _cmd, coder);
}

static void AS_Install_WK_Hooks(void) {
    @try {
        Class c = NSClassFromString(@"WKWebView");
        if (!c) return;
        Method m1 = class_getInstanceMethod(c, @selector(initWithFrame:configuration:));
        if (m1) { orig_wk_init_frame = (void *)method_getImplementation(m1);
                  method_setImplementation(m1, (IMP)swz_wk_init_frame); }
        Method m2 = class_getInstanceMethod(c, @selector(initWithCoder:));
        if (m2) { orig_wk_init_coder = (void *)method_getImplementation(m2);
                  method_setImplementation(m2, (IMP)swz_wk_init_coder); }
        NSLog(@"[AS-Min] WK hooks installed.");
    } @catch (...) {
        NSLog(@"[AS-Min] WK hooks failed.");
    }
}

#pragma mark - Safe bootstrap (no early UI)

static void AS_ShowInjectedOnceWhenReady(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        // 等应用激活/进入前台后再弹，避免冷启动早期触碰 UI
        void (^show)(void) = ^{
            AS_PresentOK(@"AliSniffer", @"注入成功（minimal + auth_key + aliyun）");
        };
        dispatch_async(dispatch_get_main_queue(), ^{
            if ([UIApplication sharedApplication].applicationState == UIApplicationStateActive) {
                show();
            } else {
                [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                                  object:nil
                                                                   queue:[NSOperationQueue mainQueue]
                                                              usingBlock:^(__unused NSNotification * _Nonnull note) {
                    show();
                }];
            }
        });
    });
}

__attribute__((constructor))
static void AS_Bootstrap_All(void) {
    @try {
        AS_Install_Session_Hooks();
        AS_Install_AV_Hooks();
        AS_Install_WK_Hooks();
        NSLog(@"[AS-Min] AliSniffer bootstrap done.");
        AS_ShowInjectedOnceWhenReady();
    } @catch (...) {
        NSLog(@"[AS-Min] AliSniffer bootstrap error.");
    }
}
