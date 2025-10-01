//
// AliSniffer.m  (minimal, auth_key-aware)
// 目标：最小可注入 dylib，尽快抓到带 auth_key 的直播源（优先匹配 auth_key）
// 依赖：Foundation / UIKit / WebKit / AVFoundation
// 编译：-fobjc-arc，arm64，iOS 11+，动态库
// 说明：当 URL 包含 "auth_key"（不区分大小写）时优先上报；否则仍会匹配常见流后缀（m3u8/ts/mp4/flv等）
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <WebKit/WebKit.h>
#import <AVFoundation/AVFoundation.h>

#pragma mark - Helpers

static BOOL AS_urlContainsAuthKey(NSString *url) {
    if (!url) return NO;
    NSString *lower = [url lowercaseString];
    if ([lower containsString:@"auth_key="] || [lower containsString:@"auth_key%3d"] || [lower containsString:@"auth_key%3D"]) {
        return YES;
    }
    // some apps may use authkey or token param names; you can extend here
    if ([lower containsString:@"authkey="] || [lower containsString:@"token="]) return YES;
    return NO;
}

static BOOL AS_urlLooksLikeStream(NSString *url) {
    if (!url) return NO;
    NSError *err = nil;
    NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:@"(m3u8|\\.mpd(\\?|$)|\\.m4s(\\?|$)|\\.ts(\\?|$)|\\.mp4(\\?|$)|\\.flv(\\?|$)|^rtmps?:\\/\\/|^wss?:\\/\\/.*\\.flv)"
                                                                            options:NSRegularExpressionCaseInsensitive
                                                                              error:&err];
    if (!re) return NO;
    NSTextCheckingResult *m = [re firstMatchInString:url options:0 range:NSMakeRange(0, url.length)];
    return (m != nil);
}

#pragma mark - 简单上报（含弹窗复制）

static void AS_ReportURLAndAlert(NSString *url) {
    if (!url.length) return;
    // Only report if it contains auth_key OR looks like a stream
    if (!AS_urlContainsAuthKey(url) && !AS_urlLooksLikeStream(url)) return;
    NSLog(@"[AS-Min] Found URL: %@", url);
    @try {
        [[NSNotificationCenter defaultCenter] postNotificationName:@"AliSnifferFoundURL"
                                                            object:nil
                                                          userInfo:@{@"url": url}];
    } @catch (...) {}
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            NSString *title = @"抓到完整请求";
            NSString *msg   = [NSString stringWithFormat:@"\n%@", url];
            UIAlertController *ac = [UIAlertController alertControllerWithTitle:title
                                                                        message:msg
                                                                 preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"复制"
                                                   style:UIAlertActionStyleDefault
                                                 handler:^(__unused UIAlertAction *a){
                UIPasteboard.generalPasteboard.string = url;
            }]];
            [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];

            UIWindow *win = UIApplication.sharedApplication.keyWindow;
            UIViewController *vc = win.rootViewController;
            while (vc.presentedViewController) vc = vc.presentedViewController;
            if (!vc) vc = [UIApplication sharedApplication].delegate.window.rootViewController;
            if (vc) {
                [vc presentViewController:ac animated:YES completion:nil];
            } else {
                UIWindow *w = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
                w.windowLevel = UIWindowLevelAlert + 1000;
                UIViewController *tmp = [UIViewController new];
                w.rootViewController = tmp;
                [w makeKeyAndVisible];
                [tmp presentViewController:ac animated:YES completion:nil];
            }
        } @catch (...) {}
    });
}

#pragma mark - NSURLSession / NSURLSessionTask

static id (*as_orig_NSURLSession_dataTaskWithRequest)(id, SEL, NSURLRequest *);
static id as_swz_NSURLSession_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *request) {
    id task = as_orig_NSURLSession_dataTaskWithRequest ? as_orig_NSURLSession_dataTaskWithRequest(self, _cmd, request) : nil;
    if (task && request.URL) {
        @try { objc_setAssociatedObject(task, "as_task_req", request, OBJC_ASSOCIATION_RETAIN_NONATOMIC); } @catch(...) {}
    }
    return task;
}

static id (*as_orig_NSURLSession_dataTaskWithURL)(id, SEL, NSURL *);
static id as_swz_NSURLSession_dataTaskWithURL(id self, SEL _cmd, NSURL *url) {
    id task = as_orig_NSURLSession_dataTaskWithURL ? as_orig_NSURLSession_dataTaskWithURL(self, _cmd, url) : nil;
    if (task && url) {
        @try {
            NSMutableURLRequest *r = [NSMutableURLRequest requestWithURL:url];
            objc_setAssociatedObject(task, "as_task_req", r, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        } @catch(...) {}
    }
    return task;
}

static void (*as_orig_NSURLSessionTask_resume)(id, SEL);
static void as_swz_NSURLSessionTask_resume(id self, SEL _cmd) {
    @try {
        NSURLRequest *r = objc_getAssociatedObject(self, "as_task_req");
        if (!r && [self respondsToSelector:@selector(currentRequest)]) {
            @try { r = [self performSelector:@selector(currentRequest)]; } @catch(...) {}
        }
        NSString *u = r.URL.absoluteString;
        if (u.length) {
            // Prefer reporting if URL contains auth_key
            if (AS_urlContainsAuthKey(u)) {
                AS_ReportURLAndAlert(u);
            } else if (AS_urlLooksLikeStream(u)) {
                AS_ReportURLAndAlert(u);
            } else {
                // Not a stream and no auth_key => ignore
            }
            NSNumber *done = objc_getAssociatedObject(self, "as_task_reported");
            if (!done || !done.boolValue) {
                objc_setAssociatedObject(self, "as_task_reported", @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            }
        }
    } @catch(...) {}
    if (as_orig_NSURLSessionTask_resume) as_orig_NSURLSessionTask_resume(self, _cmd);
}

static void as_swizzle(Class c, SEL sel, IMP newImp, IMP *origOut) {
    if (!c) return;
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    if (origOut) *origOut = method_getImplementation(m);
    method_setImplementation(m, newImp);
}

__attribute__((constructor))
static void as_install_session_hooks(void) {
    @try {
        Class s = NSClassFromString(@"NSURLSession");
        if (s) {
            as_swizzle(s, @selector(dataTaskWithRequest:), (IMP)as_swz_NSURLSession_dataTaskWithRequest, (IMP *)&as_orig_NSURLSession_dataTaskWithRequest);
            as_swizzle(s, @selector(dataTaskWithURL:),     (IMP)as_swz_NSURLSession_dataTaskWithURL,     (IMP *)&as_orig_NSURLSession_dataTaskWithURL);
        }
        Class t = NSClassFromString(@"NSURLSessionTask");
        if (t) {
            as_swizzle(t, @selector(resume), (IMP)as_swz_NSURLSessionTask_resume, (IMP *)&as_orig_NSURLSessionTask_resume);
        }
        NSLog(@"[AS-Min] NSURLSession hooks installed.");
    } @catch (...) {
        NSLog(@"[AS-Min] NSURLSession hooks failed.");
    }
}

#pragma mark - AVPlayerItem (AccessLog)

static void as_observe_AVItem_once(AVPlayerItem *item) {
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
                    // Only report if auth_key present or looks like stream
                    if (AS_urlContainsAuthKey(uri) || AS_urlLooksLikeStream(uri)) {
                        AS_ReportURLAndAlert(uri);
                    }
                }
            } @catch (...) {}
        }];
    } @catch (...) {}
}

static id (*as_orig_AVPlayerItem_initWithURL)(id, SEL, NSURL *);
static id as_swz_AVPlayerItem_initWithURL(id self, SEL _cmd, NSURL *URL) {
    id item = as_orig_AVPlayerItem_initWithURL ? as_orig_AVPlayerItem_initWithURL(self, _cmd, URL) : nil;
    if (item) as_observe_AVItem_once((AVPlayerItem *)item);
    return item;
}

__attribute__((constructor))
static void as_install_av_hooks(void) {
    @try {
        Class c = NSClassFromString(@"AVPlayerItem");
        if (c) {
            Method m = class_getInstanceMethod(c, @selector(initWithURL:));
            if (m) {
                as_orig_AVPlayerItem_initWithURL = (void *)method_getImplementation(m);
                method_setImplementation(m, (IMP)as_swz_AVPlayerItem_initWithURL);
            }
        }
        NSLog(@"[AS-Min] AV hooks installed.");
    } @catch (...) {
        NSLog(@"[AS-Min] AV hooks failed.");
    }
}

#pragma mark - WKWebView 注入（轻量）

@interface _AS_WKHandler : NSObject <WKScriptMessageHandler>
@end
@implementation _AS_WKHandler
- (void)userContentController:(WKUserContentController *)uc didReceiveScriptMessage:(WKScriptMessage *)m {
    if (![m.name isEqualToString:@"_S"]) return;
    NSString *s = nil;
    if ([m.body isKindOfClass:NSString.class]) s = (NSString *)m.body;
    else if ([m.body isKindOfClass:NSURL.class]) s = [(NSURL *)m.body absoluteString];
    if (s.length) {
        // prefer auth_key hits
        if (AS_urlContainsAuthKey(s) || AS_urlLooksLikeStream(s)) AS_ReportURLAndAlert(s);
    }
}
@end

static void as_add_wk_scripts(WKWebViewConfiguration *cfg) {
    if (!cfg) return;
    static void *kKey = &kKey;
    if (objc_getAssociatedObject(cfg, kKey)) return;
    objc_setAssociatedObject(cfg, kKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    _AS_WKHandler *h = [_AS_WKHandler new];
    @try { [cfg.userContentController addScriptMessageHandler:h name:@"_S"]; } @catch (...) {}

    NSString *js =
    @"(function(){try{"
     "if(window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers._S)"
     "window.webkit.messageHandlers._S.postMessage('AS_JS_OK');"
     "function R(u){try{if(u&&/(auth_key=|m3u8|\\.mpd(\\?|$)|\\.m4s(\\?|$)|\\.ts(\\?|$)|\\.mp4(\\?|$)|\\.flv(\\?|$)|^rtmps?:\\/\\/|^wss?:\\/\\/.*\\.flv)/i.test(u))window.webkit.messageHandlers._S.postMessage(u);}catch(e){}}"
     "if(window.fetch){var _f=window.fetch;window.fetch=function(){var u=arguments[0];try{if(typeof u==='string')R(u);}catch(e){}return _f.apply(this,arguments).then(function(r){try{if(r&&r.url)R(r.url);}catch(e){}return r;});};}"
     "if(window.XMLHttpRequest){var X=window.XMLHttpRequest;var o=X.prototype.open;X.prototype.open=function(m,u){try{R(u);}catch(e){}return o.apply(this,arguments);};}"
     "if(window.HTMLMediaElement){var d=Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype,'src');if(d&&d.set){Object.defineProperty(HTMLMediaElement.prototype,'src',{set:function(v){try{R(v);}catch(e){}return d.set.call(this,v);},get:d.get});}}"
     "}catch(e){}})();";

    WKUserScript *sc = [[WKUserScript alloc] initWithSource:js
                                              injectionTime:WKUserScriptInjectionTimeAtDocumentStart
                                           forMainFrameOnly:NO];
    @try { [cfg.userContentController addUserScript:sc]; } @catch (...) {}
}

static id (*as_orig_wk_init_frame)(id, SEL, CGRect, WKWebViewConfiguration *);
static id as_swz_wk_init_frame(id self, SEL _cmd, CGRect frame, WKWebViewConfiguration *cfg) {
    if (cfg) as_add_wk_scripts(cfg);
    return as_orig_wk_init_frame(self, _cmd, frame, cfg);
}

static id (*as_orig_wk_init_coder)(id, SEL, NSCoder *);
static id as_swz_wk_init_coder(id self, SEL _cmd, NSCoder *coder) {
    WKWebViewConfiguration *cfg = nil;
    @try { cfg = [coder decodeObjectForKey:@"configuration"]; } @catch (...) {}
    if (cfg) as_add_wk_scripts(cfg);
    return as_orig_wk_init_coder(self, _cmd, coder);
}

__attribute__((constructor))
static void as_install_wk_hooks(void) {
    @try {
        Class c = NSClassFromString(@"WKWebView");
        if (!c) return;
        Method m1 = class_getInstanceMethod(c, @selector(initWithFrame:configuration:));
        if (m1) { as_orig_wk_init_frame = (void *)method_getImplementation(m1);
                  method_setImplementation(m1, (IMP)as_swz_wk_init_frame); }
        Method m2 = class_getInstanceMethod(c, @selector(initWithCoder:));
        if (m2) { as_orig_wk_init_coder = (void *)method_getImplementation(m2);
                  method_setImplementation(m2, (IMP)as_swz_wk_init_coder); }
        NSLog(@"[AS-Min] WK hooks installed.");
    } @catch (...) {
        NSLog(@"[AS-Min] WK hooks failed.");
    }
}
