//
// AliSniffer.m  (focus live; wide hooks: Session/AV/AVURLAsset/AVPlayer/WK + generic URL setters)
// iOS 11+ / arm64 / -fobjc-arc
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <WebKit/WebKit.h>
#import <AVFoundation/AVFoundation.h>

#pragma mark - UI helpers

static UIViewController *AS_TopVC(void) {
    __block UIViewController *top = nil;
    dispatch_block_t finder = ^{
        @try {
            if (@available(iOS 13.0, *)) {
                for (UIScene *sc in UIApplication.sharedApplication.connectedScenes) {
                    if (sc.activationState != UISceneActivationStateForegroundActive) continue;
                    if (![sc isKindOfClass:UIWindowScene.class]) continue;
                    for (UIWindow *w in ((UIWindowScene *)sc).windows) {
                        if (w.hidden) continue;
                        UIViewController *vc = w.rootViewController;
                        while (vc.presentedViewController) vc = vc.presentedViewController;
                        if (vc) { top = vc; return; }
                    }
                }
            }
            UIWindow *win = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.delegate.window;
            UIViewController *vc = win.rootViewController;
            while (vc.presentedViewController) vc = vc.presentedViewController;
            top = vc;
        } @catch (...) {}
    };
    if (NSThread.isMainThread) finder(); else dispatch_sync(dispatch_get_main_queue(), finder);
    return top;
}

static void AS_AlertOK(NSString *title, NSString *msg) {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            UIAlertController *ac = [UIAlertController alertControllerWithTitle:title message:msg preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
            UIViewController *vc = AS_TopVC();
            if (!vc) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    UIViewController *v2 = AS_TopVC();
                    if (v2) [v2 presentViewController:ac animated:YES completion:nil];
                });
            } else {
                [vc presentViewController:ac animated:YES completion:nil];
            }
        } @catch (...) {}
    });
}

static void AS_AlertCopy(NSString *url) {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"抓到完整请求"
                                                                        message:[@"\n" stringByAppendingString:url]
                                                                 preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *a){
                UIPasteboard.generalPasteboard.string = url;
            }]];
            [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
            UIViewController *vc = AS_TopVC();
            if (vc) [vc presentViewController:ac animated:YES completion:nil];
        } @catch (...) {}
    });
}

#pragma mark - Matchers

static BOOL AS_isKuniNet(NSString *s) {
    if (s.length==0) return NO;
    NSString *h = [NSURL URLWithString:s].host.lowercaseString ?: @"";
    return [h hasSuffix:@"kuniunet.com"];
}

static BOOL AS_isBlack(NSString *s) {
    if (s.length==0) return NO;
    NSString *lower = s.lowercaseString;
    NSURL *u = [NSURL URLWithString:s];
    NSString *host = u.host.lowercaseString ?: @"";
    NSString *path = u.path.lowercaseString ?: @"";

    // 1) 阿里日志上报
    if ([host hasSuffix:@"log.aliyuncs.com"]) return YES;
    if ([lower containsString:@"/logstores/"]) return YES;

    // 2) kuniunet 的非流业务接口
    // liveContentList / playNumCount
    if ([host containsString:@"app.kuniunet.com"] &&
        [path containsString:@"/mag/"] &&
        ([lower containsString:@"livecontentlist"] || [lower containsString:@"playnumcount"])) {
        return YES;
    }
    // lychat 全部静音
    if ([host containsString:@"app.kuniunet.com"] &&
        [path containsString:@"/lychat/"]) {
        return YES;
    }
    return NO;
}

static BOOL AS_hasAuthKey(NSString *s) {
    if (!s) return NO;
    NSString *l = s.lowercaseString;
    return [l containsString:@"auth_key="] || [l containsString:@"auth_key%3d"] || [l containsString:@"auth_key%3D"]
        || [l containsString:@"authkey="] || [l containsString:@"token="];
}

static BOOL AS_likeStream(NSString *s) {
    if (!s) return NO;
    NSError *err=nil;
    NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:
        @"(m3u8(\\?|$)|\\.mpd(\\?|$)|\\.m4s(\\?|$)|\\.ts(\\?|$)|\\.mp4(\\?|$)|\\.flv(\\?|$)|^rtmps?:\\/\\/|^wss?:\\/\\/.*\\.flv)"
        options:NSRegularExpressionCaseInsensitive error:&err];
    if (!re) return NO;
    return [re firstMatchInString:s options:0 range:NSMakeRange(0, s.length)] != nil;
}

#pragma mark - Report

static void AS_Report(NSString *url) {
    if (url.length==0) return;
    if (AS_isBlack(url)) return;
    // 白名单域名优先；否则需命中 auth_key 或流特征
    if (!(AS_isKuniNet(url) || AS_hasAuthKey(url) || AS_likeStream(url))) return;

    NSLog(@"[AS] stream candidate: %@", url);
    @try {
        [[NSNotificationCenter defaultCenter] postNotificationName:@"AliSnifferFoundURL"
                                                            object:nil
                                                          userInfo:@{@"url":url}];
    } @catch (...) {}
    AS_AlertCopy(url);
}

#pragma mark - NSURLSession

static id (*o_NSURLSession_dataTaskWithRequest)(id,SEL,NSURLRequest*);
static id sw_NSURLSession_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *req) {
    id task = o_NSURLSession_dataTaskWithRequest? o_NSURLSession_dataTaskWithRequest(self,_cmd,req):nil;
    if (task && req) {
        @try {
            NSString *u = req.URL.absoluteString ?: @"";
            if (!AS_isBlack(u) && (AS_isKuniNet(u) || AS_hasAuthKey(u))) {
                AS_Report(u);
            }
            objc_setAssociatedObject(task, "as_req", req, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        } @catch (...) {}
    }
    return task;
}

static id (*o_NSURLSession_dataTaskWithURL)(id,SEL,NSURL*);
static id sw_NSURLSession_dataTaskWithURL(id self, SEL _cmd, NSURL *url) {
    id task = o_NSURLSession_dataTaskWithURL? o_NSURLSession_dataTaskWithURL(self,_cmd,url):nil;
    if (task && url) {
        @try {
            NSString *u = url.absoluteString ?: @"";
            if (!AS_isBlack(u) && (AS_isKuniNet(u) || AS_hasAuthKey(u))) {
                AS_Report(u);
            }
            objc_setAssociatedObject(task, "as_req", [NSURLRequest requestWithURL:url], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        } @catch (...) {}
    }
    return task;
}

static void (*o_NSURLSessionTask_resume)(id,SEL);
static void sw_NSURLSessionTask_resume(id self, SEL _cmd) {
    @try {
        NSURLRequest *r = objc_getAssociatedObject(self, "as_req");
        if (!r && [self respondsToSelector:@selector(currentRequest)]) {
            @try { r = [self performSelector:@selector(currentRequest)]; } @catch(...) {}
        }
        NSString *u = r.URL.absoluteString ?: @"";
        if (u.length && !AS_isBlack(u)) {
            if (AS_isKuniNet(u) || AS_hasAuthKey(u) || AS_likeStream(u)) {
                AS_Report(u);
            }
        }
    } @catch (...) {}
    if (o_NSURLSessionTask_resume) o_NSURLSessionTask_resume(self,_cmd);
}

static void swizzle(Class c, SEL sel, IMP newImp, IMP *outOrig) {
    if (!c) return;
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    if (outOrig) *outOrig = (IMP)method_getImplementation(m);
    method_setImplementation(m, newImp);
}

static void Install_Session(void) {
    @try {
        Class S = NSClassFromString(@"NSURLSession");
        if (S) {
            swizzle(S, @selector(dataTaskWithRequest:), (IMP)sw_NSURLSession_dataTaskWithRequest, (IMP*)&o_NSURLSession_dataTaskWithRequest);
            swizzle(S, @selector(dataTaskWithURL:), (IMP)sw_NSURLSession_dataTaskWithURL, (IMP*)&o_NSURLSession_dataTaskWithURL);
        }
        Class T = NSClassFromString(@"NSURLSessionTask");
        if (T) swizzle(T, @selector(resume), (IMP)sw_NSURLSessionTask_resume, (IMP*)&o_NSURLSessionTask_resume);
        NSLog(@"[AS] NSURLSession hooks ready.");
    } @catch(...) { NSLog(@"[AS] NSURLSession hooks failed."); }
}

#pragma mark - AV path (AVPlayerItem/AVURLAsset/AVPlayer)

static void ObserveItem(AVPlayerItem *item) {
    if (!item) return;
    @try {
        [[NSNotificationCenter defaultCenter] addObserverForName:AVPlayerItemNewAccessLogEntryNotification
                                                          object:item
                                                           queue:NSOperationQueue.mainQueue
                                                      usingBlock:^(__unused NSNotification *n){
            @try {
                AVPlayerItemAccessLog *log = item.accessLog;
                NSArray *evs = log.events;
                if (evs.count == 0) return;
                id ev = evs.lastObject;
                NSString *uri = nil;
                if ([ev respondsToSelector:NSSelectorFromString(@"URI")]) uri = [ev valueForKey:@"URI"];
                if (uri.length) AS_Report(uri);
            } @catch (...) {}
        }];
    } @catch (...) {}
}

static id (*o_Item_initWithURL)(id,SEL,NSURL*);
static id sw_Item_initWithURL(id self, SEL _cmd, NSURL *URL) {
    id item = o_Item_initWithURL? o_Item_initWithURL(self,_cmd,URL):nil;
    if (item && URL) {
        AS_Report(URL.absoluteString);
        ObserveItem(item);
    }
    return item;
}

static id (*o_Asset_initWithURL)(id,SEL,NSURL*);
static id sw_Asset_initWithURL(id self, SEL _cmd, NSURL *url) {
    id asset = o_Asset_initWithURL? o_Asset_initWithURL(self,_cmd,url):nil;
    if (asset && url) AS_Report(url.absoluteString);
    return asset;
}

static id (*o_Asset_initWithURL_opts)(id,SEL,NSURL*,NSDictionary*);
static id sw_Asset_initWithURL_opts(id self, SEL _cmd, NSURL *url, NSDictionary *opts) {
    id asset = o_Asset_initWithURL_opts? o_Asset_initWithURL_opts(self,_cmd,url,opts):nil;
    if (asset && url) AS_Report(url.absoluteString);
    return asset;
}

static void (*o_Player_replace)(id,SEL,AVPlayerItem*);
static void sw_Player_replace(id self, SEL _cmd, AVPlayerItem *item) {
    if (item) {
        @try {
            if ([item.asset isKindOfClass:AVURLAsset.class]) {
                NSURL *u = ((AVURLAsset *)item.asset).URL;
                if (u) AS_Report(u.absoluteString);
            }
        } @catch (...) {}
        ObserveItem(item);
    }
    if (o_Player_replace) o_Player_replace(self,_cmd,item);
}

static void Install_AV(void) {
    @try {
        Class C1 = NSClassFromString(@"AVPlayerItem");
        if (C1) {
            Method m = class_getInstanceMethod(C1, @selector(initWithURL:));
            if (m) { o_Item_initWithURL = (void*)method_getImplementation(m);
                     method_setImplementation(m, (IMP)sw_Item_initWithURL); }
        }
        Class C2 = NSClassFromString(@"AVURLAsset");
        if (C2) {
            Method m1 = class_getInstanceMethod(C2, @selector(initWithURL:));
            if (m1) { o_Asset_initWithURL = (void*)method_getImplementation(m1);
                      method_setImplementation(m1, (IMP)sw_Asset_initWithURL); }
            SEL sel2 = NSSelectorFromString(@"initWithURL:options:");
            Method m2 = class_getInstanceMethod(C2, sel2);
            if (m2) { o_Asset_initWithURL_opts = (void*)method_getImplementation(m2);
                      method_setImplementation(m2, (IMP)sw_Asset_initWithURL_opts); }
        }
        Class C3 = NSClassFromString(@"AVPlayer");
        if (C3) {
            Method m = class_getInstanceMethod(C3, @selector(replaceCurrentItemWithPlayerItem:));
            if (m) { o_Player_replace = (void*)method_getImplementation(m);
                     method_setImplementation(m, (IMP)sw_Player_replace); }
        }
        NSLog(@"[AS] AV hooks ready.");
    } @catch(...) { NSLog(@"[AS] AV hooks failed."); }
}

#pragma mark - WKWebView (light js)

@interface _AS_WKHandler : NSObject <WKScriptMessageHandler>
@end
@implementation _AS_WKHandler
- (void)userContentController:(WKUserContentController *)uc didReceiveScriptMessage:(WKScriptMessage *)m {
    if (![m.name isEqualToString:@"_S"]) return;
    NSString *s = nil;
    if ([m.body isKindOfClass:NSString.class]) s = m.body;
    else if ([m.body isKindOfClass:NSURL.class]) s = [(NSURL*)m.body absoluteString];
    if (s.length) AS_Report(s);
}
@end

static void AddWKScripts(WKWebViewConfiguration *cfg) {
    if (!cfg) return;
    static void *kTag = &kTag;
    if (objc_getAssociatedObject(cfg, kTag)) return;
    objc_setAssociatedObject(cfg, kTag, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    _AS_WKHandler *h = [_AS_WKHandler new];
    @try { [cfg.userContentController addScriptMessageHandler:h name:@"_S"]; } @catch (...) {}

    NSString *js =
    @"(function(){try{"
      "function R(u){try{if(u&&/(kuniunet\\.com|auth_key=|m3u8(\\?|$)|\\.mpd(\\?|$)|\\.m4s(\\?|$)|\\.ts(\\?|$)|\\.mp4(\\?|$)|\\.flv(\\?|$)|^rtmps?:\\/\\/|^wss?:\\/\\/.*\\.flv)/i.test(u))window.webkit.messageHandlers._S.postMessage(u);}catch(e){}}"
      "if(window.fetch){var _f=window.fetch;window.fetch=function(){var u=arguments[0];try{if(typeof u==='string')R(u);}catch(e){}return _f.apply(this,arguments).then(function(r){try{if(r&&r.url)R(r.url);}catch(e){}return r;});};}"
      "if(window.XMLHttpRequest){var X=window.XMLHttpRequest;var o=X.prototype.open;X.prototype.open=function(m,u){try{R(u);}catch(e){}return o.apply(this,arguments);};}"
      "if(window.HTMLMediaElement){var d=Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype,'src');if(d&&d.set){Object.defineProperty(HTMLMediaElement.prototype,'src',{set:function(v){try{R(v);}catch(e){}return d.set.call(this,v);},get:d.get});}}"
    "}catch(e){}})();";

    WKUserScript *sc = [[WKUserScript alloc] initWithSource:js
                                              injectionTime:WKUserScriptInjectionTimeAtDocumentStart
                                           forMainFrameOnly:NO];
    @try { [cfg.userContentController addUserScript:sc]; } @catch (...) {}
}

static id (*o_wk_init_frame)(id,SEL,CGRect,WKWebViewConfiguration*);
static id sw_wk_init_frame(id self, SEL _cmd, CGRect f, WKWebViewConfiguration *cfg) {
    if (cfg) AddWKScripts(cfg);
    return o_wk_init_frame(self,_cmd,f,cfg);
}
static id (*o_wk_init_coder)(id,SEL,NSCoder*);
static id sw_wk_init_coder(id self, SEL _cmd, NSCoder *coder) {
    WKWebViewConfiguration *cfg = nil;
    @try { cfg = [coder decodeObjectForKey:@"configuration"]; } @catch (...) {}
    if (cfg) AddWKScripts(cfg);
    return o_wk_init_coder(self,_cmd,coder);
}
static void Install_WK(void) {
    @try {
        Class C = NSClassFromString(@"WKWebView");
        if (!C) return;
        Method m1 = class_getInstanceMethod(C, @selector(initWithFrame:configuration:));
        if (m1) { o_wk_init_frame = (void*)method_getImplementation(m1); method_setImplementation(m1, (IMP)sw_wk_init_frame); }
        Method m2 = class_getInstanceMethod(C, @selector(initWithCoder:));
        if (m2) { o_wk_init_coder = (void*)method_getImplementation(m2); method_setImplementation(m2, (IMP)sw_wk_init_coder); }
        NSLog(@"[AS] WK hooks ready.");
    } @catch(...) { NSLog(@"[AS] WK hooks failed."); }
}

#pragma mark - Generic URL setters / play entries

static SEL AS_URLLikeSelectors[] = {
    @selector(setUrl:), @selector(setURL:),
    @selector(setPlayUrl:), @selector(setPlayURL:),
    @selector(prepareWithURL:), @selector(playWithURL:),
    @selector(replaceCurrentItemWithURL:),
    NSSelectorFromString(@"setSourceUrl:"), NSSelectorFromString(@"setSourceURL:"),
    NSSelectorFromString(@"setPlayerURL:"), NSSelectorFromString(@"startPlay:")
};

typedef void (*msgSend_id_id)(id, SEL, id);

static void AS_tryReportArg(id arg) {
    @try {
        NSString *s = nil;
        if ([arg isKindOfClass:NSString.class]) s = (NSString *)arg;
        else if ([arg isKindOfClass:NSURL.class]) s = [(NSURL *)arg absoluteString];
        if (s.length && !AS_isBlack(s) && (AS_isKuniNet(s) || AS_hasAuthKey(s) || AS_likeStream(s))) {
            AS_Report(s);
        }
    } @catch(...) {}
}

static void AS_sw_generic_setter(id self, SEL _cmd, id arg) {
    AS_tryReportArg(arg);
    // 原 IMP 存在 class 关联上，用 selector 作 key 取回
    IMP orig = (__bridge IMP)objc_getAssociatedObject([self class], _cmd);
    if (orig) ((msgSend_id_id)orig)(self, _cmd, arg);
}

static void AS_trySwizzleSelector(Class cls, SEL sel) {
    if (!cls || !sel) return;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;

    // 保存原实现到 Class 关联，key 用 selector
    IMP orig = method_getImplementation(m);
    objc_setAssociatedObject((id)cls, sel, (__bridge id)orig, OBJC_ASSOCIATION_ASSIGN);

    method_setImplementation(m, (IMP)AS_sw_generic_setter);
    NSLog(@"[AS] generic hook: %@ %@", NSStringFromClass(cls), NSStringFromSelector(sel));
}

static void AS_Install_Generic_URL_Hooks(void) {
    @try {
        NSArray<NSString *> *candidates = @[
            // 阿里/常见播放器类名（尽量覆盖）
            @"AliPlayer", @"AliLivePlayer", @"ApsaraPlayer", @"AVPUrlSource",
            @"AlivcLivePlayer", @"AlivcLongVideo", @"AUIPlayer",
            // 兜底：常见命名
            @"Player", @"LivePlayer", @"URLSource", @"VideoPlayer"
        ];

        for (NSString *name in candidates) {
            Class cls = NSClassFromString(name);
            if (!cls) continue;
            for (NSUInteger i=0; i<sizeof(AS_URLLikeSelectors)/sizeof(SEL); i++) {
                SEL sel = AS_URLLikeSelectors[i];
                if ([cls instancesRespondToSelector:sel]) {
                    AS_trySwizzleSelector(cls, sel);
                }
            }
        }
    } @catch (...) {
        NSLog(@"[AS] generic url hooks failed.");
    }
}

#pragma mark - Banner & bootstrap

static void ShowInjectedOnce(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        dispatch_async(dispatch_get_main_queue(), ^{
            if (UIApplication.sharedApplication.applicationState == UIApplicationStateActive) {
                AS_AlertOK(@"AliSniffer", @"注入成功（主抓直播源，含 AVURLAsset/AVPlayer/通用URL入口）");
            } else {
                [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                                  object:nil
                                                                   queue:NSOperationQueue.mainQueue
                                                              usingBlock:^(__unused NSNotification *n){
                    AS_AlertOK(@"AliSniffer", @"注入成功（主抓直播源，含 AVURLAsset/AVPlayer/通用URL入口）");
                }];
            }
        });
    });
}

__attribute__((constructor))
static void BootAll(void) {
    @try {
        Install_Session();
        Install_AV();
        Install_WK();
        AS_Install_Generic_URL_Hooks(); // 新增：通用 URL/播放入口
        NSLog(@"[AS] bootstrap done.");
        ShowInjectedOnce();
    } @catch(...) {
        NSLog(@"[AS] bootstrap error.");
    }
}
