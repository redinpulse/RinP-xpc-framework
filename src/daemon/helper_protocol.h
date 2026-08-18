#ifndef HELPER_PROTOCOL_H
#define HELPER_PROTOCOL_H
#import <Foundation/Foundation.h>

extern NSString *g_serviceName;

@protocol QP <NSObject>
- (void)q0:(void (^)(NSDictionary *, NSError *))r;
- (void)q1:(NSString *)a z:(void (^)(NSString *, int, NSError *))r;
- (void)q2:(NSString *)a z:(void (^)(NSData *, NSError *))r;
- (void)q3:(NSData *)a a:(NSString *)b z:(void (^)(BOOL, NSError *))r;
- (void)q4:(NSString *)a z:(void (^)(NSDictionary *, NSError *))r;
- (void)q5:(void (^)(NSDictionary *, NSError *))r;
- (void)q6:(void (^)(NSDictionary *, NSError *))r;
- (void)q7:(void (^)(NSString *, NSError *))r;
- (void)q8:(NSString *)a a:(NSString *)b z:(void (^)(BOOL, NSError *))r;
- (void)q9:(void (^)(NSDictionary *, NSError *))r;
- (void)q10:(NSString *)a a:(NSArray<NSString *> *)b b:(NSDictionary<NSString*,NSString*> *)c z:(void (^)(NSString *, int, NSError *))r;
- (void)q11:(NSString *)a a:(BOOL)b z:(void (^)(BOOL, NSString *, NSError *))r;
- (void)q12:(NSString *)a a:(NSString *)b z:(void (^)(NSString *, int, NSError *))r;
- (void)q13:(void (^)(NSString *, NSError *))r;
- (void)q14:(void (^)(NSString *, NSError *))r;
- (void)q15:(void (^)(NSDictionary *, NSError *))r;
- (void)q16:(void (^)(NSString *, NSError *))r;
- (void)q17:(void (^)(NSData *, NSError *))r;
- (void)q18:(void (^)(NSString *, NSError *))r;
- (void)q19:(void (^)(NSString *, NSError *))r;
- (void)q20:(void (^)(NSString *, NSError *))r;
- (void)q21:(void (^)(NSDictionary *, NSError *))r;
- (void)q22:(int)a a:(NSString *)b z:(void (^)(NSData *, NSError *))r;
- (void)q23:(NSString *)a z:(void (^)(BOOL, NSString *, NSError *))r;
- (void)q24:(NSString *)a a:(NSString *)b z:(void (^)(BOOL, NSError *))r;
- (void)q25:(NSString *)a z:(void (^)(BOOL, NSError *))r;
- (void)q26:(void (^)(BOOL, NSString *, NSError *))r;
- (void)q27:(void (^)(NSDictionary *, NSError *))r;
- (void)q28:(void (^)(NSDictionary *, NSError *))r;
- (void)q29:(void (^)(NSString *, NSError *))r;
- (void)q30:(void (^)(NSDictionary *, NSError *))r;
@end
#endif
