//
//  utilities.m
//  LockSmith
//
//  Created by Cody Thomas on 9/19/22.
//

#import <Foundation/Foundation.h>
#import "utilities.h"

NSString* getCurrentProcessName(){
    return [[NSProcessInfo alloc] arguments][0];
}

void printCurrentProcess(){
    NSString* processName = getCurrentProcessName();
    printf("Current Process: %s\n", [processName UTF8String]);
    SecRequirementRef secRequirementRef;
    SecTrustedApplicationRef trustedApplicationRef;
    SecTrustedApplicationCreateFromPath([processName UTF8String], &trustedApplicationRef);
    OSStatus stat = SecTrustedApplicationCopyRequirement(trustedApplicationRef, &secRequirementRef);
    if(stat == ERR_SUCCESS){
        // now get the security requirement
        if(secRequirementRef != nil){
            CFStringRef requirementString;
            stat = SecRequirementCopyString(secRequirementRef, kSecCSDefaultFlags, &requirementString);
            if(stat == ERR_SUCCESS){
                printf("\tRequirement String: %s\n", [(__bridge NSString*)requirementString UTF8String]);
            }
        } else {
            printf("\tNo Code Requirement\n");
        }
        
    }
}

typedef void (^describe_t)(void);
static char BUFFER[512000];
static struct csops_struct{
    describe_t    describe; // These are the things that make blocks shine
    unsigned int ops;
    void*     useraddr;
    size_t     usersize;
}CSOPS[] = {
    {
            .ops          = CS_OPS_CDHASH,
            .useraddr      = (void*)BUFFER, // SHA1 of code directory
            .usersize      = CC_SHA1_DIGEST_LENGTH,
            .describe      = ^{
                int i;
                for(i=0;i<CC_SHA1_DIGEST_LENGTH-1; i++){
                    fprintf(stdout, "%02x:",
                            (unsigned char)BUFFER[i]);
                }
                fprintf(stdout, "%02x\n",
                     (unsigned char)BUFFER[CC_SHA1_DIGEST_LENGTH-1]);
            }
        },
};


#define CSOPS_SIZE (sizeof(CSOPS)/sizeof(CSOPS[0]))
char* exec_csops_cdhash(){
    int result;
    unsigned int hash_size = CC_SHA1_DIGEST_LENGTH;
    struct csops_struct* cs;
    char *cdhash = malloc(hash_size);
    cs = &CSOPS[0];
    result = csops([[NSProcessInfo processInfo] processIdentifier], CS_OPS_CDHASH, (void*)cdhash, hash_size);
    if(result < 0){
        printf("Failed to get self CDHash\n");
        free(cdhash);
        return nil;
    }
    NSMutableString *string = [NSMutableString string];
    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i ++) {
        [string appendFormat:@"%02x", (unsigned char)cdhash[i]];
    }
    return [string UTF8String];
}

void printCDHash(){
    char* cdhash = exec_csops_cdhash();
    if(cdhash != nil){
        printf("Current CDHash PartitionID: %s\n", cdhash);
    } else {
        printf("Current CDHash PartitionID: (null)\n");
    }
}

void printPlistHex(NSString* plistHex){
    if (([plistHex length] % 2) == 0){
        
        NSPropertyListFormat format = NSPropertyListXMLFormat_v1_0;
        NSMutableString *string = [NSMutableString string];
        //https://stackoverflow.com/questions/6421282/how-to-convert-hex-to-nsstring-in-objective-c
        for (NSInteger i = 0; i < [plistHex length]; i += 2) {
            NSString *hex = [plistHex substringWithRange:NSMakeRange(i, 2)];
            unsigned int decimalValue = 0;
            sscanf([hex UTF8String], "%x", &decimalValue);
            [string appendFormat:@"%c", decimalValue];
        }
        NSDictionary *plist = [NSPropertyListSerialization propertyListWithData:[string dataUsingEncoding:NSUTF8StringEncoding] options:NSPropertyListImmutable format:&format error:nil];
        if( [plist objectForKey:@"Partitions"] ){
            printf("PLIST PartitionIDs:\n");
            NSArray *partitions = [plist objectForKey:@"Partitions"];
            for(NSInteger i = 0; i < [partitions count]; i++){
                printf("\t%s\n", [partitions[i] UTF8String]);
            }
        } else {
            NSLog(@"PLIST:\n%@\n", plist);
        }
    } else {
        printf("Supplied PLIST description not in hex encoded format\n");
    }
}
void printCurrentPid(){
    printf("Current PID: %d\n", [[NSProcessInfo processInfo] processIdentifier]);
}

void printRequirementForAppPath(NSString* path){
    printf("Processing requirements for path: %s\n", [path UTF8String]);
    SecTrustedApplicationRef osascriptTrustedApp;
    SecTrustedApplicationCreateFromPath([path UTF8String], &osascriptTrustedApp);
    SecRequirementRef secRequirementRef;
    OSStatus stat = SecTrustedApplicationCopyRequirement(osascriptTrustedApp, &secRequirementRef);
    if(stat == ERR_SUCCESS){
        // now get the security requirement
        if(secRequirementRef != nil){
            CFStringRef requirementString;
            stat = SecRequirementCopyString(secRequirementRef, kSecCSDefaultFlags, &requirementString);
            if(stat == ERR_SUCCESS){
                printf("Requirement String: %s\n", [(__bridge NSString*)requirementString UTF8String]);
            }
        } else {
            printf("No Code Requirement for Trusted Application\n");
        }
        stat = SecTrustedApplicationValidateWithPath(osascriptTrustedApp, (const char*)[path UTF8String]);
        if(stat == ERR_SUCCESS){
            printf("\t\t\tApplication is valid\n");
        }else if(stat == -67068){
            printf("\t\t\tFailed to find application on disk\n");
        }else if(stat == -2147415734){
            printf("\t\t\tVerification Failed\n");
        }else{
            printf("\t\t\tApplication has an error with validation: %d\n", stat);
        }
    }else{
        printf("Failed to get requirement for path: %d\n", stat);
    }
}
void PrintAllCSSMTypes(){
    printf("CSSM_ACL_SUBJECT_TYPE_COMMENT: %d\n", CSSM_ACL_SUBJECT_TYPE_COMMENT);
    printf("CSSM_ACL_SUBJECT_TYPE_ANY: %d\n", CSSM_ACL_SUBJECT_TYPE_ANY);
    printf("CSSM_ACL_SUBJECT_TYPE_PREAUTH: %d\n", CSSM_ACL_SUBJECT_TYPE_PREAUTH);
    printf("CSSM_ACL_SUBJECT_TYPE_PROCESS: %d\n", CSSM_ACL_SUBJECT_TYPE_PROCESS);
    printf("CSSM_ACL_SUBJECT_TYPE_PASSWORD: %d\n", CSSM_ACL_SUBJECT_TYPE_PASSWORD);
    printf("CSSM_ACL_SUBJECT_TYPE_BIOMETRIC: %d\n", CSSM_ACL_SUBJECT_TYPE_BIOMETRIC);
    printf("CSSM_ACL_SUBJECT_TYPE_PARTITION: %d\n", CSSM_ACL_SUBJECT_TYPE_PARTITION);
    printf("CSSM_ACL_SUBJECT_TYPE_THRESHOLD: %d\n", CSSM_ACL_SUBJECT_TYPE_THRESHOLD);
    printf("CSSM_ACL_SUBJECT_TYPE_LOGIN_NAME: %d\n", CSSM_ACL_SUBJECT_TYPE_LOGIN_NAME);
    printf("CSSM_ACL_SUBJECT_TYPE_PUBLIC_KEY: %d\n", CSSM_ACL_SUBJECT_TYPE_PUBLIC_KEY);
    printf("CSSM_ACL_SUBJECT_TYPE_SYMMETRIC_KEY: %d\n", CSSM_ACL_SUBJECT_TYPE_SYMMETRIC_KEY);
    printf("CSSM_ACL_SUBJECT_TYPE_EXT_PAM_NAME: %d\n", CSSM_ACL_SUBJECT_TYPE_EXT_PAM_NAME);
    printf("CSSM_ACL_SUBJECT_TYPE_ASYMMETRIC_KEY: %d\n", CSSM_ACL_SUBJECT_TYPE_ASYMMETRIC_KEY);
    printf("CSSM_ACL_SUBJECT_TYPE_CODE_SIGNATURE: %d\n", CSSM_ACL_SUBJECT_TYPE_CODE_SIGNATURE);
    printf("CSSM_ACL_SUBJECT_TYPE_HASHED_SUBJECT: %d\n", CSSM_ACL_SUBJECT_TYPE_HASHED_SUBJECT);
    printf("CSSM_ACL_SUBJECT_TYPE_KEYCHAIN_PROMPT: %d\n", CSSM_ACL_SUBJECT_TYPE_KEYCHAIN_PROMPT);
    printf("CSSM_ACL_SUBJECT_TYPE_PREAUTH_SOURCE: %d\n", CSSM_ACL_SUBJECT_TYPE_PREAUTH_SOURCE);
    printf("CSSM_ACL_SUBJECT_TYPE_PROMPTED_PASSWORD: %d\n", CSSM_ACL_SUBJECT_TYPE_PROMPTED_PASSWORD);
    printf("CSSM_ACL_SUBJECT_TYPE_PROTECTED_PASSWORD: %d\n", CSSM_ACL_SUBJECT_TYPE_PROTECTED_PASSWORD);
    printf("CSSM_ACL_SUBJECT_TYPE_PROMPTED_BIOMETRIC: %d\n", CSSM_ACL_SUBJECT_TYPE_PROMPTED_BIOMETRIC);
    printf("CSSM_ACL_SUBJECT_TYPE_PROTECTED_BIOMETRIC: %d\n", CSSM_ACL_SUBJECT_TYPE_PROTECTED_BIOMETRIC);
}

bool canDecryptEntry(NSString* authorization){
    NSMutableArray *validExports = [[NSMutableArray alloc] initWithCapacity:0];
    [validExports addObject:@"ACLAuthorizationExportClear"];
    [validExports addObject:@"ACLAuthorizationAny"];
    [validExports addObject:@"ACLAuthorizationExportWrapped"];
    return [validExports containsObject:authorization];
}
