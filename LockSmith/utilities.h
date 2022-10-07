//
//  utilities.h
//  LockSmith
//
//  Created by Cody Thomas on 9/19/22.
//

#ifndef utilities_h
#define utilities_h
#include <CommonCrypto/CommonDigest.h>    // SHA_HASH_LENGTH. Gratutous? Yes!
#include "codesign.h"
#include <Security/SecTrustedApplication.h>
#include <Security/SecAccess.h>
#include <sys/syslimits.h>    // PATH_MAX
#include <Security/cssmapi.h>
#import <Foundation/Foundation.h>
#include <sys/types.h>
#include <unistd.h>
#include <Security/SecACL.h>
#include <Security/SecKeychainItem.h>

#endif /* utilities_h */

void printCurrentProcess(void);
void printCDHash(void);
NSString* getCurrentProcessName(void);
void printPlistHex(NSString* plistHex);
char* exec_csops_cdhash(void);
void printCurrentPid(void);
void printRequirementForAppPath(NSString* path);
void PrintAllCSSMTypes(void);
bool canDecryptEntry(NSString* authorization);

// https://opensource.apple.com/source/Security/Security-55471/libsecurity_keychain/lib/SecTrustedApplicationPriv.h.auto.html
OSStatus SecTrustedApplicationCopyRequirement(SecTrustedApplicationRef appRef, SecRequirementRef *requirement);
// https://github.com/aosm/Security/blob/master/Security/libsecurity_codesigning/lib/SecRequirement.cpp
OSStatus SecRequirementCopyString(SecRequirementRef requirementRef, SecCSFlags flags, CFStringRef *text);

OSStatus SecTrustedApplicationValidateWithPath(SecTrustedApplicationRef appRef, const char* bytes);
