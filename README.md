# LSAdump-BOF
> #### Developed for [@Adaptix-Framework](https://github.com/Adaptix-Framework)

BOF tools for dumping LSA secrets, SAM hashes, and cached domain credentials from Windows systems.

## Commands

### lsadump_secrets
Dump LSA secrets from SECURITY hive (requires SYSTEM privileges).

```
lsadump_secrets
```

Extracts and decrypts LSA secrets including:
- Default password
- DPAPI master keys
- Service account passwords
- Auto-logon credentials

### lsadump_sam
Dump SAM hashes (requires admin privileges).

```
lsadump_sam
```

Extracts NTLM hashes for all local user accounts from the SAM registry hive.

### lsadump_cache
Dump cached domain credentials (DCC2/MSCacheV2, requires SYSTEM privileges).

```
lsadump_cache
```

Extracts cached domain credentials (DCC2/MSCacheV2 hashes) for domain users who have logged on to the system.

## Building

### Using Makefile
```bash
cd LSAdump-BOF
make
```

The compiled BOF files will be in the `_bin` directory:
- `lsadump_secrets.x64.o`
- `lsadump_sam.x64.o`
- `lsadump_cache.x64.o`

## Requirements

- Windows target system
- SYSTEM privileges for `lsadump_secrets` and `lsadump_cache`
- Admin privileges for `lsadump_sam`

## Usage

Load the `lsadump.axs` script in Adaptix to register the commands:

```javascript
ax.script_load("path/to/LSAdump-BOF/lsadump.axs");
```

Then use the commands in your beacon sessions:

```bash
# Dump LSA secrets (requires SYSTEM)
lsadump_secrets

# Dump SAM hashes (requires admin)
lsadump_sam

# Dump cached domain credentials (requires SYSTEM)
lsadump_cache
```

## Files

- `lsadump/secrets.c` - LSA secrets dumping implementation
- `lsadump/sam.c` - SAM hashes dumping implementation
- `lsadump/cache.c` - Cached credentials dumping implementation
- `lsadump/lsadump_helper.c` - Shared helper functions
- `lsadump/include/` - Header files with common definitions
- `_include/` - Base BOF framework files

## License

See LICENSE file for details.
