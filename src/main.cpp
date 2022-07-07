#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <MinHook.h>
#include "ppp.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

constexpr inline char const DEFAULT_KEYLOG_FILENAME[] = "./ssl_keylog.txt";

constexpr inline auto MODULE_WAIT_INTERVAL = 1;

constexpr inline auto MODULE_WAIT_TIME = 30000;

// int nss_keylog_int(const char *prefix, char *ssl, const uint8_t *param1, size_t param1_len, const uint8_t *param2, size_t param2_len);
constexpr inline auto find_nss_keylog_int = &ppp::any<
#if UINTPTR_MAX > 0xFFFFFFFF
#error "TODO: x64 bit support"
#else
    "o[B8] 08 00 00 00 "         // mov eax, 8
    "E8 ?? ?? ?? ?? "            // call __alloc_probe
    "8B 44 24 10 "               // mov eax, [esp+8+ssl]
    "8B 80 u[?? ?? ?? ??] "      // mov eax, [eax+offsetof(SSL, ssl_ctx)]
    "83 B8 u[?? ?? ?? ??] 00"    // cmp dword ptr [eax+offsetof(SSL_CTX, keylog_cb)], 0
    ""_pattern
#endif
    >;

static void ShowError(char const* title, char const* text) {
    title = title ? title : "nullptr";
    text = text ? text : "nullptr";
    MessageBoxA(nullptr, text, title, 0);
}

using keylog_callback_t = void (*) (char* ssl, char* line);

static FILE* log_file = nullptr;

static auto log_func (char*, char* line) noexcept -> void {
    auto const length = strlen(line);
    line[length] = '\n';
    fwrite(line, 1, length + 1, log_file);
    fflush(log_file);
    line[length] = '\0';
}

struct Offsets {
    std::uint32_t nss_keylog_int = 0;
    std::uint32_t ssl_ctx = 0;
    std::uint32_t keylog_cb = 0;
    
    Offsets() noexcept = default;
    
    Offsets(std::uintptr_t base) noexcept {
        auto const dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
        auto const nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
        auto const size = nt->OptionalHeader.BaseOfCode + nt->OptionalHeader.SizeOfCode;
        auto offset = size;
        auto last_page_size = std::uint32_t{0};
        while (offset) {
            auto const page_size = offset % 0x1000 ? offset % 0x1000 : 0x1000;
            offset -= page_size;
            auto const address = reinterpret_cast<char const*>(base + offset);
            if (IsBadReadPtr(address, page_size)) {
                last_page_size = 0;
                continue;
            }
            auto const view = std::span<char const> { address, page_size + last_page_size };
            if (auto const found = find_nss_keylog_int(view, offset)) {
                nss_keylog_int = std::get<1>(*found);
                ssl_ctx = std::get<2>(*found);
                keylog_cb = std::get<3>(*found);
                break;
            }
            last_page_size = page_size;
        }
    }
};

using nss_keylog_init_t = int (*)(const char *prefix, char *ssl, const uint8_t *param1, size_t param1_len, const uint8_t *param2, size_t param2_len);

template <auto get_module_name>
static auto HookModule() noexcept -> void {
    static char const* module_name = (char const*)get_module_name();
    static Offsets offset = {};
    static nss_keylog_init_t original = nullptr;
    static nss_keylog_init_t hook = +[] (const char *prefix, char *ssl, const uint8_t *param1, size_t param1_len, const uint8_t *param2, size_t param2_len) -> int {
        if (ssl) {
            auto ssl_ctx = *(char**)(ssl + offset.ssl_ctx);
            if (ssl_ctx) {
                *(keylog_callback_t*)(ssl_ctx + offset.keylog_cb) = log_func;
            }
        }
        return original(prefix, ssl, param1, param1_len, param2, param2_len);  
    };
    CreateThread(nullptr, 0, [] (LPVOID) -> DWORD {
        auto elapsed = MODULE_WAIT_TIME;
        while (elapsed > 0) {
            auto const module = GetModuleHandleA(module_name);
            if (!module) {
                Sleep(MODULE_WAIT_INTERVAL);
                elapsed -= MODULE_WAIT_INTERVAL;
                continue;
            }
            auto const base = reinterpret_cast<std::uintptr_t>(module);
            offset = Offsets(base);
            if (!offset.nss_keylog_int) {
                ShowError("!off.nss_keylog_int", module_name);
                break;
            }
            if (!offset.ssl_ctx) {
                ShowError("!off.ssl_ctx", module_name);
                break;
            }
            if (!offset.keylog_cb) {
                ShowError("!off.keylog_cb", module_name);
                break;
            }
            if (auto err = MH_CreateHook((LPVOID)(base + offset.nss_keylog_int), (LPVOID)hook, (LPVOID*)&original)) {
                ShowError(MH_StatusToString(err), "MH_CreateHook");
                break;
            }
            if (auto err = MH_EnableHook((LPVOID)(base + offset.nss_keylog_int))) {
                ShowError(MH_StatusToString(err), "MH_EnableHook");
                break;
            }
            break;
        }
        return 0;  
    }, nullptr, 0, nullptr);
}

auto WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) noexcept -> BOOL {
    if (reason == DLL_PROCESS_ATTACH) {
        if (auto err = MH_Initialize()) {
            ShowError(MH_StatusToString(err), "MH_Initialize");
        }
        auto const keylog_filename = getenv("SSLKEYLOGFILE") ? getenv("SSLKEYLOGFILE") : DEFAULT_KEYLOG_FILENAME;
        log_file = fopen(keylog_filename, "ab");
        if (!log_file) {
            ShowError("!log_file", keylog_filename);
            return TRUE;
        }
        HookModule<[] { return nullptr; }>();
        // HookModule<[] { return "foo.dll"; }>(nullptr);
    }
    return TRUE;
}
