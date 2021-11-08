#include <cstdint>
#include <cstddef>
#include <cstdio>
#include "ppp.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

constexpr inline char const DEFAULT_KEYLOG_FILENAME[] = "./ssl_keylog.txt";

constexpr inline auto MODULE_WAIT_INTERVAL = 1;

constexpr inline auto MODULE_WAIT_TIME = 30000;

/// Offset of ``keylog_callback`` in ``struct SSL``.
constexpr inline auto find_keylog_callback = &ppp::any<
#if UINTPTR_MAX > 0xFFFFFFFF
    "48 8B 82 ?? ?? ?? ?? 4D 8B F1 4D 8B E0 4C 8B EA 48 8B F9 48 83 B8 u[?? ?? ?? ??] 00 75 11"_pattern,
    "48 8B 82 ?? ?? ?? ?? 4D 8B F1 4D 8B F1 4C 8B EA 48 8B F9 48 83 B8 u[?? ?? ?? ??] 00 75 11"_pattern
#else
    "8B 45 0C 8B 80 ?? ?? ?? ?? 83 B8 u[?? ?? ?? ??] 00 75 09"_pattern,
    "8B 80 ?? ?? ?? ?? 83 B8 u[?? ?? ?? ??] 00 75 09"_pattern
#endif
    >;

/// Offset of ``CRYPTO_get_ex_new_index`` function.
constexpr inline auto find_CRYPTO_get_ex_new_index = &ppp::any<
#if UINTPTR_MAX > 0xFFFFFFFF
    "48 89 5C 24 28 8D 48 D5 45 33 C9 48 89 5C 24 20 33 D2 E8 r[?? ?? ?? ??]"_pattern,
    "48 89 5C 24 28 45 33 C9 33 D2 48 89 5C 24 20 8D 48 D5 E8 r[?? ?? ?? ??]"_pattern
#else
    "6A 00 6A 00 6A 00 68 ?? ?? ?? ?? 6A 00 6A 05 E8 r[?? ?? ?? ??]"_pattern
#endif
    >;

static void ShowError(char const* title, char const* text) {
    title = title ? title : "nullptr";
    text = text ? text : "nullptr";
    MessageBoxA(nullptr, text, title, 0);
}

constexpr inline auto CRYPTO_EX_INDEX_SSL_CTX = 1;

using long_t = long;

using keylog_callback_t = void (*) (char* ssl, char* line);

using CRYPTO_EX_new_t = void (*) (char* parent, void *ptr, void *ad, int idx, long_t argl, void *argp);

using CRYPTO_get_ex_new_index_t = int (*) (int class_index, long_t argl, void* argp,
                                           CRYPTO_EX_new_t new_func, void* dup_func, void* free_func);

static FILE* log_file = nullptr;

static auto log_func (char*, char* line) noexcept -> void {
    auto const length = strlen(line);
    line[length] = '\n';
    fwrite(line, 1, length + 1, log_file);
    fflush(log_file);
    line[length] = '\0';
}

static auto CRYPTO_EX_new (char* parent, void*, void*, int, long_t argl, void*) noexcept -> void {
    *reinterpret_cast<keylog_callback_t*>(parent + argl) = log_func;
}

struct Offsets {
    std::uint32_t keylog_callback = 0;
    std::uint32_t get_ex_new_index = 0;

    Offsets(std::uintptr_t base) noexcept {
        auto const dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
        auto const nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
        auto const size = nt->OptionalHeader.BaseOfCode + nt->OptionalHeader.SizeOfCode;
        auto offset = size;
        auto last_page_size = std::uint32_t{0};
        while (offset && !(keylog_callback && get_ex_new_index)) {
            auto const page_size = offset % 0x1000 ? offset % 0x1000 : 0x1000;
            offset -= page_size;
            auto const address = reinterpret_cast<char const*>(base + offset);
            if (IsBadReadPtr(address, page_size)) {
                last_page_size = 0;
                continue;
            }
            auto const view = std::span<char const> { address, page_size + last_page_size };
            if (keylog_callback == 0) {
                if (auto const found = find_keylog_callback(view, offset)) {
                    keylog_callback = std::get<1>(*found);
                }
            }
            if (get_ex_new_index == 0) {
                if (auto const found = find_CRYPTO_get_ex_new_index(view, offset)) {
                    get_ex_new_index = static_cast<std::uint32_t>(std::get<1>(*found));
                }
            }
            last_page_size = page_size;
        }
    }
};

static auto WINAPI HookModuleThread(LPVOID) noexcept -> DWORD {
    auto const moduleName = (char const*)arg;
    auto elapsed = MODULE_WAIT_TIME;
    while (elapsed > 0) {
        auto const module = GetModuleHandleA(moduleName);
        if (!module) {
            Sleep(MODULE_WAIT_INTERVAL);
            elapsed -= MODULE_WAIT_INTERVAL;
            continue;
        }
        auto const base = reinterpret_cast<std::uintptr_t>(module);
        auto const off = Offsets(base);
        if (!off.keylog_callback) {
            ShowError("!off.keylog_callback", moduleName);
            break;
        }
        if (!off.get_ex_new_index) {
            ShowError("!off.get_ex_new_index", moduleName);
            break;
        }
        auto const get_ex_new_index = reinterpret_cast<CRYPTO_get_ex_new_index_t>(base + off.get_ex_new_index);
        get_ex_new_index(CRYPTO_EX_INDEX_SSL_CTX, off.keylog_callback, nullptr, CRYPTO_EX_new, nullptr, nullptr);
        break;
    }
    return 0;
}

static void HookModule(char const* moduleName) noexcept {
    CreateThread(nullptr, 0, HookModuleThread, (LPVOID)moduleName, 0, nullptr);
}

auto WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) noexcept -> BOOL {
    if (reason == DLL_PROCESS_ATTACH) {
        auto const keylog_filename = getenv("SSLKEYLOGFILE") ? getenv("SSLKEYLOGFILE") : DEFAULT_KEYLOG_FILENAME;
        log_file = fopen(keylog_filename, "ab");
        if (!log_file) {
            ShowError("!log_file", keylog_filename);
            return TRUE;
        }
        HookModule(nullptr);
    }
    return TRUE;
}
