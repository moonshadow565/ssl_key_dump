#include <chrono>
#include <cstring>
#include <fstream>
#include <mutex>
#include <regex>
#include <thread>
#include <vector>
#include "MinHook.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#ifdef assert
#undef assert
#endif
#define assert(what) do { if (!(what)) { MessageBoxA(nullptr, #what, __func__, MB_ICONERROR); exit(1); } } while(false)

/// Config

static std::regex patterns[] = {
    #if UINTPTR_MAX > 0xFFFFFFFFF
    std::regex { R"(\x40\x57)"
                 R"(\x41\x55)"
                 R"(\x41\x56)"
                 R"(\x41\x57)"
                 R"(.{4,20})"
                 R"(\x48\x8B\x82(....))"
                 R"(\x4D\x8B\xF1)"
                 R"(\x4D\x8B\xF8)"
                 R"(\x4C\x8B\xEA)"
                 R"(\x48\x8B\xF9)"
                 R"(\x48\x83\xB8(....)\x00)"
                 R"(\x75\x11)"
    },
    #else
    std::regex { R"(\x55)"
                 R"(\x8B\xEC)"
                 R"(.{3,21})"
                 R"(\x8B\x45\x0C)"
                 R"(\x8B\x80(....))"
                 R"(\x83\xB8(....))"
                 R"(\x00\x75\x09)"
    },
    #endif
};

static char const* modules[] = {
    nullptr,
    "RiotGamesApi.dll",
    "RiotClientFoundation.dll",
};

constexpr inline auto modules_wait_interval = 50;

constexpr inline auto modules_wait_time = 30000;

constexpr inline auto log_file_name = "C:/Riot Games/ssl_keylog.txt";

/// Hooking

static void log_func(char*, char const* line) {
    static auto mutex = std::mutex{};
    auto lock = std::lock_guard<std::mutex>{ mutex };
    static auto file = std::ofstream{ log_file_name, std::ios::binary | std::ios::app };
    file.write(line, strlen(line));
    file.put('\n');
    file.flush();
};

static auto dump_data(std::uintptr_t base) {
    auto const handle = GetCurrentProcess();
    char raw[1024] = {};
    assert(ReadProcessMemory(handle, (void const*)base, raw, sizeof(raw), nullptr));
    auto const dos = (PIMAGE_DOS_HEADER)(raw);
    assert(dos->e_magic == IMAGE_DOS_SIGNATURE);
    auto const nt = (PIMAGE_NT_HEADERS32)(raw + dos->e_lfanew);
    assert(nt->Signature == IMAGE_NT_SIGNATURE);
    auto const size = (std::size_t)(nt->OptionalHeader.SizeOfImage);
    auto data = std::vector<char>();
    data.resize(size);
    for (std::size_t i = 0; i < size; i += 0x1000) {
        ReadProcessMemory(handle, (void const*)(base + i), data.data() + i, 0x1000, nullptr);
    }
    return data;
}

static auto find_offsets(std::uintptr_t base) {
    struct Offsets {
        std::ptrdiff_t nss_keylog_int = {};
        std::ptrdiff_t ssl_ctx = {};
        std::ptrdiff_t keylog_callback = {};
    };
    auto const data = dump_data(base);
    for (auto const& p: patterns) {
        std::cmatch result;
        if (std::regex_search(data.data(), data.data() + data.size(), result, p)) {
            std::int32_t ssl_ctx;
            std::memcpy(&ssl_ctx, result[1].first, sizeof(ssl_ctx));
            std::int32_t keylog_callback;
            std::memcpy(&keylog_callback, result[2].first, sizeof(keylog_callback));
            return Offsets { result.position(), ssl_ctx, keylog_callback };
        }
    }
    return Offsets {};
}

template<std::size_t I>
static bool hook_module(char const* name) noexcept {
    static std::uintptr_t base = 0;
    if (base) {
        return true;
    }
    base = (std::uintptr_t)GetModuleHandleA(name);
    if (!base) {
        return false;
    }
    using nss_keylog_int_t = int(*)(const char *prefix,
                                    char *ssl,
                                    const uint8_t *parameter_1,
                                    size_t parameter_1_len,
                                    const uint8_t *parameter_2,
                                    size_t parameter_2_len);
    using keylog_callback_t = void(*)(char* ssl, char const* line);
    static auto const off = find_offsets(base);
    assert(off.nss_keylog_int != 0);
    assert(off.ssl_ctx != 0);
    assert(off.keylog_callback != 0);
    auto const target = (nss_keylog_int_t)(base + off.nss_keylog_int);
    static nss_keylog_int_t org = nullptr;
    static nss_keylog_int_t hook = [](const char *prefix,
                                      char *ssl,
                                      const uint8_t *parameter_1,
                                      size_t parameter_1_len,
                                      const uint8_t *parameter_2,
                                      size_t parameter_2_len) -> int {
        assert(ssl);
        auto ctx = *(char**)(ssl + off.ssl_ctx);
        assert(ctx);
        *(keylog_callback_t*)(ctx + off.keylog_callback) = log_func;
        return org(prefix, ssl, parameter_1, parameter_1_len, parameter_2, parameter_2_len);
    };
    assert(MH_CreateHook((void*)target, (void*)hook, (void**)&org) == MH_OK);
    assert(MH_EnableHook((void*)target) == MH_OK);
    return true;
}

template<std::size_t I = 0>
static bool hook_all_modules_impl() {
    if constexpr(I != sizeof(modules) / sizeof(modules[0])) {
        return hook_module<I>(modules[I]) && hook_all_modules_impl<I + 1>();
    } else {
        return true;
    }
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        assert(MH_Initialize() == MH_OK);
        auto thread = std::thread([=]{
            std::uint32_t elapsed = 0;
            while (!hook_all_modules_impl()) {
                elapsed += modules_wait_interval;
                if (modules_wait_time && elapsed >= modules_wait_time) {
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(modules_wait_interval));
            }
        });
        thread.detach();
    }
    return TRUE;
}
