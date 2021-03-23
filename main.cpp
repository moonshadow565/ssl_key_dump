#include "ppp.hpp"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <thread>
#include <list>
#include <vector>

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
using long_t = long;

constexpr inline auto cache_dir = "C:/Riot Games/ssl_offset_cache";
constexpr inline auto log_file_name = "C:/Riot Games/ssl_keylog.txt";

static char const* modules[] = {
    nullptr,
    "RiotGamesApi.dll",
    "RiotClientFoundation.dll",
};

constexpr inline auto modules_wait_interval = 50;

constexpr inline auto modules_wait_time = 30000;

constexpr auto find_keylog_callback = &ppp::any<
#if UINTPTR_MAX > 0xFFFFFFFF
        "48 8B 82 ?? ?? ?? ?? 4D 8B F1 4D 8B E0 4C 8B EA 48 8B F9 48 83 B8 u[?? ?? ?? ??] 00 75 11"_pattern,
        "48 8B 82 ?? ?? ?? ?? 4D 8B F1 4D 8B F1 4C 8B EA 48 8B F9 48 83 B8 u[?? ?? ?? ??] 00 75 11"_pattern
#else
        "8B 45 0C 8B 80 ?? ?? ?? ?? 83 B8 u[?? ?? ?? ??] 00 75 09"_pattern,
        "8B 80 ?? ?? ?? ?? 83 B8 u[?? ?? ?? ??] 00 75 09"_pattern
#endif
        >;

constexpr auto find_CRYPTO_get_ex_new_index = &ppp::any<
#if UINTPTR_MAX > 0xFFFFFFFF
        "48 89 5C 24 28 8D 48 D5 45 33 C9 48 89 5C 24 20 33 D2 E8 r[?? ?? ?? ??]"_pattern,
        "48 89 5C 24 28 45 33 C9 33 D2 48 89 5C 24 20 8D 48 D5 E8 r[?? ?? ?? ??]"_pattern
#else
        "6A 00 6A 00 6A 00 68 ?? ?? ?? ?? 6A 00 6A 05 E8 r[?? ?? ?? ??]"_pattern
#endif
        >;

/// Typedefs
constexpr inline auto CRYPTO_EX_INDEX_SSL_CTX = 1;

typedef void (* keylog_callback_t) (char* ssl, char const* line);

typedef void (* CRYPTO_EX_new_t) (char* parent, void *ptr, void *ad, int idx, long_t argl, void *argp);

typedef int (* CRYPTO_get_ex_new_index_t) (int class_index, long_t argl, void* argp,
                                           CRYPTO_EX_new_t new_func, void* dup_func, void* free_func);

/// Hooking

static auto log_func(char*, char const* line) noexcept -> void {
    static auto mutex = std::mutex{};
    auto lock = std::lock_guard<std::mutex>{ mutex };
    static auto file = [] {
        auto const output_dir = std::filesystem::path(log_file_name).parent_path();
        if (!std::filesystem::exists(output_dir)) {
            assert(std::filesystem::create_directories(output_dir));
        }
        auto file = std::ofstream{ log_file_name, std::ios::binary | std::ios::app };
        assert(file.good());
        return file;
    }();
    file.write(line, strlen(line));
    file.put('\n');
    file.flush();
};

static auto CRYPTO_EX_new(char* parent, void *, void *, int, long_t argl, void *) noexcept -> void {
    *(keylog_callback_t*)(parent + argl) = &log_func;
}

struct Offsets {
    uint32_t checksum = {};
    uint32_t keylog_callback = {};
    uint32_t get_ex_new_index = {};

    static Offsets scan(HMODULE module) {
        auto result = Offsets{};
        // Scratch buffer
        char buffer[0x1000] = {};

        // Get file name of current module
        GetModuleFileNameA(module, buffer, sizeof(buffer));
        auto const filename =  std::filesystem::path(buffer).filename().replace_extension(".txt");
        auto const cachedir = std::filesystem::path(cache_dir);
        auto const cachepath = (cachedir / filename).generic_string();

        // Load offsets from cache if any
        if (auto file = fopen(cachepath.c_str(), "rb")) {
            fscanf(file, "v1 %08X %08X %08X",
                   &result.checksum, &result.keylog_callback, &result.get_ex_new_index);
            fclose(file);
        }

        // Extract PE header information of module
        auto const handle = GetCurrentProcess();
        auto const base = reinterpret_cast<std::uintptr_t>(module);
        assert(ReadProcessMemory(handle, reinterpret_cast<LPVOID>(base), buffer, 0x400, nullptr));
        auto const dos = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);
        assert(dos->e_magic == IMAGE_DOS_SIGNATURE);
        auto const nt = reinterpret_cast<PIMAGE_NT_HEADERS32>(buffer + dos->e_lfanew);
        assert(nt->Signature == IMAGE_NT_SIGNATURE);
        auto const size = static_cast<std::uint32_t>(nt->OptionalHeader.SizeOfImage);
        auto const newChecksum = static_cast<std::uint32_t>(nt->OptionalHeader.CheckSum);

        // If checksum doesn't match we need to force rescan offsets
        bool changed = false;
        if (result.checksum != newChecksum) {
            changed = true;
            result.checksum = newChecksum;
            result.keylog_callback = 0;
            result.get_ex_new_index = 0;
        }

        std::uint32_t offset = 0;
        std::uint32_t remain = size;
        while (remain > 0 && (result.keylog_callback == 0 || result.get_ex_new_index == 0)) {
            // We scan page by page since patterns are unlikely to cross page boundary
            auto const page_size = std::min(remain, 0x1000u);
            ReadProcessMemory(handle, reinterpret_cast<LPVOID>(base + offset), buffer, page_size, nullptr);

            auto const view = std::span<char const> { buffer, page_size };
            if (result.keylog_callback == 0) {
                if (auto const found = find_keylog_callback(view, offset)) {
                    result.keylog_callback = std::get<1>(*found);
                    changed = true;
                }
            }
            if (result.get_ex_new_index == 0) {
                if (auto const found = find_CRYPTO_get_ex_new_index(view, offset)) {
                    result.get_ex_new_index = static_cast<std::uint32_t>(std::get<1>(*found));
                    changed = true;
                }
            }

            offset += page_size;
            remain -= page_size;
        }

        // If we found any offsets store them in cache
        if (changed) {
            if (!std::filesystem::exists(cachedir)) {
                std::error_code ec = {};
                std::filesystem::create_directories(cachedir, ec);
            }

            if (auto file = fopen(cachepath.c_str(), "wb")) {
                fprintf(file, "v1 %08X %08X %08X",
                        result.checksum, result.keylog_callback, result.get_ex_new_index);
                fclose(file);
            }
        }

        return result;
    }
};

static auto hook_module(char const* name) noexcept -> bool {
    auto const module = GetModuleHandleA(name);
    if (!module) {
        return false;
    }

    auto const off = Offsets::scan(module);
    assert(off.keylog_callback != 0);
    assert(off.get_ex_new_index != 0);

    auto const base = reinterpret_cast<std::uintptr_t>(module);
    auto const get_ex_new_index = reinterpret_cast<CRYPTO_get_ex_new_index_t>(base + off.get_ex_new_index);
    get_ex_new_index(CRYPTO_EX_INDEX_SSL_CTX, off.keylog_callback, nullptr, CRYPTO_EX_new, nullptr, nullptr);

    return true;
}

static auto run() -> void {
    auto thread = std::thread([]{
        std::uint32_t elapsed = 0;
        std::list<char const*> unhooked = { std::begin(modules), std::end(modules) };
        while (!unhooked.empty()) {
            for (auto i = unhooked.begin(); i != unhooked.end(); ) {
                if (hook_module(*i)) {
                    i = unhooked.erase(i);
                } else {
                    ++i;
                }
            }
            elapsed += modules_wait_interval;
            if (modules_wait_time && elapsed >= modules_wait_time) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(modules_wait_interval));
        }
    });
    thread.detach();
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        run();
    }
    return TRUE;
}
