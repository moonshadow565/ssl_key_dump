#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <regex>
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

constexpr inline auto log_file_name = "C:/Riot Games/ssl_keylog.txt";

static char const* modules[] = {
    nullptr,
    "RiotGamesApi.dll",
    "RiotClientFoundation.dll",
};

constexpr inline auto modules_wait_interval = 50;

constexpr inline auto modules_wait_time = 30000;

static std::vector<std::regex> patterns_keylog_callback  {
#if UINTPTR_MAX > 0xFFFFFFFF
    std::regex {
        R"(\x48\x8B\x82....)"
        R"(\x4D\x8B\xF1)"
        R"(\x4D\x8B\xF8)"
        R"(\x4C\x8B\xEA)"
        R"(\x48\x8B\xF9)"
        R"(\x48\x83\xB8(....)\x00)"
        R"(\x75\x11)"
    },
    std::regex {
        R"(\x48\x8B\x82....)"
        R"(\x4D\x8B\xF1)"
        R"(\x4D\x8B\xE0)"
        R"(\x4C\x8B\xEA)"
        R"(\x48\x8B\xF9)"
        R"(\x48\x83\xB8(....)\x00)"
        R"(\x75\x11)"
    },
#else
    std::regex {
        R"(\x8B\x45\x0C)"
        R"(\x8B\x80....)"
        R"(\x83\xB8(....)\x00)"
        R"(\x75\x09)"
    },
    std::regex {
        R"(\x8B\x80....)"
        R"(\x83\xB8(....)\x00)"
        R"(\x75\x09)"
    },
#endif
};

static std::vector<std::regex> patterns_CRYPTO_get_ex_new_index = {
#if UINTPTR_MAX > 0xFFFFFFFF
    std::regex {
        R"(\x48\x89\x5C\x24\x28)"
        R"(\x8D\x48\xD5)"
        R"(\x45\x33\xC9)"
        R"(\x48\x89\x5C\x24\x20)"
        R"(\x33\xD2)"
        R"(\xE8(....))"
    },
    std::regex {
        R"(\x48\x89\x5C\x24\x28)"
        R"(\x45\x33\xC9)"
        R"(\x33\xD2)"
        R"(\x48\x89\x5C\x24\x20)"
        R"(\x8D\x48\xD5)"
        R"(\xE8(....))"
    },
#else
    std::regex {
        R"(\x6A\x00)"
        R"(\x6A\x00)"
        R"(\x6A\x00)"
        R"(\x68....)"
        R"(\x6A\x00)"
        R"(\x6A\x05)"
        R"(\xE8(....))"
    },
#endif
};

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

static auto dump_data(std::uintptr_t base) noexcept -> std::vector<char> {
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

static auto find_keylog_callback_off(std::vector<char> const& data) noexcept -> std::uint32_t {
    std::cmatch result;
    for (auto const& p: patterns_keylog_callback) {
        if (std::regex_search(data.data(), data.data() + data.size(), result, p)) {
            std::uint32_t buffer;
            std::memcpy(&buffer, result[1].first, sizeof(buffer));
            return buffer;
        }
    }
    return 0;
}

static auto find_CRYPTO_get_ex_new_index(std::vector<char> const& data) noexcept -> std::uintptr_t {
    std::cmatch result;
    for (auto const& p: patterns_CRYPTO_get_ex_new_index) {
        if (std::regex_search(data.data(), data.data() + data.size(), result, p)) {
            std::int32_t buffer;
            std::memcpy(&buffer, result[1].first, sizeof(buffer));
            auto const offset = (std::uintptr_t)(result[1].second - data.data());
            return offset + buffer;
        }
    }
    return 0;
}

static auto hook_module(char const* name) noexcept -> bool {
    auto const base = (std::uintptr_t)GetModuleHandleA(name);
    if (!base) {
        return false;
    }
    auto const data = dump_data(base);
    auto const keylog_callback_off = find_keylog_callback_off(data);
    assert(keylog_callback_off != 0);
    auto const CRYPTO_get_ex_new_index_off = find_CRYPTO_get_ex_new_index(data);
    assert(CRYPTO_get_ex_new_index_off != 0);
    auto const CRYPTO_get_ex_new_index = (CRYPTO_get_ex_new_index_t)(base + CRYPTO_get_ex_new_index_off);
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL_CTX, keylog_callback_off, nullptr, CRYPTO_EX_new, nullptr, nullptr);
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
