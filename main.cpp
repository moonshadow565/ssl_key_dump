#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <regex>
#include <thread>
#include <unordered_map>
#include <list>
#include <vector>
#include "json.hpp"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef assert
#undef assert
#endif
#define assert(what) do { if (!(what)) { MessageBoxA(nullptr, #what, __func__, MB_ICONERROR); exit(1); } } while(false)

/// Typedefs

constexpr inline auto CRYPTO_EX_INDEX_SSL_CTX = 1;

using long_t = long;

typedef void (* keylog_callback_t) (char* ssl, char const* line);

typedef void (* CRYPTO_EX_new_t) (char* parent, void *ptr, void *ad, int idx, long_t argl, void *argp);

typedef int (* CRYPTO_get_ex_new_index_t) (int class_index, long_t argl, void* argp,
                                           CRYPTO_EX_new_t new_func, void* dup_func, void* free_func);

/// Config

constexpr inline auto config_file_name = "C:/Riot Games/ssl_config.json";

struct Config {
    std::string cache_file_name = "C:/Riot Games/ssl_cache.json";

    std::string log_file_name = "C:/Riot Games/ssl_keylog.txt";

    std::uint32_t modules_wait_interval = 50;

    std::uint32_t modules_wait_timeout = 30000;

    std::vector<std::string> modules = {
        "",
        "RiotGamesApi.dll",
        "RiotClientFoundation.dll",
    };

    std::vector<std::regex> pat_keylog_callback = [] {
        auto result = std::vector<std::regex>{};
        if constexpr (sizeof(void*) == 8) {
            result.emplace_back(R"(\x40\x57)"
                                R"(\x41\x55)"
                                R"(\x41\x56)"
                                R"(\x41\x57)"
                                R"(.{4,20})"
                                R"(\x48\x8B\x82....)"
                                R"(\x4D\x8B\xF1)"
                                R"(\x4D\x8B\xF8)"
                                R"(\x4C\x8B\xEA)"
                                R"(\x48\x8B\xF9)"
                                R"(\x48\x83\xB8(....)\x00)"
                                R"(\x75\x11)");
        } else {
            result.emplace_back(R"(\x8B\x45\x0C)"
                                R"(\x8B\x80....)"
                                R"(\x83\xB8(....)\x00)"
                                R"(\x75\x09)");
            result.emplace_back(R"(\x8B\x80....)"
                                R"(\x83\xB8(....)\x00)"
                                R"(\x75\x09)");
        }
        return result;
    } ();

    std::vector<std::regex> pat_CRYPTO_get_ex_new_index = [] {
        auto result = std::vector<std::regex>{};
        if constexpr (sizeof(void*) == 8) {
            result.emplace_back(R"(\x48\x89\x5C\x24\x28)"
                                R"(\x8D\x48\xD5)"
                                R"(\x45\x33\xC9)"
                                R"(\x48\x89\x5C\x24\x20)"
                                R"(\x33\xD2)"
                                R"(\xE8(....))");
            result.emplace_back(R"(\x48\x89\x5C\x24\x28)"
                                R"(\x45\x33\xC9)"
                                R"(\x33\xD2 )"
                                R"(\x48\x89\x5C\x24\x20)"
                                R"(\x8D\x48\xD5)"
                                R"(\xE8(....))");
        } else {
            result.emplace_back(R"(\x6A\x00)"
                                R"(\x6A\x00)"
                                R"(\x6A\x00)"
                                R"(\x68....)"
                                R"(\x6A\x00)"
                                R"(\x6A\x05)"
                                R"(\xE8(....))");
        }
        return result;
    } ();

    Config(std::filesystem::path const& patternsPath) {
        std::ifstream infile(patternsPath);
        if (infile) {
            nlohmann::json json;
            infile >> json;
            assert(json.is_object());
            if (json.contains("log_file_name")) {
                assert(json["log_file_name"].is_string());
                cache_file_name = json["log_file_name"];
            }
            if (json.contains("cache_file_name")) {
                assert(json["cache_file_name"].is_string());
                cache_file_name = json["cache_file_name"];
            }
            if (json.contains("modules_wait_interval")) {
                assert(json["modules_wait_interval"].is_number_integer());
                cache_file_name = json["modules_wait_interval"];
            }
            if (json.contains("modules_wait_timeout")) {
                assert(json["modules_wait_timeout"].is_number_integer());
                cache_file_name = json["modules_wait_timeout"];
            }
            if (json.contains("modules")) {
                assert(json["modules"].is_array());
                for (auto const& entry: json["modules"]) {
                    assert(entry.is_string());
                    modules.push_back(entry);
                }
            }
            if (json.contains("pat_keylog_callback")) {
                assert(json["pat_keylog_callback"].is_array());
                for (auto const& entry: json["pat_keylog_callback"]) {
                    assert(entry.is_string());
                    pat_keylog_callback.push_back(entry);
                }
            }
            if (json.contains("pat_CRYPTO_get_ex_new_index")) {
                assert(json["pat_CRYPTO_get_ex_new_index"].is_array());
                for (auto const& entry: json["pat_CRYPTO_get_ex_new_index"]) {
                    assert(entry.is_string());
                    pat_CRYPTO_get_ex_new_index.push_back(entry);
                }
            }
        }
    }

    auto find_keylog_callback_off(std::vector<char> const& data) const noexcept -> std::uint32_t {
        std::cmatch result;
        for (auto const& p: pat_keylog_callback) {
            if (std::regex_search(data.data(), data.data() + data.size(), result, p)) {
                std::uint32_t buffer;
                std::memcpy(&buffer, result[1].first, sizeof(buffer));
                return buffer;
            }
        }
        return 0;
    }

    auto find_CRYPTO_get_ex_new_index(std::vector<char> const& data) const noexcept -> std::uintptr_t {
        std::cmatch result;
        for (auto const& p: pat_CRYPTO_get_ex_new_index) {
            if (std::regex_search(data.data(), data.data() + data.size(), result, p)) {
                std::int32_t buffer;
                std::memcpy(&buffer, result[1].first, sizeof(buffer));
                auto const offset = (std::uintptr_t)(result[1].second - data.data());
                return offset + buffer;
            }
        }
        return 0;
    }

    static auto instance() -> Config const& {
        static auto instance = Config{config_file_name};
        return instance;
    }
};

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

static auto get_checksum(std::vector<char> const& data) -> std::uint32_t {
    auto const dos = (PIMAGE_DOS_HEADER)(data.data());
    assert(dos->e_magic == IMAGE_DOS_SIGNATURE);
    auto const nt = (PIMAGE_NT_HEADERS32)(data.data() + dos->e_lfanew);
    assert(nt->Signature == IMAGE_NT_SIGNATURE);
    return (std::uint32_t)(nt->OptionalHeader.CheckSum);
}

struct Offsets {
    std::uint32_t keylog_callback = {};
    std::uint32_t CRYPTO_get_ex_new_index = {};

    auto scan(std::vector<char> const& data) -> bool {
        bool need_flush = false;
        if (!keylog_callback) {
            keylog_callback = Config::instance().find_keylog_callback_off(data);
            need_flush = true;
        }
        if (!CRYPTO_get_ex_new_index) {
            CRYPTO_get_ex_new_index = Config::instance().find_CRYPTO_get_ex_new_index(data);
            need_flush = true;
        }
        return need_flush;
    }
};

struct OffsetsCache {
    std::map<std::uint32_t, Offsets> modules_ = {};
    std::filesystem::path cachePath_ = {};

    OffsetsCache(std::filesystem::path const& cachePath) {
        cachePath_ = cachePath;
        std::ifstream infile(cachePath);
        if (infile) {
            nlohmann::json json;
            infile >> json;
            assert(json.is_object());
            for (auto const& [key, value] : json.items()) {
                auto& item = modules_[std::stoull(key)];
                if (value.contains("keylog_callback")) {
                    assert(value["keylog_callback"].is_number());
                    value.at("keylog_callback").get_to(item.keylog_callback);
                }
                if (value.contains("CRYPTO_get_ex_new_index")) {
                    assert(value["CRYPTO_get_ex_new_index"].is_number());
                    value.at("CRYPTO_get_ex_new_index").get_to(item.CRYPTO_get_ex_new_index);
                }
            }
        }
    }

    auto flush() const -> void {
        auto const outputDir = std::filesystem::path(cachePath_).parent_path();
        if (!std::filesystem::exists(outputDir)) {
            std::filesystem::create_directories(outputDir);
        }
        std::ofstream file(cachePath_);
        if (file) {
            nlohmann::json json;
            for (auto const&[key, value]: modules_) {
                json[std::to_string(key)] = nlohmann::json {
                    { "keylog_callback", value.keylog_callback },
                    { "CRYPTO_get_ex_new_index", value.CRYPTO_get_ex_new_index },
                };
            }
        }
    }

    auto find(std::vector<char> const& data) -> Offsets {
        auto checksum = get_checksum(data);
        auto& result = modules_[checksum];
        auto const need_flush = result.scan(data);
        if (need_flush) {
             flush();
        }
        return result;
    }

    static auto instance() -> OffsetsCache& {
        static auto instance = OffsetsCache{Config::instance().cache_file_name};
        return instance;
    }
};

/// Hooking

static auto log_func(char*, char const* line) noexcept -> void {
    static auto mutex = std::mutex{};
    auto lock = std::lock_guard<std::mutex>{ mutex };
    static auto file = [] {
        auto const& log_file_name = Config::instance().log_file_name;
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

static auto hook_module(std::string const& name) noexcept -> bool {
    auto const base = (std::uintptr_t)GetModuleHandleA(name.empty() ? nullptr : name.c_str());
    if (!base) {
        return false;
    }
    auto const data = dump_data(base);
    auto const offsets = OffsetsCache::instance().find(data);
    assert(offsets.keylog_callback != 0);
    assert(offsets.CRYPTO_get_ex_new_index != 0);
    auto const CRYPTO_get_ex_new_index = (CRYPTO_get_ex_new_index_t)(base + offsets.CRYPTO_get_ex_new_index);
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL_CTX, offsets.keylog_callback, nullptr, CRYPTO_EX_new, nullptr, nullptr);
    return true;
}

static auto run() -> void {
    auto thread = std::thread([]{
        auto const& config = Config::instance();
        auto elapsed = 0u;
        auto unhooked = std::list<std::string> { config.modules.begin(), config.modules.end() };
        while (!unhooked.empty()) {
            for (auto i = unhooked.begin(); i != unhooked.end(); ) {
                if (hook_module(*i)) {
                    i = unhooked.erase(i);
                } else {
                    ++i;
                }
            }
            elapsed += config.modules_wait_interval;
            if (config.modules_wait_timeout && elapsed >= config.modules_wait_timeout) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(config.modules_wait_interval));
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
