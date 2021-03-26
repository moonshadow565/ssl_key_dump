#include "config.hpp"
#include "common.hpp"
#ifndef NOSTDLIB
#define ResolveImports() do {} while(false)
#else
#include "resolve_imports.hpp"
#endif

static FILE* log_file = nullptr;

using long_t = long;

using keylog_callback_t = void (*) (char* ssl, char* line);

using CRYPTO_EX_new_t = void (*) (char* parent, void *ptr, void *ad, int idx, long_t argl, void *argp);

using CRYPTO_get_ex_new_index_t = int (*) (int class_index, long_t argl, void* argp,
                                           CRYPTO_EX_new_t new_func, void* dup_func, void* free_func);

constexpr inline auto CRYPTO_EX_INDEX_SSL_CTX = 1;

static auto log_func (char*, char* line) noexcept -> void {
    auto last = line;
    while (*last) ++last;
    *last = '\n';
    fwrite(line, 1, last - line + 1, log_file);
    *last = '\0';
    fflush(log_file);
}

static auto CRYPTO_EX_new (char* parent, void*, void*, int, long_t argl, void*) noexcept -> void {
    *reinterpret_cast<keylog_callback_t*>(parent + argl) = log_func;
}

struct Offsets {
    std::uint32_t reserved;
    std::uint32_t checksum;
    std::uint32_t keylog_callback;
    std::uint32_t get_ex_new_index;

    auto scan(ModuleInfo module) noexcept -> bool {
        auto const dos = reinterpret_cast<PIMAGE_DOS_HEADER>(module.base);
        auto const nt = reinterpret_cast<PIMAGE_NT_HEADERS>(module.base + dos->e_lfanew);
        auto const size = nt->OptionalHeader.BaseOfCode + nt->OptionalHeader.SizeOfCode;
        auto const newChecksum = nt->OptionalHeader.CheckSum;

        // If checksum doesn't match we need to force rescan offsets
        if (checksum != newChecksum) {
            checksum = newChecksum;
            keylog_callback = 0;
            get_ex_new_index = 0;
        }

        // Scanning pages in reverse allows us to scan any pattern that crosses page boundary
        bool changed = false;
        std::uint32_t offset = size;
        std::uint32_t last_page_size = 0;
        while (offset && (keylog_callback == 0 || get_ex_new_index == 0)) {
            auto const page_size = offset % 0x1000 ? offset % 0x1000 : 0x1000;
            offset -= page_size;
            auto const address = reinterpret_cast<char const*>(module.base + offset);
            if (IsBadReadPtr(address, page_size)) {
                last_page_size = 0;
                continue;
            }
            auto const view = std::span<char const> { address, page_size + last_page_size };
            if (keylog_callback == 0) {
                if (auto const found = find_keylog_callback(view, offset)) {
                    keylog_callback = std::get<1>(*found);
                    changed = true;
                }
            }
            if (get_ex_new_index == 0) {
                if (auto const found = find_CRYPTO_get_ex_new_index(view, offset)) {
                    get_ex_new_index = static_cast<std::uint32_t>(std::get<1>(*found));
                    changed = true;
                }
            }
            last_page_size = page_size;
        }
        return changed;
    }
};

struct CacheOffsets {
    struct Entry {
        Offsets offsets;
        wchar_t name[0x38];
    };
    Entry* entries = nullptr;
    std::size_t count = {};
    std::size_t capacity = {};
    bool needsave = false;

    auto find_or_insert(wchar_t const* name) noexcept -> Offsets& {
        auto lo = 0u;
        auto hi = count;
        while (lo < hi) {
            auto const mid =  lo + (hi - lo) / 2;
            auto const cmp = cstr_icmp(name, entries[mid].name);
            if (cmp < 0) {
                hi = mid;
            } else if (cmp > 0) {
                lo = mid + 1;
            } else {
                return entries[mid].offsets;
            }
        }
        if (count == capacity) {
            capacity += (capacity >> 1) + 1;
            entries = reinterpret_cast<Entry*>(realloc(entries, sizeof(Entry) * capacity));
        }
        memmove(entries + lo + 1, entries + lo, (count - lo) * sizeof(Entry));
        cstr_copy(entries[lo].name, name);
        entries[lo].offsets = {};
        ++count;
        needsave = true;
        return entries[lo].offsets;
    }

    auto load(char const* cache_filename) noexcept -> void {
        if (auto const file = fopen(cache_filename, "rb")) {
            for (;;) {
                if (count == capacity) {
                    capacity += (capacity >> 1) + 1;
                    entries = reinterpret_cast<Entry*>(realloc(entries, sizeof(Entry) * capacity));
                }
                if (fread(&entries[count], sizeof(Offsets), 1, file) != sizeof(Offsets)) {
                    break;
                }
                ++count;
            }
            fclose(file);
        }
    }

    auto save(char const* cache_filename) const noexcept -> void {
        if (needsave) {
            if (auto const file = fopen(cache_filename, "wb")) {
                fwrite(entries, sizeof(Entry), count, file);
                fclose(file);
            }
        }
    }

    auto hook(ModuleInfo module) noexcept -> bool {
        auto& off = find_or_insert(module.name);
        if (off.scan(module)) {
            needsave = true;
        }

        if (!off.keylog_callback || !off.get_ex_new_index) {
            return false;
        }

        auto const get_ex_new_index = reinterpret_cast<CRYPTO_get_ex_new_index_t>(module.base + off.get_ex_new_index);
        get_ex_new_index(CRYPTO_EX_INDEX_SSL_CTX, off.keylog_callback, nullptr, CRYPTO_EX_new, nullptr, nullptr);

        return true;
    }
};

struct Hook {
    char const* keylog_filename;
    CacheOffsets cache_offsets = {};
    std::uint32_t remaining = {};
    bool is_done[modules_count] = {};

    auto start() noexcept -> void {
        keylog_filename = getenv("SSLKEYLOGFILE");
        if (!keylog_filename) {
            keylog_filename = default_keylog_filename;
        }

        log_file = fopen(keylog_filename, "ab");
        assert(log_file);

        char cache_filename[0x100];
        cstr_copy(cstr_copy(cache_filename, keylog_filename), ".dat");
        cache_offsets.load(cache_filename);
        remaining = modules_count;
    }

    auto stop() noexcept -> void {
        char cache_filename[0x100];
        cstr_copy(cstr_copy(cache_filename, keylog_filename), ".dat");
        cache_offsets.save(cache_filename);
    }

    auto update() noexcept -> bool {
        for (auto i = 0; remaining != 0 && i != modules_count; ++i) {
            if (is_done[i]) {
                continue;
            }
            auto const module = ModuleInfo::find(modules_names[i]);
            if (!module.base) {
                continue;
            }
            assert(cache_offsets.hook(module));
            is_done[i] = true;
            --remaining;
        }
        return remaining != 0;
    }

    static auto WINAPI loop(LPVOID) noexcept -> DWORD {
        auto hook = Hook {};
        hook.start();
        std::uint32_t elapsed = 0;
        while (hook.update()) {
            elapsed += modules_wait_interval;
            if (elapsed >= modules_wait_time) {
                break;
            }
            Sleep(modules_wait_interval);
        }
        hook.stop();
        return 0;
    }
};

__declspec(dllexport) auto WINAPI init(LPVOID) noexcept -> DWORD {
    ResolveImports();
    Hook::loop(nullptr);
    return 0;
}

__declspec(dllexport) auto WINAPI init_new_thread(LPVOID) noexcept -> DWORD {
    ResolveImports();
    CreateThread(nullptr, 0, &Hook::loop, nullptr, 0, nullptr);
    return 0;
}

#ifndef NODLLMAIN
auto WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) noexcept -> BOOL {
    if (reason == DLL_PROCESS_ATTACH) {
        init_new_thread(nullptr);
    }
    return TRUE;
}
#endif
