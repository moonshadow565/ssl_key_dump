static_assert(sizeof(void*) == 4, "Compile in 32bit mode");
#include <algorithm>
#include <chrono>
#include <cstdarg>
#include <cstring>
#include <cstdio>
#include <functional>
#include <fstream>
#include <mutex>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include "MinHook.h"
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#ifdef assert
#undef assert
#endif
#define assert(what) do { if (!(what)) { MessageBoxA(nullptr, #what, __func__, MB_ICONERROR); exit(1); } } while(false)

static void log_key_register(void const* ssl) noexcept {
    using cb_t = void(*)(void const* ssl, char const* line);
    auto const ctx = *(void* const*)((char const*)ssl + 1424);
    auto const cb = (cb_t*)((char*)ctx + 540);
    *cb = [](void const*, char const* line) { 
        static auto mutex = std::mutex{};
        auto lock = std::lock_guard<std::mutex>{ mutex };
        static auto file = std::ofstream{ "C:/Riot Games/ssl_keylog.txt", std::ios::binary | std::ios::app };
        file.write(line, strlen(line));
        file.put('\n');
        file.flush();
    };
}

static auto dump_data(uintptr_t base) noexcept {
    auto const handle = GetCurrentProcess();
    char raw[1024] = {};
    assert(ReadProcessMemory(handle, (void const*)base, raw, sizeof(raw), nullptr));
    auto const dos = (PIMAGE_DOS_HEADER)(raw);
    assert(dos->e_magic == IMAGE_DOS_SIGNATURE);
    auto const nt = (PIMAGE_NT_HEADERS32)(raw + dos->e_lfanew);
    assert(nt->Signature == IMAGE_NT_SIGNATURE);
    auto const size = (size_t)(nt->OptionalHeader.SizeOfImage);
    auto result = std::vector<char>();
    result.resize(size);
    for (size_t i = 0; i < size; i += 0x1000) {
        ReadProcessMemory(handle, (void const*)(base + i), result.data() + i, 0x1000, nullptr);
    }
    return result;
}

template<size_t S>
static uintptr_t find_call(std::vector<char> const& data, char const(&pat)[S]) noexcept {
    constexpr auto pat_size = S - 1; // remove null terminator
    auto const data_begin = data.data();
    auto const data_end = data.data() + data.size();
    auto const pat_begin = &pat[0];
    auto const pat_end = &pat[pat_size];
    auto const i = std::search(data_begin, data_end, std::boyer_moore_horspool_searcher(pat_begin, pat_end));
    if (i == data_end) {
        return 0u;
    }
    auto offset = int32_t{0};
    memcpy(&offset, i + pat_size, sizeof(offset));
    auto const result = (int32_t)(i + pat_size + sizeof(offset) - data_begin);
    return (uintptr_t)(result + offset);
}

template<size_t I>
static bool hook_module(char const* name) noexcept {
    using hook_t = void(*)(void* s, int fd);
    auto const base = (uintptr_t)GetModuleHandleA(name);
    if (!base) {
        return false;
    }
    auto const data = dump_data(base);
    auto const offset = find_call(data, "\xFF\xB5\x3C\xFE\xFF\xFF\xFF\x70\x04\xE8");
    assert(offset != 0);
    auto const target = (hook_t)(base + offset);
    static hook_t org = nullptr;
    static hook_t hook = [](void* ssl, int fd) {
        log_key_register(ssl);
        org(ssl, fd);
    };
    assert(MH_CreateHook((void*)target, (void*)hook, (void**)&org) == MH_OK);
    assert(MH_EnableHook((void*)target) == MH_OK);
    return true;
}

template<size_t I>
static void hook_module_wait(char const* module_name, uint32_t time, uint32_t interval = 50) noexcept {
    auto thread = std::thread([=]{
        uint32_t elapsed = 0;
        while (!hook_module<I>(module_name)) {
            elapsed += interval;
            if (time && elapsed >= time) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(interval));
        }
    });
    thread.detach();
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        assert(MH_Initialize() == MH_OK);
        hook_module<0>(nullptr);
        hook_module_wait<1>("Foundation.dll", 30000);
    }
    return TRUE;
}