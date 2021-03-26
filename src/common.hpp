#pragma once
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <cstddef>
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <intrin.h>
#include <processthreadsapi.h>
#ifdef assert
#undef assert
#endif
#define assert(what) do { if (!(what)) { MessageBoxA(nullptr, #what, __func__, MB_ICONERROR); exit(1); } } while(false)

struct UNI_STR {
    USHORT Length;
    USHORT MaximumLength;
    PWCH Buffer;
};

struct DLL_LOAD_CB_DATA {
    ULONG Flags;
    UNI_STR const* FullDllName;
    UNI_STR const* BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
};
using DLL_LOAD_CB = void (WINAPI * )(ULONG reason, DLL_LOAD_CB_DATA const* data, LPVOID ctx);

template <typename T>
constexpr auto cstr_copy(T* dst, T const* src) noexcept -> T* {
    while ((*dst = *src)) {
        ++dst, ++src;
    }
    return dst;
}

template <typename T>
constexpr auto cstr_icmp(T const* lhs, T const* rhs) noexcept -> int {
    constexpr auto const lower = [] (T c) constexpr noexcept -> int {
        return (c >= 'A' && c <= 'Z') ? ((c - 'A') + 'a') : c;
    };
    while (*lhs && lower(*lhs) == lower(*rhs)) {
        ++lhs, ++rhs;
    }
    return lower(*lhs) - lower(*rhs);
};

template <typename T>
constexpr auto cstr_cmp(T const* lhs, T const* rhs) noexcept -> int {
    while (*lhs && *lhs == *rhs) {
        ++lhs, ++rhs;
    }
    return *lhs - *rhs;
};

struct ModuleInfo {
    std::uintptr_t base = {};
    wchar_t const* name = {};

    static auto from_cb(DLL_LOAD_CB_DATA const* data) -> ModuleInfo {
        return { reinterpret_cast<std::uintptr_t>(data->DllBase), data->BaseDllName->Buffer };
    }

    static auto find(wchar_t const* name) noexcept -> ModuleInfo {
        #if UINTPTR_MAX > 0xFFFFFFFF
        auto const peb = reinterpret_cast<char const*>(__readgsqword(0x60));
        #else
        auto const peb = reinterpret_cast<char const*>(__readfsdword(0x30));
        #endif
        auto const ldr = reinterpret_cast<char const* const*>(peb)[3];
        auto image_entry = reinterpret_cast<char const* const*>(ldr + 8)[1];
        while (auto const image_base = reinterpret_cast<std::uintptr_t const*>(image_entry)[6]) {
            auto const image_name = reinterpret_cast<wchar_t const* const*>(image_entry)[12];
            if (!name || cstr_icmp(name, image_name) == 0) {
                return { image_base, image_name };
            }
            image_entry = reinterpret_cast<char const* const*>(image_entry)[0];
        }
        return {};
    }
};

extern "C" {
extern DWORD NTAPI LdrRegisterDllNotification(ULONG Flags, DLL_LOAD_CB callback, PVOID, PVOID *outCookie);

extern DWORD NTAPI LdrUnregisterDllNotification(PVOID Cookie);
}
