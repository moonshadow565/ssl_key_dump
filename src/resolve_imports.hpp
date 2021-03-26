#pragma once
#include "common.hpp"

struct Resolver {
    std::uintptr_t base = {};
    std::uint32_t functions_num = {};
    std::uint32_t const* functions = {};
    std::uint32_t const* names = {};
    std::uint16_t const* ordinals = {};

    static auto find(wchar_t const* name) noexcept -> Resolver {
        auto const module = ModuleInfo::find(name);
        if (!module.base) {
            return {};
        }
        auto const dos = reinterpret_cast<PIMAGE_DOS_HEADER>(module.base);
        auto const nt = reinterpret_cast<PIMAGE_NT_HEADERS>(module.base + dos->e_lfanew);
        auto const eat_address = nt->OptionalHeader.DataDirectory[0].VirtualAddress;
        auto const eat = reinterpret_cast<std::uint32_t const*>(module.base + eat_address);
        auto result = Resolver {};
        result.base = module.base;
        result.functions_num = eat[5];
        result.functions = reinterpret_cast<std::uint32_t const*>(module.base + eat[7]);
        result.names = reinterpret_cast<std::uint32_t const*>(module.base + eat[8]);
        result.ordinals = (std::uint16_t const*)(module.base + eat[9]);
        return result;
    }

    auto find_function(char const* name) const noexcept -> std::uintptr_t {
        for (auto low = 0u, high = functions_num; low != high; ) {
            auto const mid = (low + high) / 2;
            auto const func_name = reinterpret_cast<char const*>(base + names[mid]);
            auto const result = cstr_cmp(name, func_name);
            if (result > 0) {
                low = mid + 1;
            } else if (result < 0){
                high = mid;
            } else {
                return base + functions[ordinals[mid]];
            }
        }
        return false;
    }

    template<typename T>
    auto resolve(char const* name, T* out) const noexcept -> bool {
        auto const raw = find_function(name);
        return *out = reinterpret_cast<T>(raw);
    }
};

struct IAT {
    int (WINAPI * MessageBoxA) (HWND window, LPCSTR text, LPCSTR caption, UINT type) noexcept = nullptr;
    #define MessageBoxA iat.MessageBoxA

    DWORD (NTAPI * LdrRegisterDllNotification) (ULONG Flags, DLL_LOAD_CB callback,
                                                  PVOID ctx, PVOID *outCookie) noexcept = nullptr;
    #define LdrRegisterDllNotification iat.LdrRegisterDllNotification

    DWORD (NTAPI * LdrUnregisterDllNotification) (PVOID Cookie) noexcept = nullptr;
    #define LdrUnregisterDllNotification iat.LdrUnregisterDllNotification

    HANDLE (WINAPI * CreateThread) (LPSECURITY_ATTRIBUTES attributes, SIZE_T stack,
                                      LPTHREAD_START_ROUTINE func, LPVOID arg,
                                      DWORD flags,
                                      LPDWORD tid) noexcept = nullptr;
    #define CreateThread iat.CreateThread

    BOOL (WINAPI * IsBadReadPtr) (LPCVOID address, SIZE_T size) noexcept = nullptr;
    #define IsBadReadPtr iat.IsBadReadPtr

    void (WINAPI * Sleep) (DWORD ms) noexcept = nullptr;
    #define Sleep iat.Sleep

    FILE* (* fopen) (char const* file, char const* mode) noexcept = nullptr;
    #define fopen iat.fopen

    int (* fclose) (FILE *Stream) noexcept = nullptr;
    #define fclose iat.fclose

    int (* fflush) (FILE *Stream) noexcept = nullptr;
    #define fflush iat.fflush

    size_t (* fread) (void* ptr, size_t size, size_t count, FILE* file) noexcept = nullptr;
    #define fread iat.fread

    size_t (* fwrite) (void const* ptr, size_t size, size_t count, FILE* file) noexcept = nullptr;
    #define fwrite iat.fwrite

    int (* exit) (int code) noexcept = nullptr;
    #define exit iat.exit

    char* (* getenv) (char const* name) noexcept = nullptr;
    #define getenv iat.getenv

    void* (* realloc) (void* ptr, size_t size) noexcept = nullptr;
    #define realloc iat.realloc

    void* (* memset) (void* ptr, int value, size_t num) noexcept = nullptr;
    #define memset iat.memset

    void* (* memcpy) (void* dst, void const* src, size_t num) noexcept = nullptr;
    #define memcpy iat.memcpy

    void* (* memmove) (void* dst, void const* src, size_t num) noexcept = nullptr;
    #define memmove iat.memmove
} iat = {};

extern "C" {
    void __CxxFrameHandler2() { exit(1); }
    void __CxxFrameHandler3() { exit(1); }
    void __CxxFrameHandler4() { exit(1); }
    void __std_terminate() { exit(1); }
}

void ResolveImports() noexcept {
    auto const user32 = Resolver::find(L"USER32.dll");
    auto const ntdll = Resolver::find(L"NTDLL.dll");
    auto const kernel32 = Resolver::find(L"KERNEL32.dll");
    auto const ucrtbase = Resolver::find(L"ucrtbase.dll");

    user32.resolve("MessageBoxA", &MessageBoxA);
    ntdll.resolve("LdrRegisterDllNotification", &LdrRegisterDllNotification);
    ntdll.resolve("LdrUnregisterDllNotification", &LdrUnregisterDllNotification);
    kernel32.resolve("CreateThread", &CreateThread);
    kernel32.resolve("IsBadReadPtr", &IsBadReadPtr);
    kernel32.resolve("Sleep", &Sleep);
    ucrtbase.resolve("fclose", &fclose);
    ucrtbase.resolve("fflush", &fflush);
    ucrtbase.resolve("fopen", &fopen);
    ucrtbase.resolve("fread", &fread);
    ucrtbase.resolve("fwrite", &fwrite);
    ucrtbase.resolve("exit", &exit);
    ucrtbase.resolve("getenv", &getenv);
    ucrtbase.resolve("realloc", &realloc);
    ucrtbase.resolve("memset", &memset);
    ucrtbase.resolve("memcpy", &memcpy);
    ucrtbase.resolve("memmove", &memmove);
}


