#pragma once
#include <cstdint>
#include <cstddef>
#include "ppp.hpp"

constexpr inline char const default_keylog_filename[] = "./ssl_keylog.txt";

constexpr inline wchar_t const* modules_names[] = {
    nullptr,
    L"RiotGamesApi.dll",
    L"RiotClientFoundation.dll",
};

constexpr inline auto const modules_count = sizeof(modules_names) / sizeof(modules_names[0]);

constexpr inline auto modules_wait_interval = 50;

constexpr inline auto modules_wait_time = 30000;

constexpr inline auto find_keylog_callback = &ppp::any<
#if UINTPTR_MAX > 0xFFFFFFFF
        "48 8B 82 ?? ?? ?? ?? 4D 8B F1 4D 8B E0 4C 8B EA 48 8B F9 48 83 B8 u[?? ?? ?? ??] 00 75 11"_pattern,
        "48 8B 82 ?? ?? ?? ?? 4D 8B F1 4D 8B F1 4C 8B EA 48 8B F9 48 83 B8 u[?? ?? ?? ??] 00 75 11"_pattern
#else
        "8B 45 0C 8B 80 ?? ?? ?? ?? 83 B8 u[?? ?? ?? ??] 00 75 09"_pattern,
        "8B 80 ?? ?? ?? ?? 83 B8 u[?? ?? ?? ??] 00 75 09"_pattern
#endif
        >;

constexpr inline auto find_CRYPTO_get_ex_new_index = &ppp::any<
#if UINTPTR_MAX > 0xFFFFFFFF
        "48 89 5C 24 28 8D 48 D5 45 33 C9 48 89 5C 24 20 33 D2 E8 r[?? ?? ?? ??]"_pattern,
        "48 89 5C 24 28 45 33 C9 33 D2 48 89 5C 24 20 8D 48 D5 E8 r[?? ?? ?? ??]"_pattern
#else
        "6A 00 6A 00 6A 00 68 ?? ?? ?? ?? 6A 00 6A 05 E8 r[?? ?? ?? ??]"_pattern
#endif
        >;
