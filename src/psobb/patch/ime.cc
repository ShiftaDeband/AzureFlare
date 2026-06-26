#include <console.hh>
#include <hook.hh>
#include <pattern.hh>

#include <settings/settings.hh>

#include "ime.hh"

constexpr auto INPUT_ADDRESS_OFFSET = 0x56;
constexpr auto PATCHED_CALL = 0x008EC39C;

namespace AzureFlare::Patches
{
    void IME::Patch()
    {
        PRINT_DEBUG("IME: Attempting to patch IME");

        auto ime = hook::pattern("55 8B EC 6A FF 68 88 6E 99 00");
        ime.for_each_result([](hook::pattern_match i)
        {
            auto offset = i.get<std::uint32_t>();
            PRINT_DEBUG("IME: Found pattern for IME at 0x%p, patching", offset);

            int finalOffset = reinterpret_cast<std::uint32_t>(offset) + INPUT_ADDRESS_OFFSET;
            
            if (Settings::DisableIMEInput) Utils::hook::write(finalOffset, { 0x00, 0x8E, 0xC3, 0x9C }); // call ds:dword_8EC39C
        });

        // Patch ImmGetContext to disable IME in game chat (vs. character creation)
        if (Settings::DisableIMEInput)
        {
            HMODULE hMod = GetModuleHandleA("PsoBB.exe");
            if (hMod)
            {
                uintptr_t base = reinterpret_cast<uintptr_t>(hMod);
                uint8_t* patch_addr = reinterpret_cast<uint8_t*>(base + 0x44B044);
                uint8_t expected[] = { 0x50, 0xE8, 0xDE, 0x0D, 0x06, 0x00, 0xC3 };
                if (memcmp(patch_addr, expected, 7) == 0)
                {
                    DWORD old_protect = 0;
                    if (VirtualProtect(patch_addr, 4096, PAGE_EXECUTE_READWRITE, &old_protect))
                    {
                        *reinterpret_cast<uint16_t*>(patch_addr) = 0xC033;
                        *reinterpret_cast<uint8_t*>(patch_addr + 2) = 0xC3;
                        for (int i = 3; i < 7; i++)
                            *reinterpret_cast<uint8_t*>(patch_addr + i) = 0x90;
                        VirtualProtect(patch_addr, 4096, old_protect, &old_protect);
                        PRINT_DEBUG("IME: Patched ImmGetContext at 0x%p", patch_addr);
                    }
                }
            }
        }

        ime.clear();
    }
}