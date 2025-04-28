#include <cstring>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <vector>
#include <windows.h>
#include <zlib.h>

template <typename T>
T align(T value, T alignment) {
    auto result = value + ((value % alignment == 0) ? 0 : alignment - (value % alignment));
    return result;
}

const IMAGE_NT_HEADERS64* get_nt_headers(const std::uint8_t* image) {
    auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    return reinterpret_cast<const IMAGE_NT_HEADERS64*>(image + dos_header->e_lfanew);
}

// Helper: decompress a packed section
std::vector<std::uint8_t> decompress_section(const std::uint8_t* section_start, DWORD section_size) {
    auto unpacked_size = *reinterpret_cast<const std::size_t*>(section_start);
    auto packed_data = section_start + sizeof(std::size_t);
    auto packed_size = section_size - sizeof(std::size_t);
    std::vector<std::uint8_t> out(unpacked_size);
    uLong out_size = static_cast<uLong>(unpacked_size);
    if (uncompress(out.data(), &out_size, packed_data, packed_size) != Z_OK) {
        std::cerr << "Error: couldn't decompress section data." << std::endl;
        ExitProcess(100);
    }
    return out;
}

// Helper: find min/max VirtualAddress and max section size
void find_section_bounds(const IMAGE_SECTION_HEADER* section_table, int num_sections, uintptr_t& min_va, uintptr_t& max_va, DWORD& max_raw_size) {
    min_va = (uintptr_t)-1;
    max_va = 0;
    max_raw_size = 0;
    for (int i = 0; i < num_sections; ++i) {
        if (section_table[i].VirtualAddress < min_va) min_va = section_table[i].VirtualAddress;
        if (section_table[i].VirtualAddress + section_table[i].Misc.VirtualSize > max_va)
            max_va = section_table[i].VirtualAddress + section_table[i].Misc.VirtualSize;
        if (section_table[i].SizeOfRawData > max_raw_size) max_raw_size = section_table[i].SizeOfRawData;
    }
}

// Only map sections, not headers
std::uint8_t* load_sections_only(const std::vector<std::uint8_t>& headers, const std::vector<std::uint8_t>& sections_data) {
    const IMAGE_NT_HEADERS64* nt_header = get_nt_headers(headers.data());
    const IMAGE_SECTION_HEADER* section_table = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        reinterpret_cast<const std::uint8_t*>(&nt_header->OptionalHeader) + nt_header->FileHeader.SizeOfOptionalHeader
    );
    int num_sections = nt_header->FileHeader.NumberOfSections;
    // Find bounds
    uintptr_t min_va, max_va;
    DWORD max_raw_size;
    find_section_bounds(section_table, num_sections, min_va, max_va, max_raw_size);
    size_t total_size = max_va - min_va;
    std::uint8_t* base = reinterpret_cast<std::uint8_t*>(VirtualAlloc(nullptr, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!base) {
        std::cerr << "Error: VirtualAlloc failed: Windows error " << GetLastError() << std::endl;
        ExitProcess(5);
    }
    // Copy each section to its mapped address
    auto first_section_offset = section_table[0].PointerToRawData;
    for (int i = 0; i < num_sections; ++i) {
        if (section_table[i].SizeOfRawData > 0) {
            auto section_offset = section_table[i].PointerToRawData - first_section_offset;
            if (section_offset < sections_data.size()) {
                std::memcpy(base + (section_table[i].VirtualAddress - min_va),
                    sections_data.data() + section_offset,
                    std::min<DWORD>(section_table[i].SizeOfRawData, static_cast<DWORD>(sections_data.size() - section_offset)));
            }
        }
    }
    return base - min_va; // So that VirtualAddress in headers can be used as (base + VA)
}

// Patch: all fixups/imports must use (base + VA) where base = returned pointer from load_sections_only
void load_imports_sections(std::uint8_t* base, const std::vector<std::uint8_t>& headers) {
    const IMAGE_NT_HEADERS64* nt_header = get_nt_headers(headers.data());
    auto directory_entry = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (directory_entry.VirtualAddress == 0) return;
    auto import_table = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + directory_entry.VirtualAddress);
    while (import_table->OriginalFirstThunk != 0) {
        auto dll_name = reinterpret_cast<char*>(base + import_table->Name);
        auto dll_import = LoadLibraryA(dll_name);
        if (!dll_import) {
            std::cerr << "Error: failed to load DLL from import table: " << dll_name << std::endl;
            ExitProcess(6);
        }
        auto lookup_table = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + import_table->OriginalFirstThunk);
        auto address_table = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + import_table->FirstThunk);
        while (lookup_table->u1.AddressOfData != 0) {
            FARPROC function = nullptr;
            auto lookup_address = lookup_table->u1.AddressOfData;
            if ((lookup_address & IMAGE_ORDINAL_FLAG64) != 0) {
                function = GetProcAddress(dll_import, reinterpret_cast<LPSTR>(lookup_address & 0xFFFFFFFF));
                if (!function) {
                    std::cerr << "Error: failed ordinal lookup for " << dll_name << ": " << (lookup_address & 0xFFFFFFFF) << std::endl;
                    ExitProcess(7);
                }
            } else {
                auto import_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + lookup_address);
                function = GetProcAddress(dll_import, import_name->Name);
                if (!function) {
                    std::cerr << "Error: failed named lookup: " << dll_name << "!" << import_name->Name << std::endl;
                    ExitProcess(8);
                }
            }
            address_table->u1.Function = reinterpret_cast<std::uint64_t>(function);
            ++lookup_table;
            ++address_table;
        }
        ++import_table;
    }
}

void relocate_sections(std::uint8_t* base, const std::vector<std::uint8_t>& headers) {
    const IMAGE_NT_HEADERS64* nt_header = get_nt_headers(headers.data());
    if ((nt_header->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0) {
        std::cerr << "Error: image cannot be relocated." << std::endl;
        ExitProcess(9);
    }
    auto directory_entry = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (directory_entry.VirtualAddress == 0) {
        std::cerr << "Error: image can be relocated, but contains no relocation directory." << std::endl;
        ExitProcess(10);
    }
    std::uintptr_t delta = reinterpret_cast<std::uintptr_t>(base) - nt_header->OptionalHeader.ImageBase;
    auto relocation_table = reinterpret_cast<IMAGE_BASE_RELOCATION*>(base + directory_entry.VirtualAddress);
    while (relocation_table->VirtualAddress != 0) {
        std::size_t relocations = (relocation_table->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(std::uint16_t);
        auto relocation_data = reinterpret_cast<std::uint16_t*>(&relocation_table[1]);
        for (std::size_t i = 0; i < relocations; ++i) {
            auto relocation = relocation_data[i];
            std::uint16_t type = relocation >> 12;
            std::uint16_t offset = relocation & 0xFFF;
            auto ptr = reinterpret_cast<std::uintptr_t*>(base + relocation_table->VirtualAddress + offset);
            if (type == IMAGE_REL_BASED_DIR64)
                *ptr += delta;
        }
        relocation_table = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<std::uint8_t*>(relocation_table) + relocation_table->SizeOfBlock);
    }
}

int main(int argc, char* argv[]) {
    // Find packed sections (.pack0 and .pack1)
    auto base = reinterpret_cast<const std::uint8_t*>(GetModuleHandleA(NULL));
    auto nt_header = get_nt_headers(base);
    auto section_table = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        reinterpret_cast<const std::uint8_t*>(&nt_header->OptionalHeader) + nt_header->FileHeader.SizeOfOptionalHeader
    );
    const IMAGE_SECTION_HEADER* headers_section = nullptr;
    const IMAGE_SECTION_HEADER* sections_section = nullptr;
    for (std::uint16_t i = 0; i < nt_header->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(section_table[i].Name, ".pack0", 7) == 0) headers_section = &section_table[i];
        else if (std::memcmp(section_table[i].Name, ".pack1", 7) == 0) sections_section = &section_table[i];
        if (headers_section && sections_section) break;
    }
    if (!headers_section || !sections_section) {
        std::cerr << "Error: couldn't find packed sections in binary." << std::endl;
        ExitProcess(101);
    }
    // Decompress headers, use, then discard
    auto headers = decompress_section(base + headers_section->VirtualAddress, headers_section->Misc.VirtualSize);
    // Only map sections, not headers
    auto mapped_base = load_sections_only(headers, decompress_section(base + sections_section->VirtualAddress, sections_section->Misc.VirtualSize));
    // After mapping, headers and sections buffers are out of scope and can be released
    // Use headers as a guide for fixups
    load_imports_sections(mapped_base, headers);
    relocate_sections(mapped_base, headers);
    // Entry point
    const IMAGE_NT_HEADERS64* orig_nt_headers = get_nt_headers(headers.data());
    auto entrypoint = mapped_base + orig_nt_headers->OptionalHeader.AddressOfEntryPoint;
    reinterpret_cast<void(*)()>(entrypoint)();
    return 0;
}