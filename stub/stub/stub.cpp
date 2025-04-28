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

struct PackedSections {
    std::vector<std::uint8_t> headers;
    std::vector<std::uint8_t> sections;
};

PackedSections get_packed_sections() {
    PackedSections result;
    
    // Find our packed sections (.pack0 and .pack1)
    auto base = reinterpret_cast<const std::uint8_t*>(GetModuleHandleA(NULL));
    auto nt_header = get_nt_headers(base);
    auto section_table = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        reinterpret_cast<const std::uint8_t*>(&nt_header->OptionalHeader) + nt_header->FileHeader.SizeOfOptionalHeader
    );
    
    const IMAGE_SECTION_HEADER* headers_section = nullptr;
    const IMAGE_SECTION_HEADER* sections_section = nullptr;

    for (std::uint16_t i = 0; i < nt_header->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(section_table[i].Name, ".pack0", 7) == 0) {
            headers_section = &section_table[i];
        }
        else if (std::memcmp(section_table[i].Name, ".pack1", 7) == 0) {
            sections_section = &section_table[i];
        }
        
        if (headers_section && sections_section) {
            break;
        }
    }

    if (!headers_section) {
        std::cerr << "Error: couldn't find .pack0 section (headers) in binary." << std::endl;
        ExitProcess(1);
    }
    
    if (!sections_section) {
        std::cerr << "Error: couldn't find .pack1 section (sections) in binary." << std::endl;
        ExitProcess(2);
    }

    // Extract and decompress headers
    auto headers_start = base + headers_section->VirtualAddress;
    auto headers_unpacked_size = *reinterpret_cast<const std::size_t*>(headers_start);
    auto headers_packed_data = headers_start + sizeof(std::size_t);
    auto headers_packed_size = headers_section->Misc.VirtualSize - sizeof(std::size_t);

    result.headers.resize(headers_unpacked_size);
    uLong headers_decompressed_size = static_cast<uLong>(headers_unpacked_size);

    if (uncompress(result.headers.data(), &headers_decompressed_size, headers_packed_data, headers_packed_size) != Z_OK) {
        std::cerr << "Error: couldn't decompress headers data." << std::endl;
        ExitProcess(3);
    }

    // Extract and decompress sections
    auto sections_start = base + sections_section->VirtualAddress;
    auto sections_unpacked_size = *reinterpret_cast<const std::size_t*>(sections_start);
    auto sections_packed_data = sections_start + sizeof(std::size_t);
    auto sections_packed_size = sections_section->Misc.VirtualSize - sizeof(std::size_t);

    result.sections.resize(sections_unpacked_size);
    uLong sections_decompressed_size = static_cast<uLong>(sections_unpacked_size);

    if (uncompress(result.sections.data(), &sections_decompressed_size, sections_packed_data, sections_packed_size) != Z_OK) {
        std::cerr << "Error: couldn't decompress sections data." << std::endl;
        ExitProcess(4);
    }

    return result;
}

std::uint8_t* load_image_from_parts(const std::vector<std::uint8_t>& headers, const std::vector<std::uint8_t>& sections_data) {
    // Get the NT headers from the decompressed headers
    auto nt_header = get_nt_headers(headers.data());
    
    // Get section information from the headers
    auto section_table = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        reinterpret_cast<const std::uint8_t*>(&nt_header->OptionalHeader) + nt_header->FileHeader.SizeOfOptionalHeader
    );
    
    // Create a new VirtualAlloc'd buffer with read, write and execute privileges
    auto image_size = nt_header->OptionalHeader.SizeOfImage;
    auto base = reinterpret_cast<std::uint8_t*>(VirtualAlloc(nullptr,
        image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));

    if (base == nullptr) {
        std::cerr << "Error: VirtualAlloc failed: Windows error " << GetLastError() << std::endl;
        ExitProcess(5);
    }

    // Copy the headers to our new virtually allocated image
    std::memcpy(base, headers.data(), nt_header->OptionalHeader.SizeOfHeaders);

    // Compute the offset in sections_data where each section starts based on their PointerToRawData
    // The first section's PointerToRawData is the offset from the start of sections_data
    auto first_section_offset = section_table[0].PointerToRawData;
    
    // Copy our sections to their given addresses in the virtual image
    for (std::uint16_t i = 0; i < nt_header->FileHeader.NumberOfSections; ++i) {
        if (section_table[i].SizeOfRawData > 0) {
            // Calculate where in sections_data this section begins
            auto section_offset = section_table[i].PointerToRawData - first_section_offset;
            
            if (section_offset < sections_data.size()) {
                // Copy the section data to the right virtual address in our allocated memory
                std::memcpy(base + section_table[i].VirtualAddress,
                    sections_data.data() + section_offset,
                    std::min<DWORD>(section_table[i].SizeOfRawData, static_cast<DWORD>(sections_data.size() - section_offset)));
            }
        }
    }

    return base;
}

void load_imports(std::uint8_t* image) {
    // Get the import table directory entry
    auto nt_header = get_nt_headers(image);
    auto directory_entry = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    // If there are no imports, that's fine-- return because there's nothing to do.
    if (directory_entry.VirtualAddress == 0) { return; }

    // Get a pointer to the import descriptor array
    auto import_table = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(image + directory_entry.VirtualAddress);

    // When we reach an OriginalFirstThunk value that is zero, that marks the end of our array.
    while (import_table->OriginalFirstThunk != 0) {
        // Get a string pointer to the DLL to load.
        auto dll_name = reinterpret_cast<char*>(image + import_table->Name);

        // Load the DLL with our import.
        auto dll_import = LoadLibraryA(dll_name);

        if (dll_import == nullptr) {
            std::cerr << "Error: failed to load DLL from import table: " << dll_name << std::endl;
            ExitProcess(6);
        }

        // Load the array which contains our import entries
        auto lookup_table = reinterpret_cast<IMAGE_THUNK_DATA64*>(image + import_table->OriginalFirstThunk);

        // Load the array which will contain our resolved imports
        auto address_table = reinterpret_cast<IMAGE_THUNK_DATA64*>(image + import_table->FirstThunk);

        // Process each import in the lookup table
        while (lookup_table->u1.AddressOfData != 0) {
            FARPROC function = nullptr;
            auto lookup_address = lookup_table->u1.AddressOfData;

            // If the top-most bit is set, this is a function ordinal.
            // Otherwise, it's an import by name.
            if ((lookup_address & IMAGE_ORDINAL_FLAG64) != 0) {
                // Get the function ordinal by masking the lower 32-bits of the lookup address.
                function = GetProcAddress(dll_import,
                    reinterpret_cast<LPSTR>(lookup_address & 0xFFFFFFFF));

                if (function == nullptr) {
                    std::cerr << "Error: failed ordinal lookup for " << dll_name << ": " << (lookup_address & 0xFFFFFFFF) << std::endl;
                    ExitProcess(7);
                }
            }
            else {
                // In an import by name, the lookup address is an offset to
                // an IMAGE_IMPORT_BY_NAME structure, which contains our function name
                // to import
                auto import_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(image + lookup_address);
                function = GetProcAddress(dll_import, import_name->Name);

                if (function == nullptr) {
                    std::cerr << "Error: failed named lookup: " << dll_name << "!" << import_name->Name << std::endl;
                    ExitProcess(8);
                }
            }

            // Store either the ordinal function or named function
            // in our address table.
            address_table->u1.Function = reinterpret_cast<std::uint64_t>(function);

            // Advance to the next entries in the address table and lookup table
            ++lookup_table;
            ++address_table;
        }

        // Advance to the next entry in our import table
        ++import_table;
    }
}

void relocate(std::uint8_t* image) {
    // First, check if we can even relocate the image. If the dynamic base flag isn't set,
    // then this image probably isn't prepared for relocating.
    auto nt_header = get_nt_headers(image);

    if ((nt_header->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0) {
        std::cerr << "Error: image cannot be relocated." << std::endl;
        ExitProcess(9);
    }

    // Once we know we can relocate the image, make sure a relocation directory is present
    auto directory_entry = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (directory_entry.VirtualAddress == 0) {
        std::cerr << "Error: image can be relocated, but contains no relocation directory." << std::endl;
        ExitProcess(10);
    }

    // Calculate the difference between the image base in the compiled image
    // and the current virtually allocated image. This will be added to our
    // relocations later.
    std::uintptr_t delta = reinterpret_cast<std::uintptr_t>(image) - nt_header->OptionalHeader.ImageBase;

    // Get the relocation table.
    auto relocation_table = reinterpret_cast<IMAGE_BASE_RELOCATION*>(image + directory_entry.VirtualAddress);

    // When the virtual address for our relocation header is null,
    // we've reached the end of the relocation table.
    while (relocation_table->VirtualAddress != 0) {
        // Since the SizeOfBlock value also contains the size of the relocation table header,
        // we can calculate the size of the relocation array by subtracting the size of
        // the header from the SizeOfBlock value and dividing it by its base type: a 16-bit integer.
        std::size_t relocations = (relocation_table->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(std::uint16_t);

        // Additionally, the relocation array for this table entry is directly after
        // the relocation header
        auto relocation_data = reinterpret_cast<std::uint16_t*>(&relocation_table[1]);

        for (std::size_t i = 0; i < relocations; ++i) {
            // A relocation is an encoded 16-bit value:
            //   * the upper 4 bits are its relocation type
            //   * the lower 12 bits contain the offset into the relocation entry's address base into the image
            auto relocation = relocation_data[i];
            std::uint16_t type = relocation >> 12;
            std::uint16_t offset = relocation & 0xFFF;
            auto ptr = reinterpret_cast<std::uintptr_t*>(image + relocation_table->VirtualAddress + offset);

            // There are typically only two types of relocations for a 64-bit binary:
            //   * IMAGE_REL_BASED_DIR64: a 64-bit delta calculation
            //   * IMAGE_REL_BASED_ABSOLUTE: a no-op
            if (type == IMAGE_REL_BASED_DIR64)
                *ptr += delta;
        }

        // The next relocation entry is at SizeOfBlock bytes after the current entry
        relocation_table = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            reinterpret_cast<std::uint8_t*>(relocation_table) + relocation_table->SizeOfBlock
        );
    }
}

int main(int argc, char* argv[]) {
    // First, extract and decompress the headers and sections from our packed sections
    auto packed_parts = get_packed_sections();
    
    // Load the image by manually copying headers and placing sections at the right addresses
    auto loaded_image = load_image_from_parts(packed_parts.headers, packed_parts.sections);
    
    // Resolve the imports from the executable
    load_imports(loaded_image);
    
    // Relocate the executable
    relocate(loaded_image);
    
    // Get the headers from our loaded image
    auto nt_headers = get_nt_headers(loaded_image);
    
    // Acquire and call the entrypoint
    auto entrypoint = loaded_image + nt_headers->OptionalHeader.AddressOfEntryPoint;
    reinterpret_cast<void(*)()>(entrypoint)();
    
    return 0;
}