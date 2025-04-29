#include <cstring>
#include <cstddef>
#include <cstdint>
#include <climits>
#include <iostream>
#include <fstream>
#include <vector>
#include <limits>
#include <windows.h>
#include <compressapi.h>

// System constants
constexpr size_t PAGE_SIZE = 0x1000;  // Standard x64 page size

const IMAGE_NT_HEADERS64* get_nt_headers(const std::uint8_t* image) {
    // Since we only stored NT headers, the image pointer points directly to them
    return reinterpret_cast<const IMAGE_NT_HEADERS64*>(image);
}

// Helper function to convert section characteristics to memory protection flags
DWORD get_protection_flags(DWORD characteristics) {
    DWORD protection = 0;
    bool executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    bool readable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    bool writeable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    
    if (executable) {
        if (writeable) {
            protection = PAGE_EXECUTE_READWRITE;
        } else {
            protection = readable ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
        }
    } else {
        if (writeable) {
            protection = readable ? PAGE_READWRITE : PAGE_WRITECOPY;
        } else {
            protection = readable ? PAGE_READONLY : PAGE_NOACCESS;
        }
    }
    
    if (characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
        protection |= PAGE_NOCACHE;
    }
    
    return protection;
}

// Helper: decompress a packed section
std::vector<std::uint8_t> decompress_section(const std::uint8_t* section_start, DWORD section_size) {
    auto unpacked_size = *reinterpret_cast<const std::size_t*>(section_start);
    auto packed_data = section_start + sizeof(std::size_t);
    auto packed_size = section_size - sizeof(std::size_t);
    std::vector<std::uint8_t> out(unpacked_size);

    DECOMPRESSOR_HANDLE decompressor = nullptr;
    if (!CreateDecompressor(COMPRESS_ALGORITHM_MSZIP, nullptr, &decompressor)) {
        std::cerr << "Error: couldn't create decompressor." << std::endl;
        ExitProcess(100);
    }

    SIZE_T decompressed_size = 0;
    if (!Decompress(decompressor, packed_data, packed_size, out.data(), out.size(), &decompressed_size)) {
        std::cerr << "Error: couldn't decompress section data." << std::endl;
        CloseDecompressor(decompressor);
        ExitProcess(100);
    }

    CloseDecompressor(decompressor);
    return out;
}

// Helper: find section bounds
void find_section_bounds(const IMAGE_SECTION_HEADER* section_table, int num_sections, uintptr_t& min_va, uintptr_t& max_va, DWORD& max_raw_size) {
    min_va = (uintptr_t)-1;
    max_va = 0;
    max_raw_size = 0;
    for (int i = 0; i < num_sections; ++i) {
        // Fix for Warning C26451: Cast to wider type before arithmetic
        uintptr_t current_va = static_cast<uintptr_t>(section_table[i].VirtualAddress);
        uintptr_t virtual_size = static_cast<uintptr_t>(section_table[i].Misc.VirtualSize);
        
        if (current_va < min_va) min_va = current_va;
        if (current_va + virtual_size > max_va) max_va = current_va + virtual_size;
        if (section_table[i].SizeOfRawData > max_raw_size) max_raw_size = section_table[i].SizeOfRawData;
    }
}

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

    // Initially allocate with PAGE_READWRITE for loading and fixups
    std::uint8_t* base = reinterpret_cast<std::uint8_t*>(VirtualAlloc(nullptr, total_size, 
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
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
                auto dest = base + (section_table[i].VirtualAddress - min_va);
                std::memcpy(dest,
                    sections_data.data() + section_offset,
                    std::min<DWORD>(section_table[i].SizeOfRawData, 
                        static_cast<DWORD>(sections_data.size() - section_offset)));
            }
        }
    }

    return base - min_va; // So that VirtualAddress in headers can be used as (base + VA)
}

// Apply final memory permissions after all fixups
void apply_memory_permissions(std::uint8_t* mapped_base, const std::vector<std::uint8_t>& headers) {
    const IMAGE_NT_HEADERS64* nt_header = get_nt_headers(headers.data());
    const IMAGE_SECTION_HEADER* section_table = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        reinterpret_cast<const std::uint8_t*>(&nt_header->OptionalHeader) + nt_header->FileHeader.SizeOfOptionalHeader
    );
    int num_sections = nt_header->FileHeader.NumberOfSections;

    // Find min VA for offset calculation
    uintptr_t min_va = (uintptr_t)-1;
    for (int i = 0; i < num_sections; ++i) {
        if (section_table[i].VirtualAddress < min_va) min_va = section_table[i].VirtualAddress;
    }

    // Apply protections
    DWORD old_protect;
    for (int i = 0; i < num_sections; ++i) {
        if (section_table[i].Misc.VirtualSize > 0) {
            auto section_base = mapped_base + section_table[i].VirtualAddress;
            auto section_size = section_table[i].Misc.VirtualSize;
            DWORD protection = get_protection_flags(section_table[i].Characteristics);
            
            if (!VirtualProtect(section_base, section_size, protection, &old_protect)) {
                std::cerr << "Error: Failed to set section protection: Windows error " << GetLastError() << std::endl;
                ExitProcess(6);
            }
        }
    }
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
                // Clear the function name from the import name table
                std::memset(import_name->Name, 0, strlen(reinterpret_cast<const char*>(import_name->Name)));
            }
            // Store resolved function address
            address_table->u1.Function = reinterpret_cast<std::uint64_t>(function);
            // Clear the lookup table entry
            lookup_table->u1.AddressOfData = 0;
            ++lookup_table;
            ++address_table;
        }
        // Clear DLL name after resolving all its imports
        std::memset(dll_name, 0, strlen(dll_name));
        ++import_table;
    }
    // Optional: Clear the entire import directory after resolving all imports
    std::memset(reinterpret_cast<void*>(base + directory_entry.VirtualAddress), 0, directory_entry.Size);
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
    
    // Process relocations
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

    // Wipe relocation directory after processing
    DWORD old_protect;
    auto reloc_addr = base + directory_entry.VirtualAddress;
    if (VirtualProtect(reloc_addr, directory_entry.Size, PAGE_READWRITE, &old_protect)) {
        // Zero out the entire relocation directory
        std::memset(reloc_addr, 0, directory_entry.Size);
        
        // Restore original protection
        VirtualProtect(reloc_addr, directory_entry.Size, old_protect, &old_protect);
    }
}

// Function pointer types for indirect calls
using fn_decompress_t = std::vector<std::uint8_t>(*)(const std::uint8_t*, DWORD);
using fn_load_sections_t = std::uint8_t*(*)(const std::vector<std::uint8_t>&, const std::vector<std::uint8_t>&);
using fn_imports_t = void(*)(std::uint8_t*, const std::vector<std::uint8_t>&);
using fn_relocate_t = void(*)(std::uint8_t*, const std::vector<std::uint8_t>&);
using fn_permissions_t = void(*)(std::uint8_t*, const std::vector<std::uint8_t>&);

// Indirect function table
struct unpacking_vtable {
    fn_decompress_t decompress;
    fn_load_sections_t load_sections;
    fn_imports_t imports;
    fn_relocate_t relocate;
    fn_permissions_t permissions;
};

// Initialize function table with encrypted pointers (simple XOR for demonstration)
unpacking_vtable init_vtable() {
    const std::uint64_t key = 0x1234567890ABCDEF;
    unpacking_vtable table;
    auto encrypt = [key](void* ptr) -> std::uint64_t {
        return reinterpret_cast<std::uint64_t>(ptr) ^ key;
    };
    
    table.decompress = reinterpret_cast<fn_decompress_t>(encrypt(decompress_section));
    table.load_sections = reinterpret_cast<fn_load_sections_t>(encrypt(load_sections_only));
    table.imports = reinterpret_cast<fn_imports_t>(encrypt(load_imports_sections));
    table.relocate = reinterpret_cast<fn_relocate_t>(encrypt(relocate_sections));
    table.permissions = reinterpret_cast<fn_permissions_t>(encrypt(apply_memory_permissions));
    return table;
}

// Decrypt function pointer before use
template<typename T>
T decrypt_fn(std::uint64_t encrypted) {
    const std::uint64_t key = 0x1234567890ABCDEF;
    return reinterpret_cast<T>(encrypted ^ key);
}

// Split unpacking stages into smaller functions
struct unpacking_context {
    const std::uint8_t* base;
    const IMAGE_SECTION_HEADER* headers_section;
    const IMAGE_SECTION_HEADER* sections_section;
    std::vector<std::uint8_t> headers;
    std::uint8_t* mapped_base;
};

bool find_packed_sections(unpacking_context& ctx) {
    auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(ctx.base);
    auto nt_header = reinterpret_cast<const IMAGE_NT_HEADERS64*>(ctx.base + dos_header->e_lfanew);
    auto section_table = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        reinterpret_cast<const std::uint8_t*>(&nt_header->OptionalHeader) + nt_header->FileHeader.SizeOfOptionalHeader
    );
    
    for (std::uint16_t i = 0; i < nt_header->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(section_table[i].Name, ".pack0", 7) == 0) ctx.headers_section = &section_table[i];
        else if (std::memcmp(section_table[i].Name, ".pack1", 7) == 0) ctx.sections_section = &section_table[i];
        if (ctx.headers_section && ctx.sections_section) return true;
    }
    return false;
}

bool stage1_decompress(unpacking_context& ctx, const unpacking_vtable& vtable) {
    auto decompress_fn = decrypt_fn<fn_decompress_t>(reinterpret_cast<std::uint64_t>(vtable.decompress));
    ctx.headers = decompress_fn(ctx.base + ctx.headers_section->VirtualAddress, ctx.headers_section->Misc.VirtualSize);
    return !ctx.headers.empty();
}

bool stage2_map_sections(unpacking_context& ctx, const unpacking_vtable& vtable) {
    auto load_fn = decrypt_fn<fn_load_sections_t>(reinterpret_cast<std::uint64_t>(vtable.load_sections));
    auto sections = decrypt_fn<fn_decompress_t>(reinterpret_cast<std::uint64_t>(vtable.decompress))(
        ctx.base + ctx.sections_section->VirtualAddress, 
        ctx.sections_section->Misc.VirtualSize
    );
    ctx.mapped_base = load_fn(ctx.headers, sections);
    return ctx.mapped_base != nullptr;
}

bool stage3_process_imports(unpacking_context& ctx, const unpacking_vtable& vtable) {
    auto imports_fn = decrypt_fn<fn_imports_t>(reinterpret_cast<std::uint64_t>(vtable.imports));
    imports_fn(ctx.mapped_base, ctx.headers);
    return true;
}

bool stage4_relocate(unpacking_context& ctx, const unpacking_vtable& vtable) {
    auto relocate_fn = decrypt_fn<fn_relocate_t>(reinterpret_cast<std::uint64_t>(vtable.relocate));
    relocate_fn(ctx.mapped_base, ctx.headers);
    return true;
}

bool stage5_finalize(unpacking_context& ctx, const unpacking_vtable& vtable) {
    auto permissions_fn = decrypt_fn<fn_permissions_t>(reinterpret_cast<std::uint64_t>(vtable.permissions));
    permissions_fn(ctx.mapped_base, ctx.headers);
    return true;
}

void* get_entry_point(const unpacking_context& ctx) {
    const IMAGE_NT_HEADERS64* orig_nt_headers = get_nt_headers(ctx.headers.data());
    return reinterpret_cast<void*>(ctx.mapped_base + orig_nt_headers->OptionalHeader.AddressOfEntryPoint);
}

using entry_point_t = void(*)();

void* prepare_entry_point(void* entry) {
    // Basic address obfuscation
    auto addr = reinterpret_cast<std::uint64_t>(entry);
    addr ^= 0x1234567890ABCDEF;  // XOR with constant
    addr += 0x42424242;          // Add constant
    addr ^= 0x42424242;          // XOR again
    addr -= 0x42424242;          // Subtract the same constant
    addr ^= 0x1234567890ABCDEF;  // Reverse first XOR
    return reinterpret_cast<void*>(addr);
}

void execute_entry(void* obfuscated_entry) {
    // Deobfuscate and execute
    auto addr = reinterpret_cast<std::uint64_t>(obfuscated_entry);
    addr ^= 0x1234567890ABCDEF;
    addr += 0x42424242;
    addr ^= 0x42424242;
    addr -= 0x42424242;
    addr ^= 0x1234567890ABCDEF;
    
    auto fn = reinterpret_cast<entry_point_t>(addr);
    fn();
}

int main(int argc, char* argv[]) {
    // Initialize context and function table
    unpacking_context ctx;
    ctx.base = reinterpret_cast<const std::uint8_t*>(GetModuleHandleA(NULL));
    ctx.headers_section = nullptr;
    ctx.sections_section = nullptr;
    ctx.mapped_base = nullptr;
    
    auto vtable = init_vtable();
    
    // State machine for unpacking stages
    enum class stage_t : int { 
        FIND_SECTIONS = 0, DECOMPRESS, MAP_SECTIONS, 
        PROCESS_IMPORTS, RELOCATE, FINALIZE, EXECUTE, 
        STAGE_ERROR 
    };
    
    // Obfuscated control flow using switch-case state machine
    stage_t current_stage = stage_t::FIND_SECTIONS;
    bool success = true;
    
    while (current_stage != stage_t::STAGE_ERROR && current_stage != stage_t::EXECUTE) {
        switch (current_stage) {
            case stage_t::FIND_SECTIONS:
            {
                success = find_packed_sections(ctx);
                current_stage = success ? stage_t::DECOMPRESS : stage_t::STAGE_ERROR;
                break;
            }
            case stage_t::DECOMPRESS:
            {
                success = stage1_decompress(ctx, vtable);
                current_stage = success ? stage_t::MAP_SECTIONS : stage_t::STAGE_ERROR;
                break;
            }
            case stage_t::MAP_SECTIONS:
            {
                success = stage2_map_sections(ctx, vtable);
                current_stage = success ? stage_t::PROCESS_IMPORTS : stage_t::STAGE_ERROR;
                break;
            }
            case stage_t::PROCESS_IMPORTS:
            {
                success = stage3_process_imports(ctx, vtable);
                current_stage = success ? stage_t::RELOCATE : stage_t::STAGE_ERROR;
                break;
            }
            case stage_t::RELOCATE:
            {
                success = stage4_relocate(ctx, vtable);
                current_stage = success ? stage_t::FINALIZE : stage_t::STAGE_ERROR;
                break;
            }
            case stage_t::FINALIZE:
            {
                success = stage5_finalize(ctx, vtable);
                current_stage = success ? stage_t::EXECUTE : stage_t::STAGE_ERROR;
                break;
            }
            default:
            {
                current_stage = stage_t::STAGE_ERROR;
                break;
            }
        }
    }
    
    if (current_stage == stage_t::STAGE_ERROR) {
        ExitProcess(101);
    }
    
    // Execute unpacked binary with basic OEP obfuscation
    auto entry = get_entry_point(ctx);
    auto obfuscated = prepare_entry_point(entry);
    execute_entry(obfuscated);
    
    return 0;
}