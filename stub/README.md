# PE Loader Stub: Advanced Section-Only Loader

This stub demonstrates an advanced technique for loading a packed Portable Executable (PE) file in memory, making reverse engineering and memory dumping significantly more difficult. Instead of mapping the entire PE (headers + sections), this stub only loads the **sections** into memory, using the **headers** solely as a guide for mapping, relocations, and import resolution. The headers are never present in the loaded memory region, so the in-memory image is not a valid PE and cannot be dumped as one.

## Why Use a Section-Only Loader?

Traditional packers and loaders decompress the entire PE (headers and sections) into memory, making it possible for reverse engineering tools to dump the process and reconstruct the original executable. By separating headers and sections, and only mapping the sections, you:

- Prevent standard PE dumpers from reconstructing a valid PE file from memory.
- Make static and dynamic analysis much harder, as the in-memory image is not a valid PE.
- Obfuscate the original structure of the executable, increasing the difficulty for reverse engineers.

## How It Works

1. **Packing Phase (see `packer.cpp`):**
    - The original PE file is split into two parts:
        - **Headers**: Everything up to the first section's raw data.
        - **Sections**: All section data, concatenated.
    - Both parts are compressed separately and stored in two new sections in the stub executable:
        - `.pack0`: Compressed headers
        - `.pack1`: Compressed sections

2. **Stub Loader Phase (this project):**
    - At runtime, the stub:
        1. **Decompresses the headers** from `.pack0` into a temporary buffer.
        2. **Decompresses the sections** from `.pack1` into another buffer.
        3. **Allocates memory** only for the sections, not the headers.
        4. **Maps each section** to its correct virtual address (relative to the allocated base), using the headers as a guide.
        5. **Performs relocations and import resolution** using the headers, but all fixups are applied to the mapped sections only.
        6. **Calls the entrypoint** of the loaded code.
    - After mapping, the headers and sections buffers are released. The loaded memory region contains only the mapped sections, not the headers.

## Security Benefits

- **No valid PE in memory:** The process memory does not contain a valid PE image, thwarting most memory dumpers and analysis tools.
- **Headers are never mapped:** Only the sections are mapped and executed; headers are used only as a guide and then discarded.
- **Harder to reconstruct:** Even if a memory dump is obtained, it is extremely difficult to reconstruct the original executable without the headers.

## How to Build and Use

1. **Build the stub project** (this directory) as a 64-bit Windows executable.
2. **Use the packer** to pack your target PE file, producing a new stub executable with `.pack0` and `.pack1` sections containing the compressed headers and sections.
3. **Run the packed stub**. It will decompress, map, and execute the original code in memory, without ever reconstructing a valid PE image in the process memory.

## Example Code Flow (Stub)

```cpp
// 1. Decompress headers and sections from .pack0 and .pack1
std::vector<uint8_t> headers = decompress_section(...);
std::vector<uint8_t> sections = decompress_section(...);

// 2. Allocate memory for sections only
uint8_t* mapped_base = load_sections_only(headers, sections);

// 3. Use headers as a guide for fixups
load_imports_sections(mapped_base, headers);
relocate_sections(mapped_base, headers);

// 4. Call entrypoint
const IMAGE_NT_HEADERS64* nt_headers = get_nt_headers(headers.data());
auto entrypoint = mapped_base + nt_headers->OptionalHeader.AddressOfEntryPoint;
reinterpret_cast<void(*)()>(entrypoint)();
```

## Notes
- This technique is for educational and research purposes. Use responsibly.
- You may need to adapt the stub for different PE layouts or additional anti-analysis features.

## Developer Tutorial

### Understanding the Core Concepts

1. **PE File Structure**
   - A PE file consists of headers (DOS header, PE header, section table) and sections
   - Headers contain metadata about how to load and execute the file
   - Sections contain the actual code and data

2. **Memory Protection**
   - Windows uses memory protection flags (READ, WRITE, EXECUTE)
   - Different sections need different protection flags
   - Code sections typically need EXECUTE+READ
   - Data sections typically need READ+WRITE

### Step-by-Step Development Guide

1. **Setting Up the Project**
   ```cpp
   // Required headers
   #include <windows.h>
   #include <cstdint>
   #include <vector>
   #include <zlib.h>  // For compression
   ```

2. **Header Processing Functions**
   ```cpp
   // Get NT headers from memory
   const IMAGE_NT_HEADERS64* get_nt_headers(const std::uint8_t* image) {
       auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
       return reinterpret_cast<const IMAGE_NT_HEADERS64*>(
           image + dos_header->e_lfanew
       );
   }

   // Convert section characteristics to memory protection
   DWORD get_protection_flags(DWORD characteristics) {
       bool executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
       bool readable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
       bool writeable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
       
       // Map combinations to Windows protection constants
       if (executable) {
           return writeable ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
       }
       return writeable ? PAGE_READWRITE : PAGE_READONLY;
   }
   ```

3. **Section Loading**
   ```cpp
   std::uint8_t* load_sections_only(
       const std::vector<std::uint8_t>& headers,
       const std::vector<std::uint8_t>& sections_data
   ) {
       // 1. Extract section information from headers
       const auto* nt_header = get_nt_headers(headers.data());
       const auto* section_table = /* get section table */;
       
       // 2. Calculate memory requirements
       uintptr_t min_va = /* find minimum VA */;
       uintptr_t max_va = /* find maximum VA */;
       size_t total_size = max_va - min_va;
       
       // 3. Allocate memory (initially RW for loading)
       std::uint8_t* base = VirtualAlloc(nullptr, total_size,
           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
           
       // 4. Copy sections to their correct locations
       for (int i = 0; i < num_sections; ++i) {
           /* copy section data to (base + VA - min_va) */
       }
       
       return base - min_va;  // Return adjusted base
   }
   ```

4. **Import Resolution**
   ```cpp
   void load_imports_sections(std::uint8_t* base, const std::vector<std::uint8_t>& headers) {
       // 1. Find import directory
       const auto* nt_header = get_nt_headers(headers.data());
       auto directory = nt_header->OptionalHeader.DataDirectory[
           IMAGE_DIRECTORY_ENTRY_IMPORT
       ];
       
       // 2. Process each imported DLL
       auto* import_table = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
           base + directory.VirtualAddress
       );
       while (import_table->Name) {
           // 3. Load DLL and resolve functions
           const char* dll_name = reinterpret_cast<char*>(
               base + import_table->Name
           );
           HMODULE dll = LoadLibraryA(dll_name);
           
           // 4. Fill IAT with resolved addresses
           /* Process lookup table and fill addresses */
           
           ++import_table;
       }
   }
   ```

5. **Base Relocation**
   ```cpp
   void relocate_sections(std::uint8_t* base, const std::vector<std::uint8_t>& headers) {
       // 1. Calculate delta from preferred base
       const auto* nt_header = get_nt_headers(headers.data());
       std::uintptr_t delta = reinterpret_cast<std::uintptr_t>(base) -
           nt_header->OptionalHeader.ImageBase;
           
       // 2. Process each relocation block
       auto* reloc = /* get relocation directory */;
       while (reloc->VirtualAddress) {
           // 3. Apply each relocation entry
           auto* entries = reinterpret_cast<std::uint16_t*>(reloc + 1);
           for (/* each entry */) {
               if (type == IMAGE_REL_BASED_DIR64) {
                   *target += delta;
               }
           }
           reloc = /* next block */;
       }
   }
   ```

6. **Final Memory Protection**
   ```cpp
   void apply_memory_permissions(
       std::uint8_t* mapped_base,
       const std::vector<std::uint8_t>& headers
   ) {
       // Set final protection for each section
       for (int i = 0; i < num_sections; ++i) {
           DWORD protection = get_protection_flags(
               section_table[i].Characteristics
           );
           VirtualProtect(
               section_base,
               section_size,
               protection,
               &old_protect
           );
       }
   }
   ```

### Key Development Tips

1. **Memory Management**
   - Always initialize allocated memory to prevent information leaks
   - Use exception handling for memory allocation failures
   - Clean up resources in case of errors

2. **Security Considerations**
   - Clear sensitive data (like import names) after use
   - Validate all header values before use
   - Check for buffer overflows in section copying

3. **Debugging Tips**
   - Use `VirtualQuery` to verify memory permissions
   - Check `GetLastError()` after Windows API calls
   - Log section addresses and sizes during development

4. **Common Pitfalls**
   - Not handling section alignment correctly
   - Forgetting to apply relocations
   - Incorrect memory protection flags
   - Not validating PE headers properly

5. **Testing**
   - Test with different types of executables
   - Verify protection flags after loading
   - Check import resolution with various DLLs
   - Validate relocation handling

### Advanced Topics

1. **Anti-Debug Features**
   - Add integrity checks
   - Implement timing checks
   - Add debugger detection

2. **Optimization**
   - Minimize memory copies
   - Optimize section alignment
   - Reduce memory footprint

3. **Additional Security**
   - Implement section encryption
   - Add runtime integrity checks
   - Implement anti-dump measures

Remember to always use this knowledge responsibly and in compliance with applicable laws and regulations.
