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
