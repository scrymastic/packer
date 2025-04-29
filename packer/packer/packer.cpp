#include <cassert>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <climits>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <windows.h>
#include <compressapi.h>

std::vector<std::uint8_t> read_file(const std::string& filename) {
    std::ifstream fp(filename, std::ios::binary);

    if (!fp.is_open()) {
        std::cerr << "Error: couldn't open file: " << filename << std::endl;
        ExitProcess(2);
    }

    auto vec_data = std::vector<std::uint8_t>();
    vec_data.insert(vec_data.end(),
        std::istreambuf_iterator<char>(fp),
        std::istreambuf_iterator<char>());

    return vec_data;
}

void validate_target(const std::vector<std::uint8_t>& target) {
    auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(target.data());

    // IMAGE_DOS_SIGNATURE is 0x5A4D (for "MZ")
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cerr << "Error: target image has no valid DOS header." << std::endl;
        ExitProcess(3);
    }

    auto nt_header = reinterpret_cast<const IMAGE_NT_HEADERS*>(target.data() + dos_header->e_lfanew);

    // IMAGE_NT_SIGNATURE is 0x4550 (for "PE")
    if (nt_header->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cerr << "Error: target image has no valid NT header." << std::endl;
        ExitProcess(4);
    }

    // IMAGE_NT_OPTIONAL_HDR64_MAGIC is 0x020B
    if (nt_header->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        std::cerr << "Error: only 64-bit executables are supported for this example!" << std::endl;
        ExitProcess(5);
    }
}

template <typename T>
T align(T value, T alignment) {
    auto result = value + ((value % alignment == 0) ? 0 : alignment - (value % alignment));
    return result;
}

std::vector<std::uint8_t> compress_data(const std::uint8_t* data, std::size_t size) {
    COMPRESSOR_HANDLE compressor = nullptr;
    if (!CreateCompressor(COMPRESS_ALGORITHM_MSZIP, nullptr, &compressor)) {
        std::cerr << "Error: couldn't create compressor." << std::endl;
        ExitProcess(8);
    }

    SIZE_T compressed_size = 0;
    if (!Compress(compressor, data, size, nullptr, 0, &compressed_size)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            std::cerr << "Error: couldn't calculate compressed size." << std::endl;
            CloseCompressor(compressor);
            ExitProcess(8);
        }
    }

    std::vector<std::uint8_t> compressed(compressed_size);
    if (!Compress(compressor, data, size, compressed.data(), compressed.size(), &compressed_size)) {
        std::cerr << "Error: compression failed." << std::endl;
        CloseCompressor(compressor);
        ExitProcess(8);
    }

    CloseCompressor(compressor);
    compressed.resize(compressed_size);
    return compressed;
}

int main(int argc, char* argv[]) {
    // if (argc != 2)
    // {
    //     std::cerr << "Error: no file to pack!" << std::endl;
    //     ExitProcess(1);
    // }

    // read the file to pack
    auto target = read_file("C:\\Users\\sonx\\source\\repos\\bf\\x64\\Release\\bf.exe");

    // validate that this is a PE file we can pack
    validate_target(target);

    // Extract PE headers and sections
    auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(target.data());
    auto nt_header = reinterpret_cast<const IMAGE_NT_HEADERS64*>(target.data() + dos_header->e_lfanew);

    // Find the first section header
    auto section_table = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        reinterpret_cast<const std::uint8_t*>(&nt_header->OptionalHeader) + 
        nt_header->FileHeader.SizeOfOptionalHeader
    );
    
    // Find the start of the first section in the file - this is where headers end
    auto first_section_offset = section_table[0].PointerToRawData;
    
    // Split headers (only NT headers) and sections
    // Calculate NT headers size (including section table)
    auto nt_headers_size = sizeof(IMAGE_NT_HEADERS64) + (nt_header->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    std::vector<std::uint8_t> headers(
        target.data() + dos_header->e_lfanew,  // Start from NT headers
        target.data() + dos_header->e_lfanew + nt_headers_size  // Include NT headers and section table
    );
    std::vector<std::uint8_t> sections(target.data() + first_section_offset, target.data() + target.size());
    
    // Compress headers and sections separately
    auto packed_headers = compress_data(headers.data(), headers.size());
    auto packed_sections = compress_data(sections.data(), sections.size());

    // Load the stub executable
    std::vector<std::uint8_t> stub_data = read_file("C:\\Users\\sonx\\projects\\packer\\stub\\x64\\Release\\stub.exe");
    auto stub_dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(stub_data.data());
    auto e_lfanew = stub_dos_header->e_lfanew;

    // Get the alignment information from the stub PE
    auto stub_nt_header = reinterpret_cast<IMAGE_NT_HEADERS64*>(stub_data.data() + e_lfanew);
    auto file_alignment = stub_nt_header->OptionalHeader.FileAlignment;
    auto section_alignment = stub_nt_header->OptionalHeader.SectionAlignment;

    // Align the stub data to file boundary
    if (stub_data.size() % file_alignment != 0)
        stub_data.resize(align<std::size_t>(stub_data.size(), file_alignment));

    // Save the offset for our first new section (.pack0)
    auto headers_raw_offset = static_cast<std::uint32_t>(stub_data.size());

    // Add headers size to the stub data
    auto headers_size = headers.size();
    stub_data.insert(stub_data.end(),
        reinterpret_cast<std::uint8_t*>(&headers_size),
        reinterpret_cast<std::uint8_t*>(&headers_size) + sizeof(std::size_t));

    // Add compressed headers data
    stub_data.insert(stub_data.end(), packed_headers.begin(), packed_headers.end());

    // Calculate the size for the .pack0 section
    auto headers_section_size = static_cast<std::uint32_t>(packed_headers.size() + sizeof(std::size_t));

    // Align the buffer to file boundary for the next section
    if (stub_data.size() % file_alignment != 0)
        stub_data.resize(align<std::size_t>(stub_data.size(), file_alignment));

    // Save the offset for our second new section (.pack1)
    auto sections_raw_offset = static_cast<std::uint32_t>(stub_data.size());

    // Add sections size to the stub data
    auto sections_size = sections.size();
    stub_data.insert(stub_data.end(),
        reinterpret_cast<std::uint8_t*>(&sections_size),
        reinterpret_cast<std::uint8_t*>(&sections_size) + sizeof(std::size_t));

    // Add compressed sections data
    stub_data.insert(stub_data.end(), packed_sections.begin(), packed_sections.end());

    // Calculate the size for the .pack1 section
    auto sections_section_size = static_cast<std::uint32_t>(packed_sections.size() + sizeof(std::size_t));

    // Align the buffer to file boundary
    if (stub_data.size() % file_alignment != 0)
        stub_data.resize(align<std::size_t>(stub_data.size(), file_alignment));

    // Re-acquire the NT header pointer (since our buffer address may have changed)
    stub_nt_header = reinterpret_cast<IMAGE_NT_HEADERS64*>(stub_data.data() + e_lfanew);

    // Add two new sections to the PE file
    auto original_section_count = stub_nt_header->FileHeader.NumberOfSections;
    stub_nt_header->FileHeader.NumberOfSections += 2;  // Adding 2 sections: .pack0 and .pack1

    // Get a pointer to the section table
    auto size_of_header = stub_nt_header->FileHeader.SizeOfOptionalHeader;
    auto stub_section_table = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        reinterpret_cast<std::uint8_t*>(&stub_nt_header->OptionalHeader) + size_of_header
    );

    // Set up the first new section (.pack0) for headers
    auto section0_index = original_section_count;
    auto prev_section = &stub_section_table[section0_index - 1];
    auto section0 = &stub_section_table[section0_index];

    auto virtual_offset0 = align(prev_section->VirtualAddress + prev_section->Misc.VirtualSize, section_alignment);
    auto virtual_size0 = headers_section_size;
    auto raw_size0 = align<DWORD>(headers_section_size, file_alignment);

    std::memcpy(section0->Name, ".pack0", 7);
    section0->Name[7] = 0;
    section0->Misc.VirtualSize = virtual_size0;
    section0->VirtualAddress = virtual_offset0;
    section0->SizeOfRawData = raw_size0;
    section0->PointerToRawData = headers_raw_offset;
    section0->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;

    // Set up the second new section (.pack1) for sections
    auto section1_index = original_section_count + 1;
    auto section1 = &stub_section_table[section1_index];

    auto virtual_offset1 = align(section0->VirtualAddress + section0->Misc.VirtualSize, section_alignment);
    auto virtual_size1 = sections_section_size;
    auto raw_size1 = align<DWORD>(sections_section_size, file_alignment);

    std::memcpy(section1->Name, ".pack1", 7);
    section1->Name[7] = 0;
    section1->Misc.VirtualSize = virtual_size1;
    section1->VirtualAddress = virtual_offset1;
    section1->SizeOfRawData = raw_size1;
    section1->PointerToRawData = sections_raw_offset;
    section1->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;

    // Update the size of the image in the PE header
    stub_nt_header->OptionalHeader.SizeOfImage = align(virtual_offset1 + virtual_size1, section_alignment);

    // Write the packed executable
    std::ofstream fp("C:\\Users\\sonx\\source\\repos\\bf\\x64\\Release\\packed.exe", std::ios::binary);

    if (!fp.is_open()) {
        std::cerr << "Error: couldn't open packed binary for writing." << std::endl;
        ExitProcess(9);
    }

    fp.write(reinterpret_cast<const char*>(stub_data.data()), stub_data.size());
    fp.close();

    std::cout << "File successfully packed with separated headers and sections." << std::endl;
    std::cout << "Original size: " << target.size() << " bytes" << std::endl;
    std::cout << "Headers size: " << headers.size() << " bytes (compressed: " << packed_headers.size() << " bytes)" << std::endl;
    std::cout << "Sections size: " << sections.size() << " bytes (compressed: " << packed_sections.size() << " bytes)" << std::endl;
    std::cout << "Total compressed size: " << (packed_headers.size() + packed_sections.size()) << " bytes" << std::endl;

    return 0;
}