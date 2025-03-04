#include "extract_vtable.hpp"


std::unordered_map<std::string, LibraryInfo> lib_info;  // lib_name -> path and base_addr
std::unordered_map<std::string, Symbol_info> symbol_map;  // symbol name -> lib_name 、offset 和 size

// std::vector<Symbol> symbols;  // symbols of the elf file

std::unordered_map<uint64_t, Symbol> reloc_map;  // relocation offset -> symbol name

std::string extractFileName(const std::string& path) {
    size_t pos = path.find_last_of("/\\");
    return (pos != std::string::npos) ? path.substr(pos + 1) : path;
}

void parse_proc_maps(std::string pid) {
    printf("opening /proc/%s/maps ..... \n",pid.c_str());
    std::ifstream maps("/proc/" + pid + "/maps");
    if (!maps.is_open()) {
        printf("Failed to open /proc/%s/maps \n", pid.c_str());
    }

    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(".so") != std::string::npos) {
            printf("parse line: %s \n",line.c_str());
            std::istringstream iss(line);
            uint64_t start, end;
            char dash;  // read '-' 
            char perms[5];
            std::string path;

            if (!(iss >> std::hex >> start)) {
                printf("Failed to parse start address: %s \n",line.c_str());
                continue;
            }
            if (!(iss >> dash) || dash != '-') {
                printf("Failed to parse dash separator:  %s \n",line.c_str());
                continue;
            }
            if (!(iss >> std::hex >> end)) {
                printf("Failed to parse end address: %s \n",line.c_str());
                continue;
            }
            if (!(iss >> perms)) {
                printf("Failed to parse permissions: %s \n",line.c_str());
                continue;
            }

            std::string rest;
            std::getline(iss >> std::ws, rest);
            path = rest.substr(rest.find_last_of(' ') + 1);
            std::string name = extractFileName(path);

            if (lib_info.find(name) == lib_info.end()) {
                lib_info[name] = {path, start};
                printf("add lib %s , address 0x%lx \n", name.c_str(), start);
            }
        }
    }
}

// 该函数遍历所有已知的动态库，并解析其动态符号表（SHT_DYNSYM）中 以 "_Z" 开头的符号 的符号。
// 对每个符号，提取其名称、地址、大小，并将其存入一个全局符号表（symbol_map）中。
void get_symbols_from_libs() {
    elf_version(EV_CURRENT);

    for (auto [lib_name, lib] : lib_info) {
        std::string lib_path = lib.path;
        uint64_t base_address = lib.base_address;

        int fd = open(lib_path.c_str(), O_RDONLY);
        if (fd == -1) {
            perror(("cannot open lib: " + lib_path).c_str());
            continue;
        }

        Elf *elf = elf_begin(fd, ELF_C_READ, nullptr);
        if (!elf) {
            fprintf(stderr, "ELF open failed: %s\n", elf_errmsg(elf_errno()));
            close(fd);
            continue;
        }
        Elf_Scn* scn = nullptr;
        while ((scn = elf_nextscn(elf, scn)) != nullptr) {
            GElf_Shdr shdr;
            if (gelf_getshdr(scn, &shdr) != &shdr) {
                fprintf(stderr, "get section header failed: %s\n", elf_errmsg(elf_errno()));
                continue;
            }

            if (shdr.sh_type != SHT_DYNSYM) continue;

            Elf_Data* data = elf_getdata(scn, nullptr);
            if (!data) {
                fprintf(stderr, "无法读取符号表数据\n");
                continue;
            }

            size_t num_syms = shdr.sh_size / shdr.sh_entsize;
            std::vector<GElf_Sym> symbolsOfLib(num_syms);

            // 预加载所有符号以进行地址比较
            for (size_t i = 0; i < num_syms; ++i) {
                if (gelf_getsym(data, i, &symbolsOfLib[i]) != &symbolsOfLib[i]) {
                    fprintf(stderr, "读取符号失败: %s\n", elf_errmsg(elf_errno()));
                    continue;
                }
            }

            // 实际处理符号
            for (size_t i = 0; i < num_syms; ++i) {
                const GElf_Sym& sym = symbolsOfLib[i];
                
                // 跳过未定义符号和空名称
                const char* full_name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                if (!full_name || sym.st_shndx == SHN_UNDEF) continue;

                // 剥离版本号（处理 @@ 分隔符）
                const char* version_sep = strchr(full_name, '@');
                std::string name(version_sep ? 
                                std::string(full_name, version_sep - full_name) : 
                                full_name);

                // 跳过非 _Z 开头的符号
                if (name.find("_Z") != 0) continue;
                // 处理符号大小
                size_t size = sym.st_size;
                if (size == 0 && i + 1 < num_syms) {
                    // 通过下一个符号的地址差推断大小
                    const GElf_Sym& next_sym = symbolsOfLib[i+1];
                    if (next_sym.st_value > sym.st_value) {
                        size = next_sym.st_value - sym.st_value;
                    }
                }
                // 存入符号表
                symbol_map[name] = {lib_name, sym.st_value, size};
                printf("lib: %s, symbol: %s, address: 0x%lx, size: 0x%lx\n", lib_name.c_str(), name.c_str(), sym.st_value, size);
            }
        }
        elf_end(elf);
        close(fd);
    }
}

bool is_dynsym_section(Elf_Scn *scn, GElf_Shdr &shdr) {
    return (shdr.sh_type == SHT_DYNSYM);
}

bool is_rela_dyn_section(Elf *elf, size_t shstrndx, Elf_Scn *scn, GElf_Shdr &shdr) {
    return (shdr.sh_type == SHT_RELA && 
            strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".rela.dyn") == 0);
}

// 从指定的 ELF 文件中提取动态符号信息（.dynsym）和重定位信息（.rela.dyn）。
// 它解析这些段以获取与动态链接相关的符号信息，特别是未定义的全局符号。
int extract_symbols(std::string file_path) {
    elf_version(EV_CURRENT);
    int fd = open(file_path.c_str(), O_RDONLY);
    Elf *elf = elf_begin(fd, ELF_C_READ, nullptr);

    size_t shstrndx;
    elf_getshdrstrndx(elf, &shstrndx);

    Elf_Scn *scn = nullptr;
    Elf_Scn *dynsym_scn = nullptr;
    Elf_Scn *rela_dyn_scn = nullptr;

    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        GElf_Shdr shdr;
        gelf_getshdr(scn, &shdr);

        if (is_dynsym_section(scn, shdr)) {
            dynsym_scn = scn;
        } else if (is_rela_dyn_section(elf, shstrndx, scn, shdr)) {
            rela_dyn_scn = scn;
        }
    }

    if (!dynsym_scn || !rela_dyn_scn) {
        std::cerr << "Failed to find .dynsym or .rela.dyn sections!" << std::endl;
        return 1;
    }

    GElf_Shdr dynsym_shdr;
    gelf_getshdr(dynsym_scn, &dynsym_shdr);
    Elf_Data *dynsym_data = elf_getdata(dynsym_scn, nullptr);
    size_t num_symbols = dynsym_shdr.sh_size / dynsym_shdr.sh_entsize;

    std::vector<GElf_Sym> dynsyms;
    for (size_t i = 0; i < num_symbols; i++) {
        GElf_Sym sym;
        gelf_getsym(dynsym_data, i, &sym);
        dynsyms.push_back(sym);
    }

    GElf_Shdr rela_dyn_shdr;
    gelf_getshdr(rela_dyn_scn, &rela_dyn_shdr);
    Elf_Data *rela_data = elf_getdata(rela_dyn_scn, nullptr);
    size_t num_rela = rela_dyn_shdr.sh_size / rela_dyn_shdr.sh_entsize;

    std::cout << "Required external symbols:\n";
    for (size_t i = 0; i < num_rela; i++) {
        GElf_Rela rela;
        gelf_getrela(rela_data, i, &rela);

        uint32_t sym_idx = GELF_R_SYM(rela.r_info);

        if (sym_idx >= dynsyms.size()) {
            std::cerr << "Invalid symbol index: " << sym_idx << std::endl;
            continue;
        }

        GElf_Sym &sym = dynsyms[sym_idx];
        const char *sym_name = elf_strptr(elf, dynsym_shdr.sh_link, sym.st_name);
        if (sym_name == nullptr) continue;
        if (sym.st_shndx == SHN_UNDEF && 
            GELF_ST_BIND(sym.st_info) == STB_GLOBAL) {
            std::cout << "  - Symbol: " << sym_name 
                      << ", Offset: 0x" << std::hex << rela.r_offset 
                      << ", Type: " << GELF_R_TYPE(rela.r_info)
                      << ", Addend: " << rela.r_addend
                      << ", Size: " << sym.st_size << std::endl;
            // symbols.push_back({sym_name, rela.r_offset, GELF_R_TYPE(rela.r_info), rela.r_addend});
            reloc_map[rela.r_offset] = {sym_name, rela.r_offset, GELF_R_TYPE(rela.r_info), rela.r_addend};
        }
    }

    elf_end(elf);
    close(fd);
    return 0;
}

uint64_t read_bytes_at_address(const std::string &file_path, uint64_t target_address, size_t num_bytes) {
    // 打开 ELF 文件
    int fd = open(file_path.c_str(), O_RDONLY);
    if (fd == -1) {
        std::cerr << "Cannot open ELF file: " << file_path << std::endl;
        return 0;
    }

    // 初始化 libelf
    elf_version(EV_CURRENT);
    Elf *elf = elf_begin(fd, ELF_C_READ, nullptr);
    if (!elf) {
        std::cerr << "ELF open failed: " << elf_errmsg(elf_errno()) << std::endl;
        close(fd);
        return 0;
    }

    uint64_t result = 0;
    // 遍历 ELF 文件中的段（Section）
    Elf_Scn *scn = nullptr;
    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) != &shdr) {
            std::cerr << "Error getting section header: " << elf_errmsg(elf_errno()) << std::endl;
            continue;
        }

        // 只处理包含数据的段（如 .text, .data 等）
        if (shdr.sh_type != SHT_PROGBITS && shdr.sh_type != SHT_NOBITS) {
            continue;
        }

        // 获取段数据
        Elf_Data *data = elf_getdata(scn, nullptr);
        if (!data) {
            std::cerr << "Error getting section data: " << elf_errmsg(elf_errno()) << std::endl;
            continue;
        }

        // 检查目标地址是否在该段内
        uint64_t section_start = shdr.sh_addr;
        uint64_t section_end = section_start + shdr.sh_size;

        if (target_address >= section_start && target_address < section_end) {
            // 计算目标地址在该段中的偏移
            size_t offset_in_section = target_address - section_start;

            // 确保目标地址及后续字节不会越界
            if (offset_in_section + num_bytes <= shdr.sh_size) {
                // 读取指定数量的字节
                uint8_t *section_data = (uint8_t *)data->d_buf;
                uint8_t *data_start = section_data + offset_in_section;

                std::cout << "Content at address 0x" << std::hex << target_address << ":\n";
                for (size_t i = 0; i < num_bytes; ++i) {
                    result |= (uint64_t)data_start[i] << (8 * i);  // 合并字节，假设小端序
                }
                std::cout << std::endl;
            } else {
                std::cerr << "Requested bytes go beyond section bounds." << std::endl;
            }
            break;
        }
    }

    elf_end(elf);
    close(fd);
    return result;
}

void solve_relocations(std::string file_path, std::string output_path) {
    std::vector<VTable> vtable_list;
    for (auto [address, sym] : reloc_map) {
        std::string sym_name = sym.name;
        // if (!sym_name.starts_with("_ZTV") && !sym_name.starts_with("_ZTC") ) continue;
        if (sym_name.compare(0, 4, "_ZTV") != 0 && sym_name.compare(0, 4, "_ZTC") != 0) continue;
        if (auto it = symbol_map.find(sym_name); it != symbol_map.end()) {
            const auto &symbol_info = it->second;
            uint64_t reloced_addr =  lib_info[symbol_info.lib_name].base_address + symbol_info.offset + sym.addend;
            uint64_t size = symbol_info.size;
            printf("Symbol %s, address 0x%lx , lib: %s, reloced: 0x%lx, size: 0x%lx \n", sym_name.c_str(), sym.address, symbol_info.lib_name.c_str(), reloced_addr, size);
            
            for (size_t i = 0; i < size / 8; ++i) {
                std::vector<uint8_t> content;
                content.reserve(size); 
                const uint64_t ptr_offset = address + i * 8;
                uint64_t addr = 0;

                if (auto it = reloc_map.find(ptr_offset); it != reloc_map.end()) {
                    const Symbol symbol = it->second;
                    std::string sym_name = symbol.name;
                    if (auto sym_it = symbol_map.find(sym_name); sym_it != symbol_map.end()) {
                        const auto &symbol_info_sub = sym_it->second;
                        switch (symbol.type) {
                            case 257:
                            case 1025:
                                addr = lib_info[symbol_info_sub.lib_name].base_address + symbol_info_sub.offset + symbol.addend;
                                break;
                            default:
                                printf("Unknown relocation type: %lu\n", symbol.type);
                                break;
                        }
                        printf("Symbol %s, address 0x%lx, reloced: 0x%lx \n", sym_name.c_str(), sym.address, addr);
                    } else {
                        printf("Symbol not found: %s \n",sym_name.c_str());
                    }

                } else {
                    // addr = read_bytes_at_address(file_path, ptr_offset, 8);
                    printf(" 0x%lx skip. \n",ptr_offset);
                    continue;
                }

                // 转换为小端序字节流
                for (int j = 0; j < 8; ++j) {
                    content.push_back(static_cast<uint8_t>((addr >> (j * 8)) & 0xFF));
                }
                vtable_list.push_back({ptr_offset, std::move(content)});
            }

            // vtable_contents[vtable.start] = std::move(content);
            // vtable_list.push_back({vtable.start, std::move(content)});
        } else {
            printf("Symbol %s not found\n", sym_name.c_str());
        }
    }


    std::ofstream out(output_path, std::ios::binary);
    if (!out) {
        printf("Failed to create output file: %s \n", output_path.c_str());
        return;
    }
    for (const auto& vt : vtable_list) {
        if (vt.address == 0) continue;
        // 直接写入结构体（不进行字节序转换）
        VTableHeader header{
            .address = static_cast<long>(vt.address),  // 注意类型转换
            .len = static_cast<long>(vt.content.size())
        };
        
        // 写入头部
        out.write(reinterpret_cast<const char*>(&header), sizeof(header));
        
        // 写入内容
        out.write(reinterpret_cast<const char*>(vt.content.data()), vt.content.size());
        
        printf("%lx %ld \n",header.address, header.len);
        for (int i = 0; i < vt.content.size(); ++i) {
            printf("%x ", vt.content[i]);
        }
        printf("\n");
    }

    printf("Successfully wrote %ld vtables to %s .\n" ,vtable_list.size(), output_path.c_str());

}

void process_vtables(std::string file_path, std::string pid, std::string output_path) {
    parse_proc_maps(pid);
    get_symbols_from_libs();
    extract_symbols(file_path);
    solve_relocations(file_path, output_path);
}

// int main(int argc, char **argv) {
//     if (argc != 4) {
//         std::cerr << "Usage: " << argv[0] << " <elf-file> <pid> "<< std::endl;
//         return 1;
//     }
//     process_vtables(argv[1], argv[2], argv[3]);
//     return 0;
// }