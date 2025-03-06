#include "extract_vtable.hpp"


std::unordered_map<std::string, LibraryInfo> lib_info;  // lib_name -> path and base_addr
std::unordered_map<std::string, Symbol_info> symbol_map;  // symbol name -> lib_name 、offset 和 size

std::unordered_map<uint64_t, Symbol> reloc_map;  // relocation offset -> symbol name

std::string extractFileName(const std::string& path) {
    size_t pos = path.find_last_of("/\\");
    return (pos != std::string::npos) ? path.substr(pos + 1) : path;
}

void parse_proc_maps(std::string pid) {
    std::ifstream maps("/proc/" + pid + "/maps");
    if (!maps.is_open()) {
        printf("Failed to open /proc/%s/maps \n", pid.c_str());
    }

    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(".so") != std::string::npos) {
            std::istringstream iss(line);
            uint64_t start, end;
            char dash; 
            char perms[5];
            std::string path;

            if (!(iss >> std::hex >> start)) continue;
            if (!(iss >> dash) || dash != '-') continue;
            if (!(iss >> std::hex >> end)) continue;
            if (!(iss >> perms)) continue;

            std::string rest;
            std::getline(iss >> std::ws, rest);
            path = rest.substr(rest.find_last_of(' ') + 1);
            std::string name = extractFileName(path);

            if (lib_info.find(name) == lib_info.end()) {
                lib_info[name] = {path, start};
            }
        }
    }
}

// This function iterates over all known dynamic libraries and parses the symbols of symbols 
// starting with "_Z" in their dynamic symbol table (SHT_DYNSYM). 
// For each symbol, its name, address, and size are extracted and stored in a global symbol table (symbol_map).
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
                fprintf(stderr, "cannot read symbols\n");
                continue;
            }

            size_t num_syms = shdr.sh_size / shdr.sh_entsize;
            std::vector<GElf_Sym> symbolsOfLib(num_syms);
            for (size_t i = 0; i < num_syms; ++i) {
                if (gelf_getsym(data, i, &symbolsOfLib[i]) != &symbolsOfLib[i]) {
                    fprintf(stderr, "read symbol failed: %s\n", elf_errmsg(elf_errno()));
                    continue;
                }
            }

            for (size_t i = 0; i < num_syms; ++i) {
                const GElf_Sym& sym = symbolsOfLib[i];
                const char* full_name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                if (!full_name || sym.st_shndx == SHN_UNDEF) continue;
                const char* version_sep = strchr(full_name, '@');
                std::string name(version_sep ? 
                                std::string(full_name, version_sep - full_name) : 
                                full_name);

                if (name.find("_Z") != 0) continue;
                size_t size = sym.st_size;
                if (size == 0 && i + 1 < num_syms) {
                    const GElf_Sym& next_sym = symbolsOfLib[i+1];
                    if (next_sym.st_value > sym.st_value) {
                        size = next_sym.st_value - sym.st_value;
                    }
                }
                symbol_map[name] = {lib_name, sym.st_value, size};
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

// Extract dynamic symbol information (.dynsym) and relocation information (.rela.dyn) from the specified ELF file. 
// It parses these segments to obtain symbolic information related to dynamic links, especially undefined global symbols.
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
            reloc_map[rela.r_offset] = {sym_name, rela.r_offset, GELF_R_TYPE(rela.r_info), rela.r_addend};
        }
    }

    elf_end(elf);
    close(fd);
    return 0;
}

uint64_t read_bytes_at_address(const std::string &file_path, uint64_t target_address, size_t num_bytes) {
    int fd = open(file_path.c_str(), O_RDONLY);
    if (fd == -1) {
        std::cerr << "Cannot open ELF file: " << file_path << std::endl;
        return 0;
    }

    elf_version(EV_CURRENT);
    Elf *elf = elf_begin(fd, ELF_C_READ, nullptr);
    if (!elf) {
        std::cerr << "ELF open failed: " << elf_errmsg(elf_errno()) << std::endl;
        close(fd);
        return 0;
    }

    uint64_t result = 0;
    Elf_Scn *scn = nullptr;
    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) != &shdr) {
            std::cerr << "Error getting section header: " << elf_errmsg(elf_errno()) << std::endl;
            continue;
        }

        if (shdr.sh_type != SHT_PROGBITS && shdr.sh_type != SHT_NOBITS) {
            continue;
        }
        Elf_Data *data = elf_getdata(scn, nullptr);
        if (!data) {
            std::cerr << "Error getting section data: " << elf_errmsg(elf_errno()) << std::endl;
            continue;
        }
        uint64_t section_start = shdr.sh_addr;
        uint64_t section_end = section_start + shdr.sh_size;

        if (target_address >= section_start && target_address < section_end) {
            size_t offset_in_section = target_address - section_start;
            if (offset_in_section + num_bytes <= shdr.sh_size) {
                uint8_t *section_data = (uint8_t *)data->d_buf;
                uint8_t *data_start = section_data + offset_in_section;
                for (size_t i = 0; i < num_bytes; ++i) {
                    result |= (uint64_t)data_start[i] << (8 * i); 
                }
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
        if (sym_name.compare(0, 4, "_ZTV") != 0 && sym_name.compare(0, 4, "_ZTC") != 0) continue;
        if (auto it = symbol_map.find(sym_name); it != symbol_map.end()) {
            const auto &symbol_info = it->second;
            uint64_t reloced_addr =  lib_info[symbol_info.lib_name].base_address + symbol_info.offset + sym.addend;
            uint64_t size = symbol_info.size;
            
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
                                break;
                        }
                    }
                }
                for (int j = 0; j < 8; ++j) {
                    content.push_back(static_cast<uint8_t>((addr >> (j * 8)) & 0xFF));
                }
                vtable_list.push_back({ptr_offset, std::move(content)});
            }

        }
    }

    std::ofstream out(output_path, std::ios::binary);
    if (!out) {
        printf("Failed to create output file: %s \n", output_path.c_str());
        return;
    }
    for (const auto& vt : vtable_list) {
        if (vt.address == 0) continue;
        VTableHeader header{
            .address = static_cast<long>(vt.address), 
            .len = static_cast<long>(vt.content.size())
        };
        out.write(reinterpret_cast<const char*>(&header), sizeof(header));
        out.write(reinterpret_cast<const char*>(vt.content.data()), vt.content.size());
    }

}

void process_vtables(std::string file_path, std::string pid, std::string output_path) {
    parse_proc_maps(pid);
    get_symbols_from_libs();
    extract_symbols(file_path);
    solve_relocations(file_path, output_path);
}
