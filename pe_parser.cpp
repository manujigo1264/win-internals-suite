#include "pe_parser.h"

static void parse_imports(const FileContext& ctx, PEInfo& out) {
    auto& dir = ctx.nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) return;
    auto imp = (IMAGE_IMPORT_DESCRIPTOR*)rva_to_ptr(ctx, dir.VirtualAddress);
    if (!imp) return;
    for (; imp->Name; ++imp) {
        auto dll = (char*)rva_to_ptr(ctx, imp->Name);
        if (!dll) continue;
        auto thunk = (IMAGE_THUNK_DATA*)rva_to_ptr(ctx, imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk);
        if (!thunk) continue;
        for (; thunk && thunk->u1.AddressOfData; ++thunk) {
            if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                std::ostringstream os;
                os << dll << "!#" << (thunk->u1.Ordinal & 0xFFFF);
                out.imports.push_back(os.str());
            }
            else {
                auto ibn = (IMAGE_IMPORT_BY_NAME*)rva_to_ptr(ctx, (DWORD)thunk->u1.AddressOfData);
                if (!ibn) continue;
                std::ostringstream os;
                os << dll << "!" << (char*)ibn->Name;
                out.imports.push_back(os.str());
            }
        }
    }
}

static void parse_exports(const FileContext& ctx, PEInfo& out) {
    auto& dir = ctx.nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return;
    auto exp = (IMAGE_EXPORT_DIRECTORY*)rva_to_ptr(ctx, dir.VirtualAddress);
    if (!exp) return;
    auto names = (DWORD*)rva_to_ptr(ctx, exp->AddressOfNames);
    auto ords = (WORD*)rva_to_ptr(ctx, exp->AddressOfNameOrdinals);
    auto funcs = (DWORD*)rva_to_ptr(ctx, exp->AddressOfFunctions);
    if (!funcs) return;

    if (names && ords && exp->NumberOfNames) {
        for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
            // Add bounds checking for array access
            if (ords[i] >= exp->NumberOfFunctions) continue;

            auto nm = (char*)rva_to_ptr(ctx, names[i]);
            WORD ord = ords[i] + exp->Base;
            DWORD rva = funcs[ords[i]];
            std::ostringstream os;
            os << (nm ? nm : "<noname>") << " @" << ord << " rva=0x" << std::hex << rva;
            out.exports.push_back(os.str());
        }
    }
    else {
        for (DWORD i = 0; i < exp->NumberOfFunctions; ++i) {
            WORD ord = (WORD)(i + exp->Base);
            DWORD rva = funcs[i];
            std::ostringstream os;
            os << "<noname> @" << ord << " rva=0x" << std::hex << rva;
            out.exports.push_back(os.str());
        }
    }
}

bool parse_pe_file(const wstring& path, PEInfo& out) {
    MappedFile mf;
    if (!mf.open(path)) return false;

    auto base = mf.base;
    if (!base) return false;

    // Add file size validation
    if (mf.size < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS)) {
        return false;
    }

    auto dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    // Add bounds check for e_lfanew
    if (dos->e_lfanew < 0 ||
        dos->e_lfanew >(int)(mf.size - sizeof(IMAGE_NT_HEADERS))) {
        return false;
    }

    auto nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    out.valid = true;
    out.is64 = (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
    out.numSecs = nt->FileHeader.NumberOfSections;
    out.entryRva = nt->OptionalHeader.AddressOfEntryPoint;
    out.imageBase = out.is64 ? ((IMAGE_NT_HEADERS64*)nt)->OptionalHeader.ImageBase : nt->OptionalHeader.ImageBase;
    out.sizeOfImage = nt->OptionalHeader.SizeOfImage;

    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < out.numSecs; i++) {
        char name[9] = { 0 };
        memcpy(name, sec[i].Name, 8);
        std::ostringstream os;
        os << name
            << " VA=0x" << std::hex << sec[i].VirtualAddress
            << " VSz=0x" << sec[i].Misc.VirtualSize
            << " Raw=0x" << sec[i].SizeOfRawData
            << " Char=0x" << sec[i].Characteristics;
        out.sections.push_back(os.str());
    }

    // Create FileContext for safe parsing
    FileContext ctx = { base, mf.size, nt };

    parse_imports(ctx, out);
    parse_exports(ctx, out);

    string h;
    if (sha256(base, mf.size, h)) out.sha256 = h;
    return true;
}

void print_pe(const PEInfo& pe, const wstring& path) {
    std::wcout << L"[PE] " << path << L"\n";
    if (!pe.valid) { std::wcout << L"  invalid PE\n"; return; }
    std::wcout << L"  Arch: " << (pe.is64 ? L"x64" : L"x86")
        << L"  Sections: " << pe.numSecs
        << L"  Entry(RVA)=0x" << std::hex << pe.entryRva
        << L"  ImageBase=0x" << pe.imageBase
        << L"  SizeOfImage=0x" << pe.sizeOfImage << std::dec << L"\n";
    if (!pe.sha256.empty()) std::wcout << L"  SHA256: " << to_wide(pe.sha256) << L"\n";

    std::wcout << L"  [Sections]\n";
    for (auto& s : pe.sections) std::wcout << L"    " << to_wide(s) << L"\n";

    std::wcout << L"  [Imports]\n";
    for (auto& s : pe.imports) std::wcout << L"    " << to_wide(s) << L"\n";

    std::wcout << L"  [Exports]\n";
    for (auto& s : pe.exports) std::wcout << L"    " << to_wide(s) << L"\n";
}