#include <brycecompat/core.hpp>
#include <fstream>
#include <algorithm>
#include <limits>
#include <stdexcept>
#include <functional>

namespace bc {
namespace {
struct Reader {
    std::span<const unsigned char> b;
    void need(size_t p, size_t n) const {
        if (p > b.size() || n > b.size() - p) throw std::runtime_error("Truncated or out-of-bounds binary structure");
    }
    uint64_t number(size_t p, size_t n) const {
        need(p,n); uint64_t v=0;
        for(size_t i=0;i<n;++i) v |= uint64_t(b[p+i]) << (8*i);
        return v;
    }
    uint16_t u16(size_t p) const { return static_cast<uint16_t>(number(p,2)); }
    uint32_t u32(size_t p) const { return static_cast<uint32_t>(number(p,4)); }
    std::string str(size_t p, size_t limit=4096) const {
        std::string s;
        for(size_t i=0;i<limit;++i) { need(p+i,1); if(!b[p+i]) return s; s+=char(b[p+i]); }
        throw std::runtime_error("Unterminated or oversized binary string");
    }
};
struct Section { uint32_t va, raw, size; };
}

Json inspect(std::span<const unsigned char> bytes) {
    Json out={{"format","unknown"},{"architecture","unknown"},{"imports",Json::array()},
        {"resources",Json::array()},{"warnings",Json::array()},{"valid",true}};
    Reader r{bytes};
    try {
        if(bytes.size()>=4) {
            auto signature=r.u32(0);
            if(signature==0x28635349)out["package_signature"]="InstallShield cabinet";
            else if(signature==0x8c655d13)out["package_signature"]="InstallShield Z archive";
            else if(signature==0xd879ab2a)out["package_signature"]="InstallShield installer archive";
            else if(signature==0x4643534d)out["package_signature"]="Microsoft cabinet";
            if(out.contains("package_signature"))out["warnings"].push_back("Signature identification only; archive structure and contents are not validated by this scanner");
        }
        if(bytes.size()<2 || r.u16(0)!=0x5a4d) return out;
        out["format"]="MZ"; r.need(0,64);
        size_t pe=r.u32(0x3c);
        if(!pe) { out["warnings"].push_back("MZ container without extended header; execution architecture unconfirmed"); return out; }
        r.need(pe,2);
        if(r.u16(pe)==0x454e) { r.need(pe,64); out["format"]="NE"; out["architecture"]="16-bit segmented"; out["target_os"]=r.number(pe+54,1); return out; }
        if(r.u16(pe)!=0x4550) return out;
        if(r.u32(pe)!=0x4550) throw std::runtime_error("Invalid PE signature");
        r.need(pe,24);
        auto machine=r.u16(pe+4); auto count=r.u16(pe+6); auto optsize=r.u16(pe+20);
        out["machine"]=machine;
        out["architecture"]=machine==0x14c?"x86":machine==0x8664?"x64":machine==0xaa64?"ARM64":"unknown";
        size_t opt=pe+24; r.need(opt,optsize); auto magic=r.u16(opt);
        bool wide=magic==0x20b;
        if(magic!=0x10b && !wide) throw std::runtime_error("Unknown PE optional header magic");
        if((machine==0x14c && wide) || (machine==0x8664 && !wide)) throw std::runtime_error("Machine and optional-header architecture disagree");
        size_t base=wide?112:96;
        if(optsize<base) throw std::runtime_error("Short optional header");
        out["format"]=wide?"PE32+":"PE32";
        out["is_dll"]=(r.u16(pe+22)&0x2000)!=0;
        out["subsystem"]=r.u16(opt+68);
        auto dirs=r.u32(opt+base-4);
        if(dirs>(optsize-base)/8) throw std::runtime_error("Data directories exceed optional header");
        if(count>96) throw std::runtime_error("Excessive PE section count");
        std::vector<Section> sections;
        for(size_t i=0;i<count;++i) {
            size_t s=opt+optsize+i*40; r.need(s,40);
            Section sec{r.u32(s+12),r.u32(s+20),r.u32(s+16)};
            r.need(sec.raw,sec.size); sections.push_back(sec);
        }
        auto map=[&](uint64_t va,size_t n)->size_t {
            if(va<r.u32(opt+60) && n<=uint64_t(r.u32(opt+60))-va) {r.need(size_t(va),n);return size_t(va);}
            for(auto s:sections) if(va>=s.va && va-s.va<s.size && n<=s.size-(va-s.va)) {
                size_t p=size_t(s.raw)+size_t(va-s.va); r.need(p,n); return p;
            }
            throw std::runtime_error("RVA is not backed by file data");
        };
        auto string_rva=[&](uint64_t va) {
            std::string s;
            for(size_t i=0;i<4096;++i) { auto c=bytes[map(va+i,1)]; if(!c)return s; s+=char(c); }
            throw std::runtime_error("Unterminated import string");
        };
        if(dirs>1) {
            uint64_t va=r.u32(opt+base+8); auto size=r.u32(opt+base+12);
            if(va) {
                bool end=false;
                for(size_t i=0;i<size/20 && i<4096;++i) {
                    auto d=map(va+i*20,20); auto lookup=r.u32(d); auto name=r.u32(d+12); auto iat=r.u32(d+16);
                    if(!lookup&&!name&&!iat&&!r.u32(d+4)&&!r.u32(d+8)) {end=true;break;}
                    Json imp={{"dll",string_rva(name)},{"functions",Json::array()}};
                    uint64_t table=lookup?lookup:iat; bool terminated=false;
                    for(size_t k=0;k<65536;++k) {
                        auto value=r.number(map(table+k*(wide?8:4),wide?8:4),wide?8:4);
                        if(!value) {terminated=true;break;}
                        if(value & (wide?(uint64_t(1)<<63):(uint64_t(1)<<31))) imp["functions"].push_back({{"ordinal",value&0xffff}});
                        else imp["functions"].push_back({{"name",string_rva(value+2)}});
                    }
                    if(!terminated) throw std::runtime_error("Unterminated import thunk table");
                    out["imports"].push_back(imp);
                }
                if(!end) throw std::runtime_error("Unterminated import descriptor table");
            }
        }
        if(dirs>2 && r.u32(opt+base+16)) {
            uint64_t root=r.u32(opt+base+16); auto total=r.u32(opt+base+20); size_t nodes=0;
            auto resource=[&](uint32_t rel,size_t n) {
                if(rel>total || n>total-rel) throw std::runtime_error("Resource exceeds directory bounds");
                return map(root+rel,n);
            };
            std::function<void(uint32_t,unsigned,Json)> walk;
            walk=[&](uint32_t rel,unsigned depth,Json ids) {
                if(depth>3 || ++nodes>4096) throw std::runtime_error("Resource recursion or size limit exceeded");
                auto p=resource(rel,16); size_t n=size_t(r.u16(p+12))+r.u16(p+14);
                for(size_t i=0;i<n;++i) {
                    uint64_t entry=uint64_t(rel)+16+i*8;
                    if(entry>UINT32_MAX) throw std::runtime_error("Resource offset overflow");
                    auto e=resource(uint32_t(entry),8); auto id=r.u32(e); auto next=r.u32(e+4); auto path=ids;
                    if(id&0x80000000) {
                        auto no=id&0x7fffffff; auto length=r.u16(resource(no,2));
                        if(length>1024) throw std::runtime_error("Oversized resource name");
                        auto text=resource(no+2,size_t(length)*2); std::wstring w;
                        for(size_t j=0;j<length;++j) w+=wchar_t(r.u16(text+j*2));
                        path.push_back(utf8(w));
                    } else path.push_back(id);
                    if(next&0x80000000) walk(next&0x7fffffff,depth+1,path);
                    else {
                        if(++nodes>4096) throw std::runtime_error("Resource count limit exceeded");
                        auto data=resource(next,16); auto size=r.u32(data+4); auto payload=map(r.u32(data),size);
                        Json item={{"path",path},{"size",size},{"codepage",r.u32(data+8)}};
                        if(!path.empty() && path[0]==24 && size<=1024*1024) item["manifest_bytes"]=std::string(reinterpret_cast<const char*>(bytes.data()+payload),size);
                        // VS_VERSION_INFO fixed fields are read as data, never through LoadLibrary.
                        if(!path.empty() && path[0]==16 && size>=6) {
                            Reader vr{bytes.subspan(payload,size)}; size_t k=6; std::wstring key;
                            for(;k+2<=size;k+=2) {auto c=vr.u16(k);if(!c){k+=2;break;}key+=wchar_t(c);}
                            k=(k+3)&~size_t(3);
                            if(key==L"VS_VERSION_INFO" && k+52<=size && vr.u32(k)==0xfeef04bd) {
                                auto hi=vr.u32(k+8),lo=vr.u32(k+12);
                                item["file_version"]=std::to_string(hi>>16)+"."+std::to_string(hi&65535)+"."+std::to_string(lo>>16)+"."+std::to_string(lo&65535);
                            }
                        }
                        out["resources"].push_back(item);
                    }
                }
            };
            walk(0,0,Json::array());
        }
        if(dirs>13 && r.u32(opt+base+13*8)) out["warnings"].push_back("Delay-load imports present; not enumerated");
    } catch(const std::exception& e) { out["valid"]=false; out["warnings"].push_back(e.what()); }
    return out;
}

Json analyze(const fs::path& path) {
    auto size=fs::file_size(path);
    Json out={{"path",path_text(path)},{"size",size},{"sha256",sha256(path)}};
    std::ifstream in(path,std::ios::binary); if(!in) throw std::runtime_error("Cannot open input file");
    if(size>256ull*1024*1024) {out["analysis"]={{"format","unknown"},{"warnings",{"Binary parsing skipped: exceeds 256 MiB limit"}}};return out;}
    std::vector<unsigned char> bytes(static_cast<size_t>(size));
    if(size && !in.read(reinterpret_cast<char*>(bytes.data()),static_cast<std::streamsize>(size))) throw std::runtime_error("Short file read");
    out["analysis"]=inspect(bytes);
    return out;
}

Json scan(const fs::path& path) {
    if(!fs::exists(path)) throw std::runtime_error("Input path does not exist");
    if(reparse(path)) throw std::runtime_error("Reparse point roots are not scanned");
    Json report={{"schema_version",1},{"root",path_text(fs::absolute(path))},{"host",host_info()},
        {"files",Json::array()},{"errors",Json::array()},{"compatibility","NOT TESTED"},{"release","UNKNOWN"}};
    auto add=[&](const fs::path& file) {
        try {
            auto item=analyze(file);
            item["path"]=path_text(fs::is_directory(path)?fs::relative(file,path):file.filename());
            auto ext=file.extension().wstring(); std::transform(ext.begin(),ext.end(),ext.begin(),::towlower);
            if(ext==L".iso") item["note"]="ISO inventory requires a user-mounted or extracted Windows filesystem; HFS is not parsed";
            if(ext==L".cab") item["note"]="CAB filename candidate; package not extracted";
            report["files"].push_back(item);
        } catch(const std::exception& e) {report["errors"].push_back({{"path",path_text(file)},{"error",e.what()}});}
    };
    if(fs::is_regular_file(path)) add(path);
    else if(fs::is_directory(path)) {
        // Windows junctions/reparse points are also excluded in platform code via attributes.
        std::error_code ec;
        fs::recursive_directory_iterator it(path,ec),end;
        if(ec) report["errors"].push_back(ec.message());
        for(;it!=end;) {
            const auto file=it->path();
            if(reparse(file)) {it.disable_recursion_pending();report["errors"].push_back({{"path",path_text(file)},{"error","Skipped reparse point"}});}
            else if(it->is_regular_file(ec)) add(file);
            if(ec) {report["errors"].push_back(ec.message());ec.clear();}
            it.increment(ec); if(ec) {report["errors"].push_back(ec.message());ec.clear();}
        }
    } else throw std::runtime_error("Input is not a regular file or directory");
    return report;
}

Json profile(const fs::path& path) {
    std::ifstream in(path); if(!in)throw std::runtime_error("Cannot open profile");
    Json p=Json::parse(in);
    if(p.at("schema_version")!=1 || !p.at("version").is_string() ||
       (p["version"]!="bryce3" && p["version"]!="bryce4") || !p.at("verified_fixes").is_array()) throw std::runtime_error("Unsupported profile schema");
    if(!p["verified_fixes"].empty()) throw std::runtime_error("This release cannot apply compatibility fixes");
    return p;
}
}
