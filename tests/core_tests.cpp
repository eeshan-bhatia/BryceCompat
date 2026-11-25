#include <brycecompat/core.hpp>
#include <windows.h>
#include <fstream>
#include <iostream>
#include <random>
using namespace bc;
namespace {
int checks=0;
void require(bool condition,const char* message){++checks;if(!condition)throw std::runtime_error(message);}
void put(std::vector<unsigned char>& b,size_t p,uint64_t v,size_t n=4){for(size_t i=0;i<n;++i)b.at(p+i)=static_cast<unsigned char>(v>>(i*8));}
std::vector<unsigned char> pe(bool wide=false) {
    std::vector<unsigned char> b(1024);put(b,0,0x5a4d,2);put(b,0x3c,0x80);
    put(b,0x80,0x4550);put(b,0x84,wide?0x8664:0x14c,2);put(b,0x86,1,2);put(b,0x94,wide?240:224,2);
    put(b,0x98,wide?0x20b:0x10b,2);put(b,0x98+60,512);put(b,0x98+(wide?108:92),16);
    auto sec=0x98+(wide?240:224);put(b,sec+12,0x1000);put(b,sec+16,512);put(b,sec+20,512);return b;
}
void text(std::vector<unsigned char>& b,size_t p,const char* s){for(;*s;++s)b.at(p++)=static_cast<unsigned char>(*s);b.at(p)=0;}
}
int main() {
    fs::path temp=fs::temp_directory_path()/(L"BryceCompat tests "+std::to_wstring(GetCurrentProcessId())+L" \u03a9");
    try {
        require(inspect({})["format"]=="unknown","empty input");
        for(auto sig:{0x28635349u,0x8c655d13u,0xd879ab2au,0x4643534du}) {
            std::vector<unsigned char> package(4);put(package,0,sig);
            require(inspect(package).contains("package_signature"),"package signature");
            require(inspect(package)["format"]=="unknown","archive signature is not an executable");
        }
        std::vector<unsigned char> mz(64);put(mz,0,0x5a4d,2);
        require(inspect(mz)["format"]=="MZ","MZ is not necessarily NE");
        put(mz,0x3c,0xfffffff0);require(!inspect(mz)["valid"].get<bool>(),"bad header offset");
        auto ne=std::vector<unsigned char>(128);put(ne,0,0x5a4d,2);put(ne,0x3c,64);put(ne,64,0x454e,2);
        require(inspect(ne)["format"]=="NE","NE classification");
        for(bool wide:{false,true}) {
            auto b=pe(wide);auto report=inspect(b);
            require(report["valid"]==true,"valid PE");require(report["format"]==(wide?"PE32+":"PE32"),"PE class");
            require(report["architecture"]==(wide?"x64":"x86"),"machine architecture");
            size_t dir=0x98+(wide?112:96);put(b,dir+8,0x1000);put(b,dir+12,40);
            put(b,512,0x1040);put(b,524,0x1080);put(b,528,0x1040);
            put(b,576,0x10a0,wide?8:4);put(b,576+(wide?8:4),wide?(uint64_t(1)<<63)|12:(uint64_t(1)<<31)|12,wide?8:4);
            text(b,640,"KERNEL32.dll");text(b,674,"ExitProcess");report=inspect(b);
            require(report["valid"]==true,"import parse");require(report["imports"][0]["dll"]=="KERNEL32.dll","DLL import");
            require(report["imports"][0]["functions"][0]["name"]=="ExitProcess","function import");
            require(report["imports"][0]["functions"][1]["ordinal"]==12,"ordinal import");
            put(b,524,0x4000);require(inspect(b)["valid"]==false,"unmapped import RVA");
        }
        auto b=pe();put(b,0x98+96+16,0x1000);put(b,0x98+96+20,128);
        put(b,512+14,1,2);put(b,528,24);put(b,532,32);put(b,544,0x1080);put(b,548,11);text(b,640,"<assembly/>");
        auto resources=inspect(b);require(resources["valid"]==true,"resource parse");require(resources["resources"][0]["manifest_bytes"]=="<assembly/>","manifest data");
        put(b,532,0x80000000);require(inspect(b)["valid"]==false,"cyclic resources");
        b=pe();put(b,0x84,0x8664,2);require(inspect(b)["valid"]==false,"machine/header mismatch");
        b=pe();put(b,0x98+96+16,0x1000);put(b,0x98+96+20,128);
        put(b,526,1,2);put(b,528,16);put(b,532,32);put(b,544,0x1080);put(b,548,92);
        put(b,640,92,2);put(b,642,52,2);
        std::wstring versionkey=L"VS_VERSION_INFO";for(size_t i=0;i<versionkey.size();++i)put(b,646+i*2,versionkey[i],2);
        put(b,680,0xfeef04bd);put(b,688,0x00040001);put(b,692,0x00020003);
        require(inspect(b)["resources"][0]["file_version"]=="4.1.2.3","fixed version metadata");
        b=pe();put(b,0x98+92,17);require(inspect(b)["valid"]==false,"directory bounds");
        b=pe();put(b,0x98+224+16,0xffffffff);require(inspect(b)["valid"]==false,"section bounds");
        b=pe();for(size_t n=2;n<512;++n) {auto j=inspect(std::span(b).first(n));require(j["valid"]==false,"truncated PE rejected");}
        std::mt19937 random(12345);
        for(int i=0;i<2000;++i) {b=pe();for(int k=0;k<8;++k)b[random()%b.size()]=static_cast<unsigned char>(random());auto j=inspect(b);require(j.contains("valid"),"mutation result");}
        fs::create_directories(temp);auto file=temp/L"hash \u03a9.bin";{std::ofstream out(file,std::ios::binary);out<<"abc";}
        require(sha256(file)=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","SHA256 known answer");
        auto inventory=scan(temp);require(inventory["files"].size()==1,"directory inventory");require(inventory["errors"].empty(),"scan errors");
        require(inventory["files"][0]["path"]==path_text(file.filename()),"relative Unicode filename");
        require(discover({file})["candidates"][0]["exists"]==true,"configured discovery");
        auto config=temp/"profile.json";{std::ofstream out(config);out<<R"({"schema_version":1,"version":"bryce4","verified_fixes":[]})";}
        require(profile(config)["version"]=="bryce4","profile parse");
        auto saved=temp/"report.json";write_report(saved,"{}");
        bool overwrite=false;try{write_report(saved,"bad");}catch(...){overwrite=true;}require(overwrite,"report overwrite refused");
        require(fs::file_size(saved)==2,"existing report preserved");
        {std::ofstream out(config);out<<R"({"schema_version":2,"version":"bryce4","verified_fixes":[]})";}
        bool rejected=false;try{profile(config);}catch(...){rejected=true;}require(rejected,"profile version rejection");
        auto prior_dpi=GetThreadDpiAwarenessContext();
        auto snapshot=observe(GetCurrentProcessId());require(snapshot["processes"][0]["running"]==true,"current process observation");
        require(AreDpiAwarenessContextsEqual(prior_dpi,GetThreadDpiAwarenessContext())!=FALSE,"observer DPI context restored");
        require(snapshot.contains("window_coordinate_space"),"display coordinate context recorded");
        require(!snapshot["processes"][0]["threads"].empty(),"thread inventory");
        for(const auto& t:snapshot["processes"][0]["threads"])require(t.contains("cycle_detected")||t.contains("wait_chain_error")||!snapshot["errors"].empty(),"wait chain success or explicit error");
        auto invalid_image=temp/"invalid-image.exe";b=pe();
        {std::ofstream out(invalid_image,std::ios::binary);out.write(reinterpret_cast<const char*>(b.data()),static_cast<std::streamsize>(b.size()));}
        auto failed_launch=launch(invalid_image,0);
        require(failed_launch["process_created"]==false,"invalid image cannot execute");
        require(failed_launch["launch_error"].get<unsigned>()!=0,"launch error preserved in structured report");
        fs::remove_all(temp);std::cout<<checks<<" checks passed\n";return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<" after "<<checks<<" checks\n";std::error_code ec;fs::remove_all(temp,ec);return 1;}
}
