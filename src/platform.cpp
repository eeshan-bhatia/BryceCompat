#include <brycecompat/core.hpp>
#include <windows.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <fstream>
#include <array>
#include <set>
#include <stdexcept>

namespace bc {
namespace {
struct Handle {
    HANDLE h=nullptr;
    ~Handle(){if(h && h!=INVALID_HANDLE_VALUE)CloseHandle(h);}
    Handle()=default;
    explicit Handle(HANDLE value):h(value){}
    Handle(const Handle&)=delete;
    Handle& operator=(const Handle&)=delete;
};
std::runtime_error winerror(const char* operation) {return std::runtime_error(std::string(operation)+" failed; Win32 error "+std::to_string(GetLastError()));}
void check(NTSTATUS status) {if(status<0)throw std::runtime_error("BCrypt error "+std::to_string(status));}
}
std::string utf8(std::wstring_view value) {
    if(value.empty())return {};
    int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),nullptr,0,nullptr,nullptr);
    if(!n)throw winerror("UTF-8 conversion");
    std::string s(n,'\0');
    if(!WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),s.data(),n,nullptr,nullptr))throw winerror("UTF-8 conversion");
    return s;
}
std::string path_text(const fs::path& path){return utf8(path.wstring());}
bool reparse(const fs::path& path) {
    auto a=GetFileAttributesW(path.c_str());
    if(a==INVALID_FILE_ATTRIBUTES)throw winerror("GetFileAttributesW");
    return (a&FILE_ATTRIBUTE_REPARSE_POINT)!=0;
}
void write_report(const fs::path& path,std::string_view data) {
    // CREATE_NEW prevents accidental overwrite even if the destination appears concurrently.
    Handle file(CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr));
    if(file.h==INVALID_HANDLE_VALUE)throw winerror("Create report (destination must not exist)");
    size_t offset=0;
    while(offset<data.size()) {
        auto chunk=static_cast<DWORD>((std::min)(data.size()-offset,size_t(1024*1024)));DWORD written=0;
        if(!WriteFile(file.h,data.data()+offset,chunk,&written,nullptr))throw winerror("Write report");
        if(!written)throw std::runtime_error("Report write made no progress");offset+=written;
    }
    if(!FlushFileBuffers(file.h))throw winerror("Flush report");
}
std::string sha256(const fs::path& path) {
    struct Algorithm {BCRYPT_ALG_HANDLE h=nullptr;~Algorithm(){if(h)BCryptCloseAlgorithmProvider(h,0);}} a;
    struct Hash {BCRYPT_HASH_HANDLE h=nullptr;~Hash(){if(h)BCryptDestroyHash(h);}} hash;
    check(BCryptOpenAlgorithmProvider(&a.h,BCRYPT_SHA256_ALGORITHM,nullptr,0));
    check(BCryptCreateHash(a.h,&hash.h,nullptr,0,nullptr,0,0));
    std::ifstream in(path,std::ios::binary);if(!in)throw std::runtime_error("Cannot open file for hashing");
    std::array<unsigned char,65536> buffer{};
    while(in) {in.read(reinterpret_cast<char*>(buffer.data()),buffer.size());auto n=in.gcount();if(n)check(BCryptHashData(hash.h,buffer.data(),static_cast<ULONG>(n),0));}
    if(!in.eof())throw std::runtime_error("File read failed during hashing");
    std::array<unsigned char,32> digest{};check(BCryptFinishHash(hash.h,digest.data(),static_cast<ULONG>(digest.size()),0));
    constexpr char hex[]="0123456789abcdef";std::string result;
    for(auto b:digest){result+=hex[b>>4];result+=hex[b&15];}return result;
}
Json host_info() {
    Json j={{"platform","Windows"},{"tool_architecture",sizeof(void*)==8?"64-bit":"32-bit"}};
    // Registry reports the installed build without manifest-dependent GetVersionEx behavior.
    HKEY key=nullptr;
    auto status=RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",0,KEY_QUERY_VALUE|KEY_WOW64_64KEY,&key);
    if(status==ERROR_SUCCESS) {
        for(auto name:{L"CurrentBuildNumber",L"DisplayVersion"}) {
            wchar_t value[256]{};DWORD size=sizeof(value);
            auto error=RegGetValueW(key,nullptr,name,RRF_RT_REG_SZ,nullptr,value,&size);
            if(error==ERROR_SUCCESS)j[utf8(name)]=utf8(value);else j[utf8(name)+"_error"]=error;
        }
        RegCloseKey(key);
    } else j["os_version_error"]=status;
    return j;
}
Json discover(const std::vector<fs::path>& configured) {
    Json j={{"schema_version",1},{"candidates",Json::array()},{"note","Candidates do not confirm a Bryce release or compatibility"}};
    std::set<fs::path> seen;
    auto add=[&](const fs::path& p,const char* source) {
        if(seen.insert(p).second) {std::error_code ec;bool exists=fs::exists(p,ec);j["candidates"].push_back({{"path",path_text(p)},{"source",source},{"exists",exists},{"error",ec.message()}});}
    };
    for(const auto& p:configured)add(p,"configured");
    for(auto name:{L"Bryce3DCD.iso",L"Bryce_4.iso",L"bryce4\\Bryce_4.iso",L"Bryce3DCD\\Bryce3DCD.iso"}) {
        auto p=fs::current_path()/name;if(fs::exists(p))add(p,"expected media filename (identity unverified)");
    }
    wchar_t env[32768]{};
    auto n=GetEnvironmentVariableW(L"BRYCECOMPAT_MEDIA",env,32768);
    if(n && n<32768)add(env,"BRYCECOMPAT_MEDIA");
    for(auto base:{fs::current_path()/"original-media",fs::current_path().parent_path()/"original-media"})if(fs::exists(base))add(base,"development media directory");
    wchar_t drives[512]{};auto len=GetLogicalDriveStringsW(512,drives);
    if(!len || len>=512)throw winerror("GetLogicalDriveStringsW");
    for(auto p=drives;*p;p+=wcslen(p)+1)if(GetDriveTypeW(p)==DRIVE_CDROM)add(p,"CD-ROM drive");
    for(auto root:{L"ProgramFiles",L"ProgramFiles(x86)"}) {
        n=GetEnvironmentVariableW(root,env,32768);
        if(n && n<32768) for(auto suffix:{L"MetaCreations\\Bryce 4",L"MetaCreations\\Bryce 3D",L"Bryce 4",L"Bryce 3D"}) {
            fs::path p=fs::path(env)/suffix;if(fs::exists(p))add(p,"common installation directory");
        }
    }
    return j;
}
Json observe(unsigned long pid) {
    Json result={{"pid",pid},{"processes",Json::array()},{"errors",Json::array()},{"functional_compatibility","NOT TESTED"}};
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));
    if(snapshot.h==INVALID_HANDLE_VALUE)throw winerror("CreateToolhelp32Snapshot");
    PROCESSENTRY32W pe{};pe.dwSize=sizeof(pe);std::vector<PROCESSENTRY32W> entries;
    if(!Process32FirstW(snapshot.h,&pe))throw winerror("Process32FirstW");
    do {entries.push_back(pe);} while(Process32NextW(snapshot.h,&pe));
    if(GetLastError()!=ERROR_NO_MORE_FILES)throw winerror("Process32NextW");
    std::set<DWORD> ids{pid};bool changed;
    do {changed=false;for(auto& e:entries)if(ids.count(e.th32ParentProcessID)&&!ids.count(e.th32ProcessID)){ids.insert(e.th32ProcessID);changed=true;}}while(changed);
    for(auto id:ids) {
        Json process={{"pid",id},{"windows",Json::array()}};
        for(auto& e:entries)if(e.th32ProcessID==id){process["parent_pid"]=e.th32ParentProcessID;process["image_name"]=utf8(e.szExeFile);}
        Handle h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,id));
        if(h.h) {
            DWORD code=0;if(GetExitCodeProcess(h.h,&code)) {auto state=WaitForSingleObject(h.h,0);process["running"]=state==WAIT_TIMEOUT;process["exit_code"]=state==WAIT_OBJECT_0?Json(code):Json(nullptr);if(state==WAIT_FAILED)process["wait_error"]=GetLastError();}
            else process["exit_status_error"]=GetLastError();
            USHORT machine=0,native=0;
            if(IsWow64Process2(h.h,&machine,&native)){process["process_machine"]=machine;process["native_machine"]=native;}else process["bitness_error"]=GetLastError();
        } else process["open_error"]=GetLastError();
        struct Context {DWORD id;Json* windows;bool failed=false;};Context context{id,&process["windows"]};
        SetLastError(ERROR_SUCCESS);
        auto ok=EnumWindows([](HWND window,LPARAM param)->BOOL {
            auto& c=*reinterpret_cast<Context*>(param);DWORD owner=0;GetWindowThreadProcessId(window,&owner);if(owner!=c.id)return TRUE;
            try {
                RECT rect{};bool has_rect=GetWindowRect(window,&rect)!=0;
                DWORD_PTR response=0;SetLastError(ERROR_SUCCESS);
                bool responsive=SendMessageTimeoutW(window,WM_NULL,0,0,SMTO_ABORTIFHUNG|SMTO_BLOCK,100,&response)!=0;
                Json w={{"visible",IsWindowVisible(window)!=FALSE},{"responsive_probe",responsive},{"probe_error",responsive?0:GetLastError()}};
                if(has_rect)w["rectangle"]={rect.left,rect.top,rect.right,rect.bottom};
                // Titles deliberately omitted: installer windows can contain serial numbers.
                c.windows->push_back(w);return TRUE;
            } catch(...) {c.failed=true;return FALSE;}
        },reinterpret_cast<LPARAM>(&context));
        if(!ok || context.failed)process["window_enumeration_error"]=context.failed?ERROR_NOT_ENOUGH_MEMORY:GetLastError();
        result["processes"].push_back(process);
    }
    result["limitations"]="Snapshot descendants only; exited/reparented children may be absent. A responsive window does not prove application functionality.";
    return result;
}
Json launch(const fs::path& executable,unsigned timeout_ms) {
    auto path=fs::absolute(executable);auto binary=analyze(path);auto a=binary["analysis"];
    if(!a.value("valid",false) || (a.value("architecture","")!="x86" && a.value("architecture","")!="x64") ||
       (a.value("format","")!="PE32" && a.value("format","")!="PE32+") || a.value("is_dll",false))throw std::runtime_error("Only valid x86/x64 PE applications may be launched");
    std::wstring command=L"\""+path.wstring()+L"\"";
    STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION info{};
    if(!CreateProcessW(path.c_str(),command.data(),nullptr,nullptr,FALSE,0,nullptr,path.parent_path().c_str(),&startup,&info))throw winerror("CreateProcessW");
    Handle process(info.hProcess),thread(info.hThread);
    auto wait=WaitForSingleObject(process.h,timeout_ms);
    Json result={{"schema_version",1},{"executable",binary},{"host",host_info()},{"pid",info.dwProcessId},
        {"process_created",true},{"observation_ms",timeout_ms},{"working_directory",path_text(path.parent_path())},
        {"observation_elapsed_while_running",wait==WAIT_TIMEOUT},{"compatibility","NOT TESTED"}};
    if(wait==WAIT_FAILED)result["wait_error"]=GetLastError();
    DWORD code=0;if(GetExitCodeProcess(process.h,&code))result["exit_code"]=wait==WAIT_OBJECT_0?Json(code):Json(nullptr);else result["exit_code_error"]=GetLastError();
    result["snapshot"]=observe(info.dwProcessId);
    result["note"]="Processes are never terminated when observation ends; elapsed observation is not a crash or proof of GUI initialization.";
    return result;
}
}
