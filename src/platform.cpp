#include <brycecompat/core.hpp>
#include <windows.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <wct.h>
#include <shellapi.h>
#include <shellscalingapi.h>
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
    // Change only our observer thread's coordinate context, never the target app.
    struct DpiScope {
        DPI_AWARENESS_CONTEXT previous=SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        ~DpiScope(){if(previous)SetThreadDpiAwarenessContext(previous);}
    } dpi_scope;
    result["window_coordinate_space"]=dpi_scope.previous?"physical screen pixels":"observer default (may be DPI virtualized)";
    if(!dpi_scope.previous)result["errors"].push_back({{"observer_dpi_context_error",GetLastError()}});
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));
    if(snapshot.h==INVALID_HANDLE_VALUE)throw winerror("CreateToolhelp32Snapshot");
    PROCESSENTRY32W pe{};pe.dwSize=sizeof(pe);std::vector<PROCESSENTRY32W> entries;
    if(!Process32FirstW(snapshot.h,&pe))throw winerror("Process32FirstW");
    do {entries.push_back(pe);} while(Process32NextW(snapshot.h,&pe));
    if(GetLastError()!=ERROR_NO_MORE_FILES)throw winerror("Process32NextW");
    std::set<DWORD> ids{pid};bool changed;
    do {changed=false;for(auto& e:entries)if(ids.count(e.th32ParentProcessID)&&!ids.count(e.th32ProcessID)){ids.insert(e.th32ProcessID);changed=true;}}while(changed);
    Handle threads(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0));
    std::vector<THREADENTRY32> thread_entries;
    if(threads.h==INVALID_HANDLE_VALUE)result["errors"].push_back({{"thread_snapshot_error",GetLastError()}});
    else {
        THREADENTRY32 entry{};entry.dwSize=sizeof(entry);
        if(Thread32First(threads.h,&entry)) {
            do {if(ids.count(entry.th32OwnerProcessID))thread_entries.push_back(entry);}while(Thread32Next(threads.h,&entry));
            if(GetLastError()!=ERROR_NO_MORE_FILES)result["errors"].push_back({{"thread_enumeration_error",GetLastError()}});
        } else result["errors"].push_back({{"thread_enumeration_error",GetLastError()}});
    }
    struct WaitSession {HWCT h=OpenThreadWaitChainSession(0,nullptr);~WaitSession(){if(h)CloseThreadWaitChainSession(h);}} waits;
    if(!waits.h)result["errors"].push_back({{"wait_chain_session_error",GetLastError()}});
    for(auto id:ids) {
        Json process={{"pid",id},{"windows",Json::array()},{"threads",Json::array()}};
        for(const auto& entry:thread_entries)if(entry.th32OwnerProcessID==id) {
            Json t={{"tid",entry.th32ThreadID},{"wait_chain",Json::array()}};
            if(waits.h) {
                std::array<WAITCHAIN_NODE_INFO,WCT_MAX_NODE_COUNT> nodes{};DWORD count=WCT_MAX_NODE_COUNT;BOOL cycle=FALSE;
                // Read-only inspection; do not enable debug privileges or change another process.
                if(GetThreadWaitChain(waits.h,0,WCT_OUT_OF_PROC_FLAG,entry.th32ThreadID,&count,nodes.data(),&cycle)) {
                    t["cycle_detected"]=cycle!=FALSE;
                    for(DWORD i=0;i<(std::min)(count,DWORD(WCT_MAX_NODE_COUNT));++i) {
                        const auto& n=nodes[i];Json node={{"object_type",int(n.ObjectType)},{"object_status",int(n.ObjectStatus)}};
                        switch(n.ObjectStatus) {
                            case WctStatusNoAccess: node["status"]="access_denied";break;
                            case WctStatusRunning: node["status"]="running";break;
                            case WctStatusBlocked: node["status"]="blocked";break;
                            case WctStatusOwned: node["status"]="owned";break;
                            case WctStatusNotOwned: node["status"]="not_owned";break;
                            default: node["status"]="other";break;
                        }
                        if(n.ObjectType==WctThreadType) {
                            node["type"]="thread";node["pid"]=n.ThreadObject.ProcessId;node["tid"]=n.ThreadObject.ThreadId;
                            for(const auto& image:entries)if(image.th32ProcessID==n.ThreadObject.ProcessId){node["image_name"]=utf8(image.szExeFile);break;}
                        }
                        else if(n.ObjectType==WctSendMessageType)node["type"]="send_message";
                        else if(n.ObjectType==WctMutexType)node["type"]="mutex";
                        else if(n.ObjectType==WctCriticalSectionType)node["type"]="critical_section";
                        else if(n.ObjectType==WctProcessWaitType)node["type"]="process_wait";
                        // Omit object names: they can contain user-specific information.
                        t["wait_chain"].push_back(node);
                    }
                } else {
                    auto error=GetLastError();t["wait_chain_error"]=error;
                    if(error==ERROR_ACCESS_DENIED)t["note"]="Cannot inspect this thread at current privileges; an administrator can rerun doctor --pid. No privilege is enabled automatically.";
                }
            }
            process["threads"].push_back(t);
        }
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
                RECT rect{};bool has_rect=GetWindowRect(window,&rect)!=0;auto rect_error=has_rect?ERROR_SUCCESS:GetLastError();
                DWORD_PTR response=0;SetLastError(ERROR_SUCCESS);
                bool responsive=SendMessageTimeoutW(window,WM_NULL,0,0,SMTO_ABORTIFHUNG|SMTO_BLOCK,100,&response)!=0;
                auto probe_error=responsive?ERROR_SUCCESS:GetLastError();
                Json w={{"visible",IsWindowVisible(window)!=FALSE},{"responsive_probe",responsive},{"probe_error",probe_error}};
                if(has_rect)w["rectangle"]={rect.left,rect.top,rect.right,rect.bottom};
                else w["rectangle_error"]=rect_error;
                w["minimized"]=IsIconic(window)!=FALSE;w["maximized"]=IsZoomed(window)!=FALSE;
                RECT client{};
                if(GetClientRect(window,&client))w["client_rectangle"]={client.left,client.top,client.right,client.bottom};
                else w["client_rectangle_error"]=GetLastError();
                auto dpi=GetDpiForWindow(window);if(dpi)w["window_dpi"]=dpi;else w["window_dpi_error"]=GetLastError();
                auto awareness=GetAwarenessFromDpiAwarenessContext(GetWindowDpiAwarenessContext(window));
                w["dpi_awareness"]=awareness==DPI_AWARENESS_UNAWARE?"unaware":awareness==DPI_AWARENESS_SYSTEM_AWARE?"system":awareness==DPI_AWARENESS_PER_MONITOR_AWARE?"per_monitor":"unknown";
                SetLastError(ERROR_SUCCESS);auto style=GetWindowLongPtrW(window,GWL_STYLE);auto style_error=GetLastError();
                if(style||!style_error) {w["resizable_border"]=(style&WS_THICKFRAME)!=0;w["maximize_box"]=(style&WS_MAXIMIZEBOX)!=0;}
                else w["style_error"]=style_error;
                auto monitor=MonitorFromWindow(window,MONITOR_DEFAULTTONEAREST);
                MONITORINFO mi{};mi.cbSize=sizeof(mi);
                if(monitor&&GetMonitorInfoW(monitor,&mi)) {
                    w["monitor_rectangle"]={mi.rcMonitor.left,mi.rcMonitor.top,mi.rcMonitor.right,mi.rcMonitor.bottom};
                    w["monitor_work_area"]={mi.rcWork.left,mi.rcWork.top,mi.rcWork.right,mi.rcWork.bottom};
                    w["monitor_primary"]=(mi.dwFlags&MONITORINFOF_PRIMARY)!=0;
                    DEVICE_SCALE_FACTOR factor{};auto status=GetScaleFactorForMonitor(monitor,&factor);
                    if(SUCCEEDED(status))w["monitor_scale_percent"]=int(factor);else w["monitor_scale_error"]=status;
                    if(has_rect)w["covers_monitor_bounds"]=rect.left<=mi.rcMonitor.left&&rect.top<=mi.rcMonitor.top&&rect.right>=mi.rcMonitor.right&&rect.bottom>=mi.rcMonitor.bottom;
                } else w["monitor_info_error"]=GetLastError();
                // Titles deliberately omitted: installer windows can contain serial numbers.
                c.windows->push_back(w);return TRUE;
            } catch(...) {c.failed=true;return FALSE;}
        },reinterpret_cast<LPARAM>(&context));
        if(!ok || context.failed)process["window_enumeration_error"]=context.failed?ERROR_NOT_ENOUGH_MEMORY:GetLastError();
        result["processes"].push_back(process);
    }
    result["limitations"]="Snapshot descendants only; exited/reparented children may be absent. Wait chains are transient and not all waits are supported. A responsive window does not prove application functionality.";
    return result;
}
Json launch(const fs::path& executable,unsigned timeout_ms,bool elevate) {
    auto path=fs::absolute(executable);auto binary=analyze(path);auto a=binary["analysis"];
    if(!a.value("valid",false) || (a.value("architecture","")!="x86" && a.value("architecture","")!="x64") ||
       (a.value("format","")!="PE32" && a.value("format","")!="PE32+") || a.value("is_dll",false))throw std::runtime_error("Only valid x86/x64 PE applications may be launched");
    Json result={{"schema_version",1},{"executable",binary},{"host",host_info()},{"process_created",false},
        {"elevation_requested",elevate},{"working_directory",path_text(path.parent_path())},{"compatibility","NOT TESTED"}};
    Handle process,thread;DWORD pid=0;DWORD error=0;
    if(elevate) {
        auto directory=path.parent_path().wstring();SHELLEXECUTEINFOW info{};info.cbSize=sizeof(info);
        info.fMask=SEE_MASK_NOCLOSEPROCESS|SEE_MASK_NOASYNC|SEE_MASK_FLAG_NO_UI;info.lpVerb=L"runas";
        info.lpFile=path.c_str();info.lpDirectory=directory.c_str();info.nShow=SW_SHOWNORMAL;
        if(!ShellExecuteExW(&info))error=GetLastError();else {process.h=info.hProcess;if(process.h)pid=GetProcessId(process.h);else error=ERROR_INVALID_HANDLE;}
    } else {
        std::wstring command=L"\""+path.wstring()+L"\"";
        STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION info{};
        if(!CreateProcessW(path.c_str(),command.data(),nullptr,nullptr,FALSE,0,nullptr,path.parent_path().c_str(),&startup,&info))error=GetLastError();
        else {process.h=info.hProcess;thread.h=info.hThread;pid=info.dwProcessId;}
    }
    if(error) {result["launch_error"]=error;result["elevation_required"]=error==ERROR_ELEVATION_REQUIRED;result["cancelled"]=error==ERROR_CANCELLED;return result;}
    if(!pid) {result["launch_error"]=GetLastError();return result;}
    auto wait=WaitForSingleObject(process.h,timeout_ms);
    result["pid"]=pid;result["process_created"]=true;result["observation_ms"]=timeout_ms;
    result["observation_elapsed_while_running"]=wait==WAIT_TIMEOUT;
    if(wait==WAIT_FAILED)result["wait_error"]=GetLastError();
    DWORD code=0;if(GetExitCodeProcess(process.h,&code))result["exit_code"]=wait==WAIT_OBJECT_0?Json(code):Json(nullptr);else result["exit_code_error"]=GetLastError();
    result["snapshot"]=observe(pid);
    result["note"]="Processes are never terminated when observation ends; elapsed observation is not a crash or proof of GUI initialization.";
    return result;
}
}
