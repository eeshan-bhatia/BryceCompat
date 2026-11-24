#include <brycecompat/core.hpp>
#include <iostream>
#include <fstream>
#include <set>
using namespace bc;
namespace {
const char* help=R"(BryceCompat 0.1 - native Windows investigation toolkit
  scan <file-or-directory> [--json] [--output <report.json>]
  detect [--media <path>] [--config <config.json>] [--json]
  doctor --installer <exe> [--run --consent] [--timeout-ms <0..60000>]
  doctor --pid <pid> [--json]
  launch --exe <exe> --consent [--timeout-ms <0..60000>] [--dry-run]
  report --profile <profile.json> [--json]
All reports can be saved with --output. Scan and doctor never execute media
unless --run --consent is supplied. Launch requires --consent. No compatibility
fixes or replacement installations are verified in this release.
Exit codes: 0 success, 2 usage/consent, 3 I/O or operation failure,
4 partial scan (unreadable/skipped entries). Compatibility remains NOT TESTED.
)";
unsigned number(const std::wstring& s,unsigned maximum) {
    if(s.empty()||s.find_first_not_of(L"0123456789")!=s.npos)throw std::invalid_argument("Expected unsigned integer");
    auto n=std::stoull(s);if(n>maximum)throw std::invalid_argument("Numeric argument out of range");return static_cast<unsigned>(n);
}
}
int wmain(int argc,wchar_t** argv) {
    try {
        if(argc<2 || std::wstring(argv[1])==L"--help") {std::cout<<help;return 0;}
        std::wstring command=argv[1];std::map<std::wstring,std::wstring> options;std::set<std::wstring> flags;std::vector<fs::path> args;
        for(int i=2;i<argc;++i) {
            std::wstring a=argv[i];
            if(a==L"--json"||a==L"--consent"||a==L"--run"||a==L"--dry-run") {if(!flags.insert(a).second)throw std::invalid_argument("Duplicate flag");}
            else if(a==L"--output"||a==L"--media"||a==L"--config"||a==L"--installer"||a==L"--pid"||a==L"--exe"||a==L"--profile"||a==L"--timeout-ms") {
                if(++i==argc)throw std::invalid_argument("Missing option value");if(!options.emplace(a,argv[i]).second)throw std::invalid_argument("Duplicate option");
            } else if(a.starts_with(L"--"))throw std::invalid_argument("Unknown option");else args.emplace_back(a);
        }
        std::set<std::wstring> allowed{L"--output"};std::set<std::wstring> permitted{L"--json"};
        if(command==L"detect") {allowed.insert(L"--media");allowed.insert(L"--config");}
        else if(command==L"doctor") {allowed.insert(L"--installer");allowed.insert(L"--pid");allowed.insert(L"--timeout-ms");permitted.insert(L"--run");permitted.insert(L"--consent");permitted.insert(L"--dry-run");}
        else if(command==L"launch") {allowed.insert(L"--exe");allowed.insert(L"--timeout-ms");permitted.insert(L"--consent");permitted.insert(L"--dry-run");}
        else if(command==L"report")allowed.insert(L"--profile");
        else if(command!=L"scan")throw std::invalid_argument("Unknown or not yet supported command; use --help");
        for(auto& [k,v]:options)if(!allowed.count(k))throw std::invalid_argument("Option does not apply to command");
        for(auto& f:flags)if(!permitted.count(f))throw std::invalid_argument("Flag does not apply to command");
        if(command!=L"scan"&&!args.empty())throw std::invalid_argument("Unexpected positional argument");
        unsigned timeout=options.count(L"--timeout-ms")?number(options.at(L"--timeout-ms"),60000):3000;
        Json report;int code=0;
        if(command==L"scan") {if(args.size()!=1)throw std::invalid_argument("scan requires one path");report=scan(args[0]);if(!report["errors"].empty())code=4;}
        else if(command==L"detect") {
            std::vector<fs::path> paths;if(options.count(L"--media"))paths.emplace_back(options.at(L"--media"));
            if(options.count(L"--config")) {
                fs::path config=options.at(L"--config");std::ifstream in(config);if(!in)throw std::runtime_error("Cannot open config");auto j=Json::parse(in);
                if(j.at("schema_version")!=1||!j.at("media_paths").is_array())throw std::invalid_argument("Invalid config schema");
                for(auto& p:j["media_paths"]) {if(!p.is_string())throw std::invalid_argument("media_paths entries must be strings");auto s=p.get<std::string>();fs::path path=std::u8string(s.begin(),s.end());paths.push_back(path.is_absolute()?path:config.parent_path()/path);}
            }
            report=discover(paths);
        } else if(command==L"report") {if(!options.count(L"--profile"))throw std::invalid_argument("report requires --profile");report=profile(options.at(L"--profile"));}
        else if(command==L"doctor"&&options.count(L"--pid")) {
            if(options.count(L"--installer")||flags.count(L"--run")||flags.count(L"--consent")||flags.count(L"--dry-run")||options.count(L"--timeout-ms"))throw std::invalid_argument("PID observation cannot be combined with launch options");
            auto pid=number(options.at(L"--pid"),0xffffffff);if(!pid)throw std::invalid_argument("PID must be positive");report=observe(pid);
        } else {
            auto key=command==L"launch"?L"--exe":L"--installer";
            if(!options.count(key))throw std::invalid_argument("Executable path is required");
            bool run=command==L"launch"||flags.count(L"--run");
            if(run&&!flags.count(L"--consent")&&!flags.count(L"--dry-run"))throw std::invalid_argument("Execution requires explicit --consent");
            if(run&&!flags.count(L"--dry-run"))report=launch(options.at(key),timeout);
            else report={{"schema_version",1},{"executable",analyze(options.at(key))},{"executed",false},{"compatibility","NOT TESTED"}};
        }
        auto serialized=report.dump(2,' ',false,Json::error_handler_t::replace)+"\n";
        if(options.count(L"--output")) {
            fs::path output=options.at(L"--output");
            write_report(output,serialized);
        }
        if(!flags.count(L"--json"))std::cout<<"BryceCompat diagnostic report (functional compatibility: NOT TESTED)\n";
        std::cout<<serialized;return code;
    } catch(const std::invalid_argument& e) {std::cerr<<e.what()<<"\n";return 2;}
    catch(const std::exception& e) {std::cerr<<e.what()<<"\n";return 3;}
}
