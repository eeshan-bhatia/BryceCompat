#pragma once
#include <filesystem>
#include <span>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
namespace bc {
namespace fs = std::filesystem;
using Json = nlohmann::json;
std::string utf8(std::wstring_view value);
std::string path_text(const fs::path& path);
Json inspect(std::span<const unsigned char> bytes);
std::string sha256(const fs::path& path);
Json analyze(const fs::path& path);
Json scan(const fs::path& path);
Json discover(const std::vector<fs::path>& configured);
Json observe(unsigned long pid);
Json launch(const fs::path& executable, unsigned timeout_ms);
Json host_info();
Json profile(const fs::path& path);
bool reparse(const fs::path& path);
void write_report(const fs::path& path, std::string_view data);
}
