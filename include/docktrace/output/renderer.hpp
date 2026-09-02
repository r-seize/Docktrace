#pragma once
#include <string>
#include "docktrace/model/report.hpp"

namespace docktrace::output {

enum class Format { Terminal, Json, Markdown, Html };

Format parse_format(const std::string& s);

void render(const Report& report, Format fmt, const std::string& output_path = "");

} // namespace docktrace::output
