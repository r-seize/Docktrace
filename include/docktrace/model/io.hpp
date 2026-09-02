#pragma once
#include <string>
#include "docktrace/model/report.hpp"

namespace docktrace::model {

// Load a Report from a JSON file (docktrace schema v1.0).
Report load_report(const std::string& path);

// Save a Report to a JSON file.
void save_report(const Report& report, const std::string& path);

} // namespace docktrace::model
