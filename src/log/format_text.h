#pragma once
// Offline formatting of nlog records: the dictionary's format string plus the
// decoded arguments, field by field with std::format. Never throws: a format
// string from a corrupt file renders the bad field as "{?}" instead.
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include "log/arg_value.h"

namespace lle::nlog {

// Appends the formatted message. Strings that were cut at 64 bytes are followed
// by "...". In `escape_controls` mode bytes < 0x20 and 0x7F inside string
// arguments are written as \n, \t, \r or \xNN so one record stays on one line.
void format_message(std::string& out, std::string_view fmt, std::span<const ArgValue> args,
                    bool escape_controls = true);

// Appends `s` as the inside of a JSON string literal (quotes not included).
// Invalid UTF-8 bytes become U+FFFD.
void append_json_escaped(std::string& out, std::string_view s);

// Appends a JSON value for one argument (numbers, true/false, strings; non-finite
// doubles as strings "nan", "inf", "-inf").
void append_json_arg(std::string& out, const ArgValue& a);

// Appends "YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ" for ns since the UNIX epoch (UTC).
void append_utc_time(std::string& out, std::int64_t unix_ns);

// Last path component of a source file name.
[[nodiscard]] std::string_view basename_of(std::string_view path) noexcept;

}  // namespace lle::nlog
