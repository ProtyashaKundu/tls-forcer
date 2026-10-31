//Acknowledgement: Swarnadeep Saha.

// ==========================================================================
// FILE: json.hpp                             LAYER: utility (header-only)
//
// WHAT THIS FILE DOES
//   A tiny JSON writer, just enough to build the dashboard API responses
//   without an external library. Values are written as strings and
//   combined, so objects and arrays nest naturally. All functions are
//   `inline` so the header can be included from several .cpp files.
//
// NAMESPACE
//   tlsf::json   Kept separate so short names like str() and obj() don't
//                clash with the rest of the project.
//
// FUNCTIONS
//   str(s)          JSON string with escaping: quote, backslash, newline,
//                   CR, tab, and other control characters as
//                   a 4-digit unicode escape code.
//   num(double)     Number with two decimals (timings).
//   num(long long)  Whole number.
//   boolean(b)      true / false.
//   arr(items)      Join already-encoded items into [a,b,c].
//   arr(v, f)       Template: encode each element of v with f, then arr().
//   strs(v)         Array of escaped strings.
//   obj({{k, v}, ...})
//                   Object {"k":v,...} from (key, already-encoded value) pairs.
//   Field           Alias for std::pair<std::string, std::string> (key, value).
// ==========================================================================

#pragma once
#include <cstdio>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

namespace tlsf::json
{

	inline std::string str(const std::string& s)
	{
	    std::string o = "\"";
	    for (unsigned char c : s) {
		  switch (c) {
		      case '"': o += "\\\""; break;
		      case '\\': o += "\\\\"; break;
		      case '\n': o += "\\n"; break;
		      case '\r': o += "\\r"; break;
		      case '\t': o += "\\t"; break;
		      default:
		          if (c < 0x20)
		          {
		              char b[8];
		              std::snprintf(b, sizeof b, "\\u%04x", c);
		              o += b;
		          }
		          else
		          {
		              o += static_cast<char>(c);
		          }
		  }
	    }
	    return o + "\"";
	}

	inline std::string num(double v)
	{
	    char b[32];
	    std::snprintf(b, sizeof b, "%.2f", v);
	    return b;
	}
	inline std::string num(long long v)
	{
		return std::to_string(v);
	}
	inline std::string boolean(bool b)
	{
		return b ? "true" : "false";
	}

	inline std::string arr(const std::vector<std::string>& items)
	{
	    std::string o = "[";
	    for (size_t i = 0; i < items.size(); ++i)
	    	o += (i ? "," : "") + items[i];
	    return o + "]";
	}

	template <class T, class F>
	std::string arr(const std::vector<T>& v, F f)
	{
	    std::vector<std::string> items;
	    for (const auto& x : v) items.push_back(f(x));
	    return arr(items);
	}

	inline std::string strs(const std::vector<std::string>& v)
	{
	    return arr(v, [](const std::string& s) { return str(s); });
	}

	using Field = std::pair<std::string, std::string>;
	inline std::string obj(std::initializer_list<Field> fields)
	{
	    std::string o = "{";
	    bool first = true;
	    for (const auto& f : fields)
	    {
		  o += (first ? "" : ",") + str(f.first) + ":" + f.second;
		  first = false;
	    }
	    return o + "}";
	}

}
