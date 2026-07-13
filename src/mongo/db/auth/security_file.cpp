// Copyright (c) MongoDB, Inc.
// SPDX-License-Identifier: SSPL-1.0


#include "mongo/base/error_codes.h"
#include "mongo/base/status.h"
#include "mongo/base/status_with.h"
#include "mongo/db/server_options.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/str.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <functional>
#include <iterator>
#include <string>
#include <vector>

#include <boost/move/utility_core.hpp>
#include <sys/stat.h>
#include <yaml-cpp/exceptions.h>
#include <yaml-cpp/node/detail/iterator.h>
#include <yaml-cpp/node/impl.h>
#include <yaml-cpp/node/iterator.h>
#include <yaml-cpp/node/node.h>
#include <yaml-cpp/node/parse.h>

namespace mongo {
namespace {
std::string stripString(const std::string& filename, const std::string& str) {
    std::string out;
    out.reserve(str.size());

    std::copy_if(str.begin(), str.end(), std::back_inserter(out), [&](const char ch) {
        // don't copy any whitespace
        if ((ch >= '\x09' && ch <= '\x0D') || ch == ' ') {
            return false;
            // uassert if string contains any non-base64 characters
        } else if ((ch < 'A' || ch > 'Z') && (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') &&
                   ch != '+' && ch != '/' && ch != '=') {
            uasserted(ErrorCodes::UnsupportedFormat,
                      str::stream() << "invalid char in key file " << filename << ": " << str);
        }
        return true;
    });

    return out;
}

}  // namespace

StatusWith<std::vector<std::string>> readSecurityFile(const std::string& filename) try {
    struct stat stats;

    // check obvious file errors
    if (stat(filename.c_str(), &stats) == -1) {
        return Status(ErrorCodes::InvalidPath,
                      str::stream()
                          << "Error reading file " << filename << ": " << strerror(errno));
    }

#if !defined(_WIN32)
    if (serverGlobalParams.relaxPermChecks && stats.st_uid == 0) {
        /* In case the owner is root then permission of the key file
         * can be a bit more open than for the non root users. The
         * group read is also permissible values for the file permission.
         * -rwx--r---- 740 owner read, write and execute and group read
         * bit.
         * These remaining bit should not be set for key file.
         * S_IWGRP -- Group Write.
         * S_IXGRP -- Group Execute.
         * S_IRWXO -- Read, Write and Execute for others.
         * ref: https://www.gnu.org/software/libc/manual/html_node/Permission-Bits.html
         */
        if ((stats.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO)) != 0) {
            return Status(ErrorCodes::InvalidPath,
                          str::stream() << "permissions on " << filename << " are too open");
        }
    } else {
        // Check permissions: must be X00, where X is >= 4 in case of non root owner.
        if ((stats.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
            return Status(ErrorCodes::InvalidPath,
                          str::stream() << "permissions on " << filename << " are too open");
        }
    }
#endif

    std::vector<std::string> ret;
    const std::function<void(const YAML::Node&)> visitNode = [&](const YAML::Node& node) {
        if (node.IsScalar()) {
            ret.push_back(stripString(filename, node.Scalar()));
        } else if (node.IsSequence()) {
            for (const auto& child : node) {
                visitNode(child);
            }
        } else {
            uasserted(ErrorCodes::UnsupportedFormat,
                      "Only strings and sequences are supported for YAML key files");
        }
    };

    visitNode(YAML::LoadFile(filename));

    uassert(50981,
            str::stream() << "Security key file " << filename << " does not contain any valid keys",
            !ret.empty());

    return ret;
} catch (const YAML::BadFile& e) {
    return Status(ErrorCodes::InvalidPath,
                  str::stream() << "error opening file: " << filename << ": " << e.what());
} catch (const YAML::ParserException& e) {
    return Status(ErrorCodes::UnsupportedFormat,
                  str::stream() << "error reading file: " << filename << ": " << e.what());
} catch (const DBException& e) {
    return e.toStatus();
}

}  // namespace mongo
