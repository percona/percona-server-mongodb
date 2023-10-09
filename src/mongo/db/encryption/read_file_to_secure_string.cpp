/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2023-present Percona and/or its affiliates. All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the Server Side Public License, version 1,
    as published by MongoDB, Inc.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Server Side Public License for more details.

    You should have received a copy of the Server Side Public License
    along with this program. If not, see
    <http://www.mongodb.com/licensing/server-side-public-license>.

    As a special exception, the copyright holders give permission to link the
    code of portions of this program with the OpenSSL library under certain
    conditions as described in each individual source file and distribute
    linked combinations including the program with the OpenSSL library. You
    must comply with the Server Side Public License in all respects for
    all of the code used other than as permitted herein. If you modify file(s)
    with this exception, you may extend this exception to your version of the
    file(s), but you are not obligated to do so. If you do not wish to do so,
    delete this exception statement from your version. If you delete this
    exception statement from all source files in the program, then also delete
    it in the license file.
======= */

#include "mongo/db/encryption/read_file_to_secure_string.h"

#include <sys/stat.h>

#include <fstream>
#include <sstream>
#include <stdexcept>

#include "mongo/db/server_options.h"

namespace mongo::encryption::detail {
// @todo: rewrite using C++17's filesystem library
// for the MongoDB versions with C++17 enabled
SecureString readFileToSecureString(const std::string& path, const std::string& description) {
    struct stat stats;
    if (stat(path.c_str(), &stats) == -1) {
        std::ostringstream msg;
        msg << "cannot read stats of the " << description << (description.empty() ? "" : " ")
            << "file: " << path << ": " << strerror(errno);
        throw std::runtime_error(msg.str());
    }
    auto prohibited_perms{S_IRWXG | S_IRWXO};
    if (serverGlobalParams.relaxPermChecks && stats.st_uid == 0) {
        prohibited_perms = S_IWGRP | S_IXGRP | S_IRWXO;
    }
    if ((stats.st_mode & prohibited_perms) != 0) {
        std::ostringstream msg;
        msg << "permissions on " << path << " are too open";
        throw std::runtime_error(msg.str());
    }

    std::ifstream f(path);
    if (!f.is_open()) {
        std::ostringstream msg;
        msg << "cannot open specified " << description << (description.empty() ? "" : " ")
            << "file: " + path;
        throw std::runtime_error(msg.str());
    }
    SecureString data;
    f >> *data;
    return data;
}
}
