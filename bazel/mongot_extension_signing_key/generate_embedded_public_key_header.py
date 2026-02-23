#!/usr/bin/env python3
import argparse

FILE_HEADER = """/**
*    Copyright (C) 2026-present MongoDB, Inc.
*
*    This program is free software: you can redistribute it and/or modify
*    it under the terms of the Server Side Public License, version 1,
*    as published by MongoDB, Inc.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    Server Side Public License for more details.
*
*    You should have received a copy of the Server Side Public License
*    along with this program. If not, see
*    <http://www.mongodb.com/licensing/server-side-public-license>.
*
*    As a special exception, the copyright holders give permission to link the
*    code of portions of this program with the OpenSSL library under certain
*    conditions as described in each individual source file and distribute
*    linked combinations including the program with the OpenSSL library. You
*    must comply with the Server Side Public License in all respects for
*    all of the code used other than as permitted herein. If you modify file(s)
*    with this exception, you may extend this exception to your version of the
*    file(s), but you are not obligated to do so. If you do not wish to do so,
*    delete this exception statement from your version. If you delete this
*    exception statement from all source files in the program, then also delete
*    it in the license file.
*/

// Generated file. Do not edit.
#pragma once
#include <string_view>

namespace mongo {
namespace extension{
namespace host {\n"""


FILE_FOOTER = """} // namespace host
} // namespace extension
} // namespace mongo
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--public_key_path", dest="public_key_path", required=True)
    ap.add_argument("--embedded_key_header_path", required=True)
    args = ap.parse_args()

    with open(args.public_key_path, "r") as f:
        public_key_contents = f.read()

    # Write header
    with open(args.embedded_key_header_path, "w") as h:
        h.write(FILE_HEADER)
        public_key_definition = """static constexpr std::string_view kMongoExtensionSigningPublicKey = R\"({0})\";\n""".format(
            public_key_contents
        )
        h.write(public_key_definition)
        h.write(FILE_FOOTER)


if __name__ == "__main__":
    main()
