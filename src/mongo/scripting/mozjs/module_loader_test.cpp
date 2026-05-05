/**
 *    Copyright (C) 2022-present MongoDB, Inc.
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

#include <boost/filesystem.hpp>

#include "mongo/scripting/engine.h"
#include "mongo/scripting/mozjs/implscope.h"
#include "mongo/unittest/unittest.h"

namespace mongo {
namespace mozjs {

// Fixture ensures the global ScriptEngine is explicitly destroyed after each test rather than
// during global-destructor time. Without this, the engine's destructor calls JS_ShutDown() after
// libmozjs.so has already torn down its internal helper-thread mutex, causing EINVAL from
// pthread_mutex_lock and a subsequent crash when linking dynamically.
class ModuleLoaderTest : public unittest::Test {
protected:
    void setUp() override {
        mongo::ScriptEngine::setup();
    }

    void tearDown() override {
        setGlobalScriptEngine(nullptr);
    }
};

TEST_F(ModuleLoaderTest, ImportBaseSpecifierFails) {
    std::unique_ptr<mongo::Scope> scope(mongo::getGlobalScriptEngine()->newScope());

    auto code = "import * as test from \"base_specifier\""_sd;
    ASSERT_THROWS_WITH_CHECK(
        scope->exec(code,
                    "root_module",
                    true /* printResult */,
                    true /* reportError */,
                    true /* assertOnError , timeout*/),
        DBException,
        [&](const auto& ex) { ASSERT_STRING_CONTAINS(ex.what(), "Cannot find module"); });
}

#if !defined(_WIN32)
TEST_F(ModuleLoaderTest, ImportDirectoryFails) {
    std::unique_ptr<mongo::Scope> scope(mongo::getGlobalScriptEngine()->newScope());

    auto code = fmt::format("import * as test from \"{}\"",
                            boost::filesystem::temp_directory_path().string());
    ASSERT_THROWS_WITH_CHECK(
        scope->exec(code,
                    "root_module",
                    true /* printResult */,
                    true /* reportError */,
                    true /* assertOnError , timeout*/),
        DBException,
        [&](const auto& ex) { ASSERT_STRING_CONTAINS(ex.what(), "Directory import"); });
}
#endif

TEST_F(ModuleLoaderTest, ImportInInteractiveFails) {
    std::unique_ptr<mongo::Scope> scope(mongo::getGlobalScriptEngine()->newScope());

    auto code = "import * as test from \"some_module\""_sd;
    ASSERT_THROWS_WITH_CHECK(
        scope->exec(code,
                    MozJSImplScope::kInteractiveShellName,
                    true /* printResult */,
                    true /* reportError */,
                    true /* assertOnError , timeout*/),
        DBException,
        [&](const auto& ex) {
            ASSERT_STRING_CONTAINS(ex.what(),
                                   "import declarations may only appear at top level of a module");
        });
}

TEST_F(ModuleLoaderTest, TopLevelAwaitWorks) {
    std::unique_ptr<mongo::Scope> scope(mongo::getGlobalScriptEngine()->newScope());
    auto code = "async function test() { return 42; } await test();"_sd;
    ASSERT_DOES_NOT_THROW(scope->exec(code,
                                      "root_module",
                                      true /* printResult */,
                                      true /* reportError */,
                                      true /* assertOnError , timeout*/));
}

}  // namespace mozjs
}  // namespace mongo
