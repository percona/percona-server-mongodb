/**
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

#include "mongo/shell/debugger/adapter.h"

#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/bson/json.h"
#include "mongo/bson/oid.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace mongo {
namespace mozjs {

// Network state
int _clientSocket = -1;
AtomicWord<bool> _running{false};
std::unique_ptr<std::thread> _messageThread;


Request Request::fromJSON(std::string line) {
    BSONObj obj = fromjson(line);

    Request msg;
    msg.seq = obj.getIntField("seq");
    msg.command = std::string(toStdStringViewForInterop(obj.getStringField("command")));
    msg.arguments = obj.getObjectField("arguments");

    return msg;
}


SetBreakpointsRequest SetBreakpointsRequest::fromRequest(Request request) {
    SetBreakpointsRequest req;
    req.seq = request.seq;

    // Get source from arguments
    req.source = std::string(toStdStringViewForInterop(request.arguments.getStringField("source")));

    // Get lines array from arguments and extract line numbers
    std::vector<BSONElement> linesArr = request.arguments.getField("lines").Array();
    for (const auto& lineElem : linesArr) {
        BSONObj lineObj = lineElem.Obj();
        int lineNum = lineObj.getIntField("line");
        req.lines.push_back(lineNum);
    }

    return req;
}

SetBreakpointsResponse SetBreakpointsResponse::fromRequest(SetBreakpointsRequest request) {
    SetBreakpointsResponse response;
    response.request = request;
    response.seq = request.seq;
    return response;
}

void SetBreakpointsResponse::send() {
    // STUB response, simply match on "seq"
    DebugAdapter::sendMessage("{\"type\":\"response\",\"seq\":" + std::to_string(seq) +
                              ",\"body\":{\"breakpoints\":[{\"id\":\"1\","
                              "\"verified\":true,\"line\":\"12\","
                              "\"column\":\"0\"}]}}");
}

void DebugAdapter::handleRequest(const Request& request) {
    // Dispatch based on command
    // std::cout << "Handling message: " << msg.raw_json << std::endl;
    if (request.command == "setBreakpoints") {
        SetBreakpointsRequest req = SetBreakpointsRequest::fromRequest(request);
        DebugAdapter::handleSetBreakpoints(req);
    }
}

void DebugAdapter::handleSetBreakpoints(SetBreakpointsRequest request) {
    // TODO: actually set the breakpoints in the underlying scripts

    SetBreakpointsResponse response = SetBreakpointsResponse::fromRequest(request);
    response.send();
}

void DebugAdapter::sendMessage(std::string json) {
    if (_clientSocket < 0)
        return;
    send(_clientSocket, json.c_str(), json.length(), 0);
}

void DebugAdapter::handleMessagesThread() {
    char buffer[4096];
    std::string msgBuffer;

    while (_running.load() && _clientSocket >= 0) {
        ssize_t n = recv(_clientSocket, buffer, sizeof(buffer), 0);
        if (n <= 0) {
            break;  // Connection closed or error
        }

        msgBuffer.append(buffer, n);

        // Process complete messages (newline-delimited JSON)
        size_t pos;
        while ((pos = msgBuffer.find('\n')) != std::string::npos) {
            std::string line = msgBuffer.substr(0, pos);
            msgBuffer.erase(0, pos + 1);

            if (!line.empty()) {
                // Parse and handle message
                Request req;
                try {
                    req = Request::fromJSON(line);
                } catch (const std::exception& e) {
                    std::cout << "[ERROR] Failed to parse JSON: " << e.what() << "\nLine: " << line
                              << std::endl;
                }
                handleRequest(req);
            }
        }
    }

    DebugAdapter::disconnect();
}


Status DebugAdapter::connect() {

    // Create CLIENT socket (connecting to debug adapter)
    _clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (_clientSocket < 0) {
        return Status(ErrorCodes::JSInterpreterFailure, "Failed to create client socket");
    }

    // Set up address to connect to debug adapter client
    int port = 9229;
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);


    if (::connect(_clientSocket, (sockaddr*)&addr, sizeof(addr)) == 0) {
        std::cout << "Shell connected to debug adapter client on port " << port << std::endl;
        _running.store(true);
        _messageThread = std::make_unique<std::thread>(handleMessagesThread);
    }

    return Status::OK();
}


void DebugAdapter::disconnect() {
    if (_clientSocket >= 0) {
        close(_clientSocket);
        _clientSocket = -1;
    }
}

}  // namespace mozjs
}  // namespace mongo
