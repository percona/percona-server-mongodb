/**
 * MongoDB Shell JS Debug Session
 *
 * Implements the Debug Adapter Protocol for debugging JavaScript in MongoDB Shell.
 *   https://microsoft.github.io/debug-adapter-protocol/overview
 */

const {
    Breakpoint,
    BreakpointEvent,
    DebugSession,
    InitializedEvent,
    OutputEvent,
    // https://github.com/microsoft/vscode-debugadapter-node/tree/main/adapter
} = require("vscode-debugadapter");
const net = require("net");

class MongoShellDebugSession extends DebugSession {
    constructor() {
        super();
        this.setDebuggerLinesStartAt1(true);
        this.setDebuggerColumnsStartAt1(true);

        // State
        this.debugConnection = null;
        this.debugServer = null;
        this.connected = false;

        // Handles for variables
        this.breakpoints = new Map();

        // Request tracking
        this.messageSeq = 1;
        this.pendingRequests = new Map();
    }

    // Initialize - tell VSCode what we support
    initializeRequest(response, _args) {
        response.body = {
            supportsConfigurationDoneRequest: true,
            supportsEvaluateForHovers: true,
            supportsSetVariable: true,
            supportsConditionalBreakpoints: true,
            supportsLogPoints: true,
            supportsBreakpointLocationsRequest: true,
            supportsTerminateRequest: true,
        };
        this.sendResponse(response);
        this.sendEvent(new InitializedEvent());
    }

    // Attach - start a debug server, listening for a mongo shell to attach to
    async attachRequest(response, args) {
        try {
            await this.startDebugServer(args.debugPort || 9229);
            this.log(`Waiting for mongo shell to connect on port ${args.debugPort || 9229}...`);
            this.log("Use resmoke's --shellJSDebugMode flag when running a JS test file to stop on breakpoints.");
            this.sendResponse(response);
        } catch (err) {
            this.sendErrorResponse(response, 1000, `Failed to attach: ${err.message}`);
        }
    }

    // Start TCP server to accept connections from mongo shell
    startDebugServer(port) {
        return new Promise((resolve, reject) => {
            this.debugServer = net.createServer((socket) => {
                this.debugConnection = socket;
                this.connected = true;
                this.setupDebugConnection();
            });

            this.debugServer.listen(port, "localhost", () => {
                this.log(`Debug server listening on port ${port}`);
                resolve();
            });

            this.debugServer.on("error", reject);
        });
    }

    // Set up message handling for debug protocol
    setupDebugConnection() {
        this.debugConnection.on("data", (data) => {
            let line = data.toString();
            if (!line.trim()) return;

            this.log(`Received message: ${line}`);
            try {
                const msg = JSON.parse(line);
                this.handleDebugMessage(msg);
            } catch (err) {
                this.log(`Failed to parse: ${line}`, "stderr");
                this.log(err);
            }
        });

        this.debugConnection.on("end", () => {
            this.connected = false;
        });

        // Send any queued breakpoints from before connection (attach mode)
        this.sendQueuedBreakpoints();
    }

    // Helper to send output to debug console
    log(text, category = "stdout") {
        this.sendEvent(new OutputEvent(text + "\n", category));
    }

    disconnectRequest(response, _args) {
        this.cleanup();
        this.sendResponse(response);
    }

    // Clean up resources
    cleanup() {
        if (this.debugConnection) {
            this.debugConnection.end();
            this.debugConnection = null;
        }

        if (this.debugServer) {
            this.debugServer.close();
            this.debugServer = null;
        }

        this.connected = false;
    }

    // Set breakpoints
    setBreakPointsRequest(response, args) {
        const filePath = args.source.path;
        const lines = (args.breakpoints || []).map((bp) => ({
            line: bp.line,
            condition: bp.condition,
            logMessage: bp.logMessage,
        }));

        // If not connected yet (attach mode), return unverified breakpoints
        // They will be sent to the shell once it connects
        if (!this.connected) {
            const bps = lines.map((bp) => {
                const breakpoint = new Breakpoint(false, bp.line, 0);
                return breakpoint;
            });

            this.breakpoints.set(filePath, {lines, unverified: bps});
            response.body = {breakpoints: bps};
            this.sendResponse(response);
            return;
        }

        // Connected - send to shell
        this.sendCommand("setBreakpoints", {source: filePath, lines})
            .then((result) => {
                const bps = result.breakpoints.map((bp) => {
                    const breakpoint = new Breakpoint(bp.verified, bp.line, bp.column);
                    breakpoint.id = bp.id;
                    return breakpoint;
                });

                this.breakpoints.set(filePath, bps);
                response.body = {breakpoints: bps};
                this.sendResponse(response);
            })
            .catch((err) => {
                this.sendErrorResponse(response, 1002, `Failed to set breakpoints: ${err.message}`);
            });
    }

    // Send breakpoints that were set before shell connected
    sendQueuedBreakpoints() {
        for (const [filePath, value] of this.breakpoints.entries()) {
            // Check if these are unverified (queued) breakpoints
            if (value.lines && value.unverified) {
                this.log(
                    `Sending queued breakpoints for ${filePath}, lines ${value.lines.map((l) => l.line).join(", ")}`,
                );
                this.sendCommand("setBreakpoints", {source: filePath, lines: value.lines})
                    .then((result) => {
                        const bps = result.breakpoints.map((bp) => {
                            const breakpoint = new Breakpoint(bp.verified, bp.line, bp.column);
                            breakpoint.id = bp.id;
                            return breakpoint;
                        });

                        // Update stored breakpoints
                        this.breakpoints.set(filePath, bps);

                        // Send breakpoint changed events for each one
                        bps.forEach((bp) => {
                            this.sendEvent(new BreakpointEvent("changed", bp));
                        });
                    })
                    .catch((err) => {
                        this.log(`Failed to set queued breakpoints: ${err.message}`, "stderr");
                    });
            }
        }
    }
    // Handle incoming messages from debug server
    handleDebugMessage(msg) {
        if (msg.type === "event") {
            this.handleEvent(msg);
        } else if (msg.type === "response" && msg.seq) {
            const resolver = this.pendingRequests.get(msg.seq);
            if (resolver) {
                this.log(`Resolving pending request for seq ${msg.seq}`);
                resolver(msg.body);
                this.pendingRequests.delete(msg.seq);
            }
        }
    }

    // Send command to debug server
    sendCommand(command, args) {
        return new Promise((resolve, reject) => {
            if (!this.connected || !this.debugConnection) {
                return reject(new Error("Not connected"));
            }

            const seq = this.messageSeq++;
            this.pendingRequests.set(seq, resolve);

            const msg =
                JSON.stringify({
                    type: "request",
                    seq,
                    command,
                    arguments: args,
                }) + "\n";

            this.debugConnection.write(msg, (err) => {
                if (err) {
                    this.pendingRequests.delete(seq);
                    reject(err);
                }
            });

            // Timeout after 5 seconds
            setTimeout(() => {
                if (this.pendingRequests.has(seq)) {
                    this.pendingRequests.delete(seq);
                    reject(new Error("Command timeout"));
                }
            }, 5_000);
        });
    }
}

module.exports = {MongoShellDebugSession};
