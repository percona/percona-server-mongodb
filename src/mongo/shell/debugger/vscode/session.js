/**
 * MongoDB Shell JS Debug Session
 *
 * Implements the Debug Adapter Protocol for debugging JavaScript in MongoDB Shell.
 *   https://microsoft.github.io/debug-adapter-protocol/overview
 */

const {
    DebugSession,
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
    }

    // Attach - start a debug server, listening for a mongo shell to attach to
    async attachRequest(response, args) {
        try {
            await this.startDebugServer(args.debugPort || 9229);
            this.log(`Waiting for mongo shell to connect on port ${args.debugPort || 9229}...\n`);
            this.log("Use resmoke's --shellJSDebugMode flag when running a JS test file to stop on breakpoints.\n");
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
                this.log(`Debug server listening on port ${port}\n`);
                resolve();
            });

            this.debugServer.on("error", reject);
        });
    }

    // Set up message handling for debug protocol
    setupDebugConnection() {
        this.debugConnection.on("data", (_data) => {
            // TODO
        });

        this.debugConnection.on("end", () => {
            this.connected = false;
        });
    }

    // Helper to send output to debug console
    log(text, category = "stdout") {
        this.sendEvent(new OutputEvent(text, category));
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
}

module.exports = {MongoShellDebugSession};
