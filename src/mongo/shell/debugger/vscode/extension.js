/**
 * VSCode Extension for MongoDB Shell Debugger
 *
 * Registers the 'mongo-shell' debug type and provides configuration.
 */

const vscode = require("vscode");
const path = require("path");

// Extension entry point
function activate(context) {
    // Register debug config provider
    context.subscriptions.push(
        vscode.debug.registerDebugConfigurationProvider("mongo-shell", {
            provideDebugConfigurations,
        }),
    );

    // Register debug adapter factory
    context.subscriptions.push(
        vscode.debug.registerDebugAdapterDescriptorFactory("mongo-shell", {
            createDebugAdapterDescriptor: (session) => createDebugAdapter(context, session),
        }),
    );
}

function deactivate() {}

function provideDebugConfigurations(_folder) {
    return [
        {
            type: "mongo-shell",
            request: "attach",
            name: "Attach to MongoDB Shell",
            debugPort: 9229,
        },
    ];
}

function createDebugAdapter(context, _session) {
    const adapterPath = path.join(context.extensionPath, "adapter.js");
    return new vscode.DebugAdapterExecutable("node", [adapterPath]);
}

module.exports = {activate, deactivate};
