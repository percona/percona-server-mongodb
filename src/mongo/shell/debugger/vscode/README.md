# VSCode Extension for Debugging JS in the Mongo Shell

Install the extension:

```bash
./src/mongo/shell/debugger/vscode/install.sh
```

Add a "mongo-shell" type configuration in your `~/.vscode/launch.json` file:

```json
{
  "version": "0.1.0",
  "configurations": [
    {
      "type": "mongo-shell",
      "request": "attach",
      "name": "Attach to MongoDB Shell",
      "debugPort": 9229
    }
  ]
}
```

Restart VSCode, or use CMD+SHIFT+P and select "Developer: Reload Window".

## Usage

1. Open a .js test file in VSCode
2. Add a breakpoint next to the line number (a red dot)
3. Press F5 to start the (VSCode) debug server, ready to "attach" to a debug shell
   > You should see the following in the "Debug Console" of VSCode:
   ```
   Debug server listening on port 9229
   Waiting for mongo shell to connect on port 9229...
   Use resmoke's --shellJSDebugMode flag when running a JS test file to stop on breakpoints.
   ```
4. [TODO] Now you can run resmoke with the `--shellJSDebugMode` flag to stop on the breakpoints
