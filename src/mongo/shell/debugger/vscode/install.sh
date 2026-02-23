#!/bin/bash

cd $MONGO_REPO
cd src/mongo/shell/debugger/vscode

npm install

# Get version from package.json
VERSION=$(node -p "require('./package.json').version")
PUBLISHER=$(node -p "require('./package.json').publisher")
EXT_NAME=$(node -p "require('./package.json').name")

# Clean up old versions of the extension
rm -rf ~/.vscode/extensions/$PUBLISHER.$EXT_NAME-*
rm -rf ~/.vscode-server/extensions/$PUBLISHER.$EXT_NAME-*

# Detect if using VS Code Remote SSH or local
if [ -d ~/.vscode-server/extensions ]; then
    EXT_DIR=~/.vscode-server/extensions/$PUBLISHER.$EXT_NAME-$VERSION
else
    EXT_DIR=~/.vscode/extensions/$PUBLISHER.$EXT_NAME-$VERSION
fi

# Create extension directory and copy all necessary files
mkdir -p $EXT_DIR

cp ./package.json $EXT_DIR/
cp ./README.md $EXT_DIR/

cp ./adapter.js $EXT_DIR/
cp ./extension.js $EXT_DIR/
cp ./session.js $EXT_DIR/

cp -r ./node_modules $EXT_DIR/

echo "Extension installed to $EXT_DIR"
echo "Restart VSCode or run 'Developer: Reload Window' to activate the extension"

cd $MONGO_REPO
