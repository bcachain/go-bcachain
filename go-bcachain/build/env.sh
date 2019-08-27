#!/bin/sh

set -e

if [ ! -f "build/env.sh" ]; then
    echo "$0 must be run from the root of the repository."
    exit 2
fi

# Create fake Go workspace if it doesn't exist yet.
workspace="$PWD/build/_workspace"
root="$PWD"
bcachaindir="$workspace/src/github.com/bcachain"
if [ ! -L "$bcachaindir/go-bcachain" ]; then
    mkdir -p "$bcachaindir"
    cd "$bcachaindir"
    ln -s ../../../../../. go-bcachain
    cd "$root"
fi

# Set up the environment to use the workspace.
GOPATH="$workspace"
export GOPATH

# Run the command inside the workspace.
cd "$bcachaindir/go-bcachain"
PWD="$bcachaindir/go-bcachain"

# Launch the arguments with the configured environment.
exec "$@"
