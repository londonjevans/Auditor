#!/bin/sh
# Synthetic version-only regression control. No chain, listener, funds or target execution.
if [ "$#" -eq 1 ] && [ "$1" = "--version" ]; then
    printf '%s\n' 'anvil Version: mmaudit-synthetic-control'
    exit 0
fi
exit 90
