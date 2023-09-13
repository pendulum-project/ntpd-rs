#!/usr/bin/env bash

bind_port_arg=(-p "127.0.0.1:8000:8000")
if [ "$#" -gt 0 ]; then
    if [ "$1" == "--no-bind-port" ]; then
        shift
        bind_port_arg=()
    fi
fi

exec docker run --rm "${bind_port_arg[@]}" -v "${PWD}:/docs" -u "$(id -u):$(id -g)" squidfunk/mkdocs-material "$@"
