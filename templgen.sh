#!/usr/bin/env sh

set -eu

templ_version="$(go list -m -f '{{.Version}}' github.com/a-h/templ)"

# install the templ CLI version that matches go.mod
echo "installing templ ${templ_version} via go install..."
go install "github.com/a-h/templ/cmd/templ@${templ_version}"

# generate templ docs
templ generate
