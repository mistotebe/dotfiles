#!/bin/bash
set -e

shopt -s globstar

log() {
	echo "${FUNCNAME[1]}:" "$@"
}

deploy_files() {
	local dir="$1"
	local dest="$2"
	local prefix="${3-.}"

	if ! [ -d "$dir" ]; then
		log "Skipping '$dir'"
		return
	fi
	log "Deploying '$dir'"
	pushd "$dir" >/dev/null

	for d in **/; do
		mkdir -p "$dest/$d"
	done
	for f in **/*; do
		if ! [ -e "$dest/${prefix}$f" ]; then
			log ln -s -v $(readlink -f "$f") "$dest/${prefix}$f"
		fi
	done
	popd >/dev/null
}

deploy() {
	local dir="$1"
	if ! [ -d "$dir" ]; then
		log "Skipping '$dir'"
		return
	fi
	log "Context is '$dir'"

	pushd "$dir" >/dev/null
	deploy_files bin "$HOME/bin" ""
	deploy_files config "$HOME" "."
	popd >/dev/null
}

deploy "local/$(hostname)"
deploy common
