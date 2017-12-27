#!/bin/bash
set -e

shopt -s nullglob
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
		mkdir -p "$dest/${prefix}$d"
	done
	for f in **/*; do
		if ! [ -e "$dest/${prefix}$f" ]; then
			ln -s -v $(readlink -f "$f") "$dest/${prefix}$f"
		fi
	done
	popd >/dev/null
}

sync_files() {
	local dir="$1"
	local dest="$2"
	local prefix="${3-.}"

	if ! [ -d "$dir" ]; then
		log "Skipping '$dir'"
		return
	fi
	log "Syncing '$dir'"
	pushd "$dir" >/dev/null

	for f in **/*; do
		if ! [ -h "$dest/${prefix}$f" ] \
				&& [ -f "$dest/${prefix}$f" ] \
				&& cmp -s "$f" "$dest/${prefix}$f" ; then
			ln -s -f -v $(readlink -f "$f") "$dest/${prefix}$f"
		fi
	done
	popd >/dev/null
}

run() {
	local mode="$1"
	local dir="$2"
	if ! [ -d "$dir" ]; then
		log "Skipping '$dir'"
		return
	fi
	log "Context is '$dir'"

	pushd "$dir" >/dev/null
	"${mode}_files" bin "$HOME/bin" ""
	"${mode}_files" config "$HOME" "."
	popd >/dev/null
}

run deploy "local/$(hostname)"
run deploy common

if [ "$1" = "sync" ]; then
	run sync "local/$(hostname)"
	run sync common
fi
