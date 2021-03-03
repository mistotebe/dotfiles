# various utility functions

cgrep () {
    grep "$@" --color=always | LESS=FRSX pager
    return $pipestatus[1]
}
compdef cgrep=grep

vgrep() {
    vim -q <(grep -I -n "$@")
}
compdef vgrep=grep

stealEnvironment() {
    grep -z "^$2=" "/proc/$1/environ" | cut -f2- -d=
}

stealParentEnvironment() {
    stealEnvironment $PPID "$1"
}

refreshTmuxEnvironment() {
    local env="$(tmux show-environment | grep -v "^-" | sed -e "s/'/\\\'/g" -e "s/=\(.*\)/=\$'\1'/")"
    eval "$env"
    local -a vars
    vars=( $(tmux show-environment | grep -v "^-" | sed -e "s/=.*//") )
    [ "${#vars[@]}" -gt 0 ] && export "${vars[@]}"
}

argv0dup() {
    "$1" "$@"
}

libtool() {
    if !git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        "$@"
        return $?
    fi

    local worktree=$(git rev-parse --show-toplevel)
    if [ -x "${worktree}"/libtool ]; then
        "${worktree}"/libtool --mode=execute "$@"
        return $?
    fi

    return 127
}
