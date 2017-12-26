# various utility functions

cgrep () {
    grep "$@" --color=always | LESS=FRSX pager
    return $pipestatus[1]
}

jump() {
    local host="$1"
    shift
    ssh -o ProxyCommand="ssh $host -W %h:%p" "$@"
}

vgrep() {
    vim -q <(grep -I -n "$@")
}

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
