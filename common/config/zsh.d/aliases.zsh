# enable color support of ls and also add handy aliases
if [ "$TERM" != "dumb" ]; then
    eval "`dircolors -b`"
    alias ls='ls --color=auto'

    for grep_prefix in "" "e" "f" "r"; do
        alias "${grep_prefix}grep=${grep_prefix}grep --color=auto"
    done
    unset grep_prefix
fi

# some more ls aliases
alias ll='ls -l'
alias la='ls -A'
alias l='ls -CF'

alias go='xdg-open'
alias cal='cal -m'
alias follow='tail -n0 -f'
alias diff='diff -u'
alias ems='emacsclient -nw'
alias dquilt="quilt --quiltrc=${HOME}/.quiltrc-dpkg"
alias wcdiff="wdiff -w '`tput setaf 1`' -x '`tput sgr0`' -y '`tput setaf 2`' -z '`tput sgr0`'"
