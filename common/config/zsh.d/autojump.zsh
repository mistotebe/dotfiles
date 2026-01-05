# autojump launches python for each command, expensive when on battery

if test -n $commands[zoxide]; then
    eval "$(zoxide init zsh)"
    alias "j=z"
elif [ -e /usr/share/autojump/autojump.zsh ]; then
    source /usr/share/autojump/autojump.zsh
fi
