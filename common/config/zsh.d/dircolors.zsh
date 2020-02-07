if [ -f "$HOME/.dircolors" ]; then
    eval "$(dircolors -b "$HOME/.dircolors")"
    zstyle ':completion:*' list-colors ${(s.:.)LS_COLORS}
fi
