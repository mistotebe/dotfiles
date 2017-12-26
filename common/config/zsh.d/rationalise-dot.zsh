rationalise-dot() {
  if [[ $LBUFFER = . ]] || [[ $LBUFFER = *[/\ \"\']. ]]; then
    LBUFFER+=./
  else
    LBUFFER+=.
  fi
}
zle -N rationalise-dot
bindkey . rationalise-dot
