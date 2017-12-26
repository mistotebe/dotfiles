# if $PWD no longer exists under that name, change to $PWD
# but not in /proc, to stay in the same process' env.

precmd () {
  # if under /proc/[0-9]+/, stay there no matter what
  if [[ "${PWD}" =~ '^/proc/[0-9]+(/|$)' ]]
  then
    return
  fi

  if ! [ . -ef "${PWD}" ]
  then
    OLDOLDPWD="${OLDPWD}"
    if ! cd -- "${PWD}" >/dev/null 2>&1
    then
      echo "W: ${PWD} does not exist anymore"
      return 1
    fi
    echo "W: ${PWD} recreated"
    OLDPWD="${OLDOLDPWD}"
  fi
}

