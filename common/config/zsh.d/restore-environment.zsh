if test -s "$HOME/.gnupg/gpg-agent-info-$(hostname)"; then
    BACKUP_SSH_AUTH_SOCK="$SSH_AUTH_SOCK"
    source "$HOME/.gnupg/gpg-agent-info-$(hostname)"

    # we may have a forwarded agent from an ssh connection, use that
    if [ -n "$BACKUP_SSH_AUTH_SOCK" -a -S "$BACKUP_SSH_AUTH_SOCK" ]; then
        SSH_AUTH_SOCK="$BACKUP_SSH_AUTH_SOCK"
    fi
    unset BACKUP_SSH_AUTH_SOCK
fi
GPG_TTY=`tty`

export GPG_AGENT_INFO SSH_AUTH_SOCK SSH_AGENT_PID GPG_TTY

echo UPDATESTARTUPTTY | gpg-connect-agent >/dev/null 2>&1

if [ ! -r "$XAUTHORITY" ]; then
    #export XAUTHORITY=$(find /tmp/ -path "/tmp/.gdm*" -user $(whoami) -print -quit 2>/dev/null)
    export XAUTHORITY="/run/user/$(id -u)/gdm/Xauthority"
fi

# if DBUS_SESSION_BUS_ADDRESS is invalid, update
if [ -n "$DBUS_SESSION_BUS_ADDRESS" ] && [ -x /usr/bin/socat ] && ! socat ABSTRACT-CONNECT:$(echo $DBUS_SESSION_BUS_ADDRESS | grep -P -o "(?<==).*(?=,)") STDIN </dev/null 2>/dev/null; then
    for pid in $(pgrep -u $(whoami) dbus-daemon); do
        DBUS_SESSION_BUS_ADDRESS=$(stealEnvironment "$pid" DBUS_SESSION_BUS_ADDRESS)
        if [ -n "$DBUS_SESSION_BUS_ADDRESS" ]; then
            break
        fi
    done
    unset pid
    export DBUS_SESSION_BUS_ADDRESS
fi
