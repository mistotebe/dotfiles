mountpoint() {
    local dir="$(readlink -f "$1")"
    #[ -n "$(comm -12 <(print '/home/oku/remote') <(cut -d' ' -f5 </proc/self/mountinfo | sort -u))" ]
    local mountpoint mountpoints="$(cut -d' ' -f5 </proc/self/mountinfo | sort -u)"
    mountpoints=("${(f)mountpoints}")
    for mountpoint in "${mountpoints[@]}"; do
        test "$dir" = "${(g::)mountpoint}" && return 0
    done
    return 1
}

chroot() {
    local chroot="$1"
    local -a shares

    if [ ! -d "$1" ]; then
        echo "Cannot chroot, '$1' does not exist"
        return 1
    fi

    shares=( "repos" )
    for m in "${shares[@]}"; do
        local mountpoint="$chroot/mnt/$m"
        sudo mkdir -p "$mountpoint" || return $?
        #if ! [ "$(stat -c %m "$mountpoint")" = "$(readlink -f "$mountpoint")" ] && ! test -d "$mountpoint"(F); then
        if ! mountpoint "$mountpoint"; then
            sudo mount -o bind ~/"$m" "$mountpoint" || return $?
            sudo mount -o remount,bind,ro "$mountpoint" || return $?
        fi
    done
    if grep -q / "$chroot/etc/fstab"; then
        # If there's something to mount, we need /proc
        mountpoint "$chroot/proc" || sudo mount -t proc procfs "$chroot/proc"
        sudo env SHELL=/bin/bash chroot "$chroot" mount -a
    fi
    sudo env SHELL=/bin/bash chroot "$@"
}

_unshare() {
    local file new dir template
    # must be a regular file (and we might need sudo to be able to find out)
    sudo test -f "$1" || return 1

    file="$1"
    dir=$(dirname "$file")
    template="$(basename "$file").XXXXXX"
    new=$(sudo mktemp --tmpdir="$dir" "$template") || return 1
    sudo cp -a "$file" "$new" && \
        sudo mv "$new" "$file"
}

clone() {
    [ $# -ge 2 ] || {
        echo "clone source dest <to unshare...>"
        return 1
    }

    local source="$1"
    local dest="$2"
    shift 2
    local f to_unshare
    to_unshare=( "/root/.bash_history" "$@" )

    [ -e "$dest" ] && {
        echo "Destination already exists"
        return 1
    }

    if mount | grep -q "$(readlink -f "$source")"; then
        echo "Cannot clone, source directory has things mounted:"
        mount | grep "$(readlink -f "$source")"
        return 1
    fi
    sudo cp -ral "$source" "$dest" || return 1
    for f in "${to_unshare[@]}"; do
        _unshare "$dest/$f" || {
            echo "Failed to unshare '$f', aborting"
            return 1
        }
    done
}
    
