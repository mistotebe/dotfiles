eavesdrop() {
    local host="$1"
    shift
    ssh "$host" tcpdump -U -s 0 -w - "$@" | wireshark -i- -k
}
