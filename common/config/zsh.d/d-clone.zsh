# Clones the git sources of a Debian package
# needs debcheckout from devscripts and gbp clone from git-buildpackage
function d-clone() {
    local package=$1
    if debcheckout --print $package >/dev/null; then
        set -- $(debcheckout --print $package)
        if [ "$1" != "git" ]; then
            echo "$package does not use git, but $1 instead."
            return
        fi

        echo "cloning $2"
        gbp clone $2 || return

        # Change to the newest git repository
        cd $(basename "$2") || return

        # This tells git to push all branches at once,
        # i.e. if you changed upstream and debian (after git-import-orig),
        # both upstream and debian will be pushed when running “git push”.
        git config push.default matching || return

        # This tells git to push tags automatically,
        # so you don’t have to use “git push; git push --tags”.
        git config --add remote.origin.push "+refs/heads/*:refs/remotes/origin/*" || return
        git config --add remote.origin.push "+refs/tags/*:refs/tags/*" || return

        echo "d-clone set up everything successfully."
    else
        echo "debcheckout $package failed. Is $package missing Vcs tags?"
    fi
}
