#!/usr/bin/env bash

set -e
set -u
set -x
set -o pipefail

# NOTE: if running on macOS, follow this guide https://omarkhawaja.com/cross-compiling-rust-from-macos-to-linux/
# NOTE: for ARM support, might need to install --with-aarch64 https://github.com/FiloSottile/homebrew-musl-cross
# TODO: auto-install rust compilation targets as needed

function _usage() {
    echo "usage: ${0} [-a x86_64|aarch64] [-p Linux|Darwin] [clean|build|install|release]"
    exit ${1:-1}
}

function _setup_dependencies() {
    if [[ $CURRENT_PLATFORM == "Linux" ]]; then
        if command -v apt-get &>/dev/null; then
            APT_CMD="sudo apt-get"
            if [[ $(whoami) == "root" ]]; then
                APT_CMD="apt-get"
            fi
            $APT_CMD update -y
            $APT_CMD install -y curl build-essential zip
        else
            echo "UNSUPPORTED LINUX OS, USE UBUNTU W/ APT CLI"
            exit 1
        fi
    elif [[ $CURRENT_PLATFORM == "Darwin" ]]; then
        if command -v brew &>/dev/null; then
            if ! command -v curl &>/dev/null; then
                brew update
                brew install curl
            fi
        else
            echo "INSTALL MACOS HOMEBREW"
            exit 1
        fi
    fi
    if ! command -v rustup &>/dev/null; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly
        source $HOME/.cargo/env
    fi
    if ! [[ "$(rustc --version)" =~ .*nightly.* ]]; then
        rustup toolchain install nightly
        rustup default nightly
    fi
}

function _clean() {
    cargo clean || true
    find . "${FIND_DEPTH_PARAM}" 1 -name 'ps*' -type f -perm ${FIND_PERM_PREFIX}111 -exec rm {} \; || true
    find . "${FIND_DEPTH_PARAM}" 1 -name 'fencrypt' -type f -perm ${FIND_PERM_PREFIX}111 -exec rm {} \; || true
    find . "${FIND_DEPTH_PARAM}" 1 -name '*.zip' -type f -exec rm {} \; || true
}

function _build() {
    if ! rustup target list --installed | grep "${TARGET}" &>/dev/null; then
        rustup target add "${TARGET}"
    fi
    cargo build --release --target "${TARGET}"
}

function _install() {
    [[ ! -f "./target/${TARGET}" ]] || _build
    find "./target/${TARGET}/release" "${FIND_DEPTH_PARAM}" 1 -name "ps*" -type f -perm ${FIND_PERM_PREFIX}111 -exec cp {} . \;
    find "./target/${TARGET}/release" "${FIND_DEPTH_PARAM}" 1 -name "fencrypt*" -type f -perm ${FIND_PERM_PREFIX}111 -exec cp {} . \;
}

function _release() {
    local zip_name="$(basename $(pwd) | tr ' ' '_')".zip
    [[ -f ${zip_name} ]] && rm ${zip_name}
    _build
    _install
    zip \
        -r "${zip_name}" \
        . \
        -x 'target/*' \
        -x '.idea/*' \
        -x 'Cargo.lock' \
        -x '*.iml' \
        -x '.DS_Store' \
        -x 'ps*' \
        -x 'fencrypt' \
        ''

}

ARCHITECTURE="$(uname -m)"
CURRENT_PLATFORM="$(uname)"
TARGET_PLATFORM="${CURRENT_PLATFORM}"

while getopts "a:p:h" opt; do
    case "$opt" in
        a) ARCHITECTURE=${OPTARG} ;;
        p) TARGET_PLATFORM=${OPTARG} ;;
        h) _usage; exit 0;;
        :) _usage "-${OPTARG} needs argument" ; exit 1 ;;
        \?) _usage "Unrecognized option -${OPTARG}" ; exit 1;;
    esac
done
shift $((OPTIND-1))
CMD="${1:-release}"

if [[ "${ARCHITECTURE}" != x86_64 ]]; then
    echo "Only supported architecture is currently x86_64. aarch64 coming soon!"
    _usage 1
fi

TARGET="${ARCHITECTURE}"
if [[ "${TARGET_PLATFORM}" == "Linux" ]]; then
    TARGET="${TARGET}-unknown-linux-musl"
elif [[ "${TARGET_PLATFORM}" == "Darwin" ]]; then
    TARGET="${TARGET}-apple-darwin"
else
    usage 1
fi

FIND_PERM_PREFIX="+"
FIND_DEPTH_PARAM="-depth"
if [[ "${CURRENT_PLATFORM}" == "Linux" ]]; then
    FIND_PERM_PREFIX="/"
    FIND_DEPTH_PARAM="-maxdepth"
fi

[[ -f "${HOME}/.cargo/env" ]] && source "${HOME}/.cargo/env"

# NOTE: gradescope's auto-grader runs this script from cwd of /autograder but
#       unzips files into /autograder/submission so we need to cd into that
#       subfolder for the build to work properly.
[[ -d ./submission ]] && cd ./submission

_setup_dependencies

case "${CMD}" in
    build)      _build      ;;
    clean)      _clean      ;;
    install)    _install    ;;
    release)    _release    ;;
    \?)         _usage      ;;
esac