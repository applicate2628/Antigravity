#!/bin/sh
# Installs a verified helper only into a new private content directory.
set -eu
set -f
umask 077
fail() { printf '%s\n' "install-helper: $*" >&2; exit 1; }
# Optional: --receipt-v1 SOURCE SHA-256. Accept a receipt only with exit 0
# and exactly seven NUL-terminated fields: ag-wsl-install-v1, published|reused,
# final path, directory device, directory inode, file device, file inode.
# The four identities are unsigned decimal GNU stat values. Reuse grants no
# ownership, including when another caller created the directory concurrently.
receipt=0
if [ "$#" -eq 3 ] && [ "$1" = --receipt-v1 ]; then
    receipt=1
    shift
fi
[ "$#" -eq 2 ] || fail 'expected source and SHA-256'
source_file=$1
expected=$2
case "$expected" in *[!0-9a-f]*|'') fail 'invalid SHA-256';; esac
[ "${#expected}" -eq 64 ] || fail 'invalid SHA-256 length'
[ -n "${HOME:-}" ] || fail 'HOME is missing'
case "$HOME" in /*) ;; *) fail 'HOME must be absolute';; esac
uid=$(id -u)
# Every existing ancestor must be an ordinary directory owned by root or the
# current user, with no group/other write bits.  No path component is followed
# through a symbolic link. The clean window excludes independent same-user
# namespace writers. Concurrent calls to this installer may share the namespace.
check_dir() {
    [ ! -L "$1" ] && [ -d "$1" ] || fail "unsafe directory: $1"
    owner=$(stat -c '%u' -- "$1") || fail 'stat failed'
    mode=$(stat -c '%a' -- "$1") || fail 'stat failed'
    [ "$owner" = 0 ] || [ "$owner" = "$uid" ] || fail 'foreign directory owner'
    case "$mode" in *[!0-7]*|'') fail 'invalid mode';; esac
    [ $((0$mode & 0022)) -eq 0 ] || fail 'writable shared ancestor'
}
check_dir /
oldifs=$IFS; IFS=/; set -- $HOME; IFS=$oldifs
path=''
for part do
    [ -n "$part" ] || continue
    case "$part" in .|..) fail 'invalid HOME component';; esac
    path="$path/$part"; check_dir "$path"
done
[ "$(stat -c '%u' -- "$HOME")" = "$uid" ] || fail 'HOME is not owned by current user'
path=$HOME
for part in .local share ag-unlocker wsl; do
    path="$path/$part"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        if ! mkdir -m 700 -- "$path" 2>/dev/null; then
            [ -e "$path" ] || [ -L "$path" ] || fail 'cannot create private directory'
        fi
    fi
    check_dir "$path"
    [ "$(stat -c '%u' -- "$path")" = "$uid" ] || fail 'namespace is not owned by current user'
    case "$part" in ag-unlocker|wsl) [ "$(stat -c '%a' -- "$path")" = 700 ] || fail 'namespace mode must be 700';; esac
done
destination="$path/$expected"
leaf="$destination/ag_wsl_launch"
native_identity() { stat -c '%d:%i' -- "$1"; }
verify_existing() {
    disposition=$1
    check_dir "$destination"
    [ ! -L "$leaf" ] && [ -f "$leaf" ] || fail 'existing helper is not a regular file'
    if [ "$disposition" = reused ]; then
        receipt_dir=$(native_identity "$destination") || fail 'cannot identify reused directory'
        receipt_file=$(native_identity "$leaf") || fail 'cannot identify reused helper'
    else
        receipt_dir=$stage_id
        receipt_file=$staged_file_id
    fi
    [ "$(stat -c '%u:%a' -- "$destination")" = "$uid:700" ] || fail 'foreign or unsafe destination'
    [ "$(stat -c '%u:%a:%h' -- "$leaf")" = "$uid:500:1" ] || fail 'existing helper owner, mode or links conflict'
    actual=$(sha256sum -- "$leaf") || fail 'existing helper hash failed'
    [ "${actual%% *}" = "$expected" ] || fail 'existing helper hash mismatch'
    final_dir=$(native_identity "$destination") || fail 'cannot identify final directory'
    final_file=$(native_identity "$leaf") || fail 'cannot identify final helper'
    [ "$final_dir" = "$receipt_dir" ] || fail 'directory identity changed'
    [ "$final_file" = "$receipt_file" ] || fail 'helper identity changed'
    if [ "$receipt" -eq 1 ]; then
        printf '%s\000' ag-wsl-install-v1 "$disposition" "$leaf" \
            "${final_dir%%:*}" "${final_dir#*:}" "${final_file%%:*}" "${final_file#*:}" \
            || fail 'cannot emit installation receipt'
    else
        printf '%s\n' "$leaf"
    fi
}
if [ -e "$destination" ] || [ -L "$destination" ]; then
    verify_existing reused
    exit 0
fi
stage=''
stage_id=''
staged_file=''
staged_file_id=''
remove_owned_stage() {
    [ -n "$stage" ] || return 0
    if [ ! -e "$stage" ] && [ ! -L "$stage" ]; then return 0; fi
    [ -n "$stage_id" ] && [ ! -L "$stage" ] && [ -d "$stage" ] \
        && [ "$(native_identity "$stage")" = "$stage_id" ] || return 1
    if [ -n "$staged_file" ] && { [ -e "$staged_file" ] || [ -L "$staged_file" ]; }; then
        [ -n "$staged_file_id" ] && [ ! -L "$staged_file" ] && [ -f "$staged_file" ] \
            && [ "$(native_identity "$staged_file")" = "$staged_file_id" ] \
            && [ "$(stat -c '%u:%h' -- "$staged_file")" = "$uid:1" ] || return 1
        rm -- "$staged_file" || return 1
    fi
    rmdir -- "$stage" || return 1
    stage=''
}
cleanup() {
    remove_owned_stage || printf '%s\n' "install-helper: retained staging directory $stage" >&2
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
stage=$(mktemp -d -- "$path/.helper-stage.$expected.XXXXXXXX") || fail 'cannot create private staging directory'
stage_id=$(native_identity "$stage") || fail 'cannot identify staging directory'
staged_file="$stage/ag_wsl_launch"
(set -C; : > "$staged_file") || fail 'cannot create staged helper'
staged_file_id=$(native_identity "$staged_file") || fail 'cannot identify staged helper'
cat -- "$source_file" > "$staged_file" || fail 'copy failed'
actual=$(sha256sum -- "$staged_file") || fail 'hash failed'
actual=${actual%% *}
[ "$actual" = "$expected" ] || fail 'hash mismatch'
# ELF64 little-endian, x86-64 (e_machine = 62).
magic=$(od -An -tx1 -N20 -- "$staged_file" | tr -d ' \n')
case "$magic" in 7f454c46020101??????????????????????3e00) ;; *) fail 'unsupported ELF header';; esac
chmod 500 -- "$staged_file"
[ ! -L "$stage" ] && [ -d "$stage" ] && [ "$(native_identity "$stage")" = "$stage_id" ] \
    && [ "$(stat -c '%u:%a' -- "$stage")" = "$uid:700" ] || fail 'staging directory changed'
[ ! -L "$staged_file" ] && [ -f "$staged_file" ] && [ "$(native_identity "$staged_file")" = "$staged_file_id" ] \
    && [ "$(stat -c '%u:%a:%h' -- "$staged_file")" = "$uid:500:1" ] || fail 'staged helper changed'

# Both names share the same parent. GNU mv may report a skipped move as success,
# so a successful exit alone does not establish which caller published.
move_status=0
mv -T --no-clobber -- "$stage" "$destination" || move_status=$?
if [ ! -e "$stage" ] && [ ! -L "$stage" ]; then
    [ "$move_status" -eq 0 ] || fail 'publishing the staged helper failed'
    # Once the staging name disappears, never clean up through the final name.
    trap - EXIT HUP INT TERM
    verify_existing published
else
    [ -e "$destination" ] || [ -L "$destination" ] || fail 'verified staging directory was not published'
    remove_owned_stage || fail 'cannot settle retained helper staging directory'
    trap - EXIT HUP INT TERM
    verify_existing reused
fi
