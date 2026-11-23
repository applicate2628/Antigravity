#!/usr/bin/env bash
# Antigravity Unlocker - macOS Release Packager
# Packages Antigravity Unlocker.app into ZIP and, when available, DMG in dist/
set -euo pipefail

PUBLIC_DISTRIBUTION=0
for ARG in "$@"; do
    if [[ "$ARG" == "--prepare-public-app" ]]; then
        echo "--prepare-public-app is available only in macos/build_app.sh" >&2
        exit 1
    fi
    if [[ "$ARG" == "--public-distribution" ]]; then
        if [[ $# -ne 1 ]]; then
            echo "--public-distribution must be used on its own" >&2
            exit 1
        fi
        PUBLIC_DISTRIBUTION=1
        set +x
    fi
done

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

public_failure() {
    printf 'Public macOS distribution failed at %s\n' "$1" >&2
    exit 1
}

public_step() {
    local step="$1"
    shift
    "$@" >"$log_dir/$step.stdout" 2>"$log_dir/$step.stderr" || public_failure "$step"
}

public_sha256() {
    local result
    [[ -f "$1" && ! -L "$1" ]] || return 1
    result="$(/usr/bin/shasum -a 256 -- "$1" 2>/dev/null)" || return 1
    result="${result%% *}"
    [[ "$result" =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s\n' "$result"
}

public_verify_app() {
    local app="$1" phase="$2" expected="${3:-}" path key
    for path in "$app" "$app/Contents" "$app/Contents/MacOS"; do
        [[ -d "$path" && ! -L "$path" ]] || public_failure "$phase-app-layout"
    done
    for path in "$app/Contents/Info.plist" "$app/Contents/MacOS/ag_unlocker"; do
        [[ -f "$path" && ! -L "$path" ]] || public_failure "$phase-app-layout"
    done
    for key in CFBundleShortVersionString CFBundleVersion; do
        public_step "$phase-$key" /usr/libexec/PlistBuddy -c "Print :$key" "$app/Contents/Info.plist"
        [[ "$(cat "$log_dir/$phase-$key.stdout")" == "$version" ]] || public_failure "$phase-app-version"
    done
    public_step "$phase-app-signature" /usr/bin/codesign --verify --deep --strict --all-architectures \
        -R "=$app_requirement" "$app"
    if [[ -n "$expected" ]]; then
        [[ "$(public_sha256 "$app/Contents/MacOS/ag_unlocker")" == "$expected" ]] ||
            public_failure "$phase-app-executable"
    fi
}

public_notary_id() {
    /usr/bin/python3 -I -B - "$1" "${2:-}" <<'PY'
import json
import re
import sys
import uuid


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


try:
    with open(sys.argv[1], encoding="utf-8") as receipt:
        data = json.load(receipt, object_pairs_hook=unique_object)
    identifier = data.get("id") if isinstance(data, dict) else None
    if not isinstance(identifier, str) or not re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        identifier,
    ):
        raise ValueError("invalid request ID")
    parsed = uuid.UUID(identifier)
    if not parsed.int:
        raise ValueError("empty request ID")
    request_id = str(parsed)
    if sys.argv[2] and (request_id != sys.argv[2] or data.get("status") != "Accepted"):
        raise ValueError("request was not accepted")
    print(request_id)
except (OSError, ValueError):
    raise SystemExit(1)
PY
}

prepare_public_distribution() {
    : "${AG_ACCEPTED_RELEASE_RECORD:?accepted release record required}"
    : "${AG_RELEASE_SOURCE_MANIFEST:?verified release source manifest required}"
    : "${AG_RELEASE_RECORD_SHA256:?approved release record pin required}"
    : "${AG_RELEASE_SOURCE_SHA256:?approved release source pin required}"
    : "${AG_MAC_NOTARY_PROFILE:?macOS notarization keychain profile required}"
    [[ "${AG_RELEASE_PROFILE:-}" == public-release ]] || public_failure release-profile
    [[ "${AG_MAC_SIGNING_IDENTITY:-}" =~ ^[0-9a-fA-F]{40}$ ]] || public_failure signing-identity
    [[ "$(/usr/bin/uname -s)" == Darwin ]] || public_failure macOS-required
    local tool
    for tool in /usr/bin/hdiutil /usr/bin/ditto /usr/bin/codesign /usr/bin/xcrun \
                /usr/bin/python3 /usr/bin/shasum /usr/bin/diff /usr/libexec/PlistBuddy; do
        [[ -x "$tool" ]] || public_failure native-tools
    done

    local build_root="$(pwd -P)" app_name="Antigravity Unlocker.app"
    local release_root="$build_root/target/release" path
    for path in "$build_root/target" "$release_root"; do
        [[ ! -L "$path" && ( ! -e "$path" || -d "$path" ) ]] || public_failure release-root
    done
    local existing_stages=("$release_root"/.public-app.*)
    local build_output line app="" version="" app_markers=0 version_markers=0
    build_output="$("$DIR/macos/build_app.sh" --prepare-public-app)" || public_failure app-preparation
    while IFS= read -r line; do
        case "$line" in
            AG_PREPARED_PUBLIC_APP_PATH=*) app="${line#*=}"; (( app_markers += 1 )) ;;
            AG_PREPARED_PUBLIC_APP_VERSION=*) version="${line#*=}"; (( version_markers += 1 )) ;;
        esac
    done <<< "$build_output"
    (( app_markers == 1 && version_markers == 1 )) || public_failure prepared-app-receipt
    [[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || public_failure prepared-app-version
    local stage="${app%/*}" stage_name
    stage_name="${stage##*/}"
    [[ "$stage_name" =~ ^\.public-app\.[A-Za-z0-9]{6}$ && "$app" == "$release_root/$stage_name/$app_name" ]] ||
        public_failure prepared-app-path
    for path in ${existing_stages[@]+"${existing_stages[@]}"}; do
        [[ "$path" != "$stage" ]] || public_failure stale-preparation-stage
    done
    for path in "$build_root/target" "$release_root" "$stage"; do
        [[ -d "$path" && ! -L "$path" ]] || public_failure prepared-app-path
    done
    [[ -O "$stage" ]] || public_failure prepared-app-owner

    umask 077
    local work="$stage/distribution-work" output="$stage/distribution"
    local log_dir="$work/logs" dmg_source="$work/dmg-source" zip_check="$work/zip-check"
    mkdir "$work" "$output" "$log_dir" "$dmg_source" "$zip_check" || public_failure distribution-stage
    printf 'Public distribution work stage: %s\n' "$work" >&2

    local signer_requirement='anchor apple generic'
    signer_requirement+=' and certificate 1[field.1.2.840.113635.100.6.2.6] exists'
    signer_requirement+=' and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
    signer_requirement+=" and certificate leaf = H\"$AG_MAC_SIGNING_IDENTITY\""
    local app_requirement="$signer_requirement"' and identifier = "com.antigravity.unlocker"'
    local executable_sha
    public_verify_app "$app" prepared
    executable_sha="$(public_sha256 "$app/Contents/MacOS/ag_unlocker")" || public_failure prepared-app-executable

    local dmg_app="$dmg_source/$app_name"
    local dmg="$output/Antigravity-Unlocker-$version-macOS.dmg"
    local zip="$output/Antigravity-Unlocker-$version-macOS.zip"
    public_step dmg-app-copy /usr/bin/ditto "$app" "$dmg_app"
    public_step dmg-app-copy-content /usr/bin/diff -qr "$app" "$dmg_app"
    public_verify_app "$dmg_app" dmg-source "$executable_sha"
    public_step dmg-create /usr/bin/hdiutil create -format UDZO -srcfolder "$dmg_source" -volname "Antigravity Unlocker" "$dmg"
    public_step dmg-sign /usr/bin/codesign --force --timestamp --sign "$AG_MAC_SIGNING_IDENTITY" "$dmg"
    public_step dmg-signature /usr/bin/codesign --verify --strict -R "=$signer_requirement" "$dmg"

    local submitted_sha request_id accepted_id
    submitted_sha="$(public_sha256 "$dmg")" || public_failure dmg-submitted-digest
    printf '%s\n' "$submitted_sha" >"$work/submitted-dmg.sha256" || public_failure digest-retention
    public_step notary-submit /usr/bin/xcrun notarytool submit "$dmg" \
        --keychain-profile "$AG_MAC_NOTARY_PROFILE" --output-format json
    request_id="$(public_notary_id "$log_dir/notary-submit.stdout" 2>"$log_dir/notary-submit-parse.stderr")" ||
        public_failure notary-submit-receipt
    printf 'id=%s\nsha256=%s\n' "$request_id" "$submitted_sha" >"$work/notary-submission.txt" ||
        public_failure submission-retention
    [[ "$(public_sha256 "$dmg")" == "$submitted_sha" ]] || public_failure dmg-submission-drift
    public_step notary-wait /usr/bin/xcrun notarytool wait "$request_id" \
        --keychain-profile "$AG_MAC_NOTARY_PROFILE" --output-format json
    accepted_id="$(public_notary_id "$log_dir/notary-wait.stdout" "$request_id" 2>"$log_dir/notary-wait-parse.stderr")" ||
        public_failure notary-acceptance
    [[ "$accepted_id" == "$request_id" && "$(public_sha256 "$dmg")" == "$submitted_sha" ]] ||
        public_failure dmg-before-stapling
    public_verify_app "$dmg_app" before-stapling "$executable_sha"

    local dmg_sha zip_sha
    public_step dmg-staple /usr/bin/xcrun stapler staple "$dmg"
    dmg_sha="$(public_sha256 "$dmg")" || public_failure final-dmg-digest
    public_step app-staple /usr/bin/xcrun stapler staple "$dmg_app"
    public_step app-ticket /usr/bin/xcrun stapler validate "$dmg_app"
    public_verify_app "$dmg_app" stapled "$executable_sha"
    public_step zip-create /usr/bin/ditto -c -k --sequesterRsrc --keepParent "$dmg_app" "$zip"
    zip_sha="$(public_sha256 "$zip")" || public_failure final-zip-digest
    public_step zip-extract /usr/bin/ditto -x -k "$zip" "$zip_check"
    local extracted_app="$zip_check/$app_name"
    public_verify_app "$extracted_app" zip-extracted "$executable_sha"
    public_step zip-app-ticket /usr/bin/xcrun stapler validate "$extracted_app"
    public_step final-dmg-signature /usr/bin/codesign --verify --strict -R "=$signer_requirement" "$dmg"
    public_step final-dmg-ticket /usr/bin/xcrun stapler validate "$dmg"
    public_step final-dmg-integrity /usr/bin/hdiutil verify "$dmg"

    [[ "$(public_sha256 "$dmg")" == "$dmg_sha" && "$(public_sha256 "$zip")" == "$zip_sha" ]] ||
        public_failure final-artifact-drift
    printf 'AG_PUBLIC_DMG_SHA256=%s\nAG_PUBLIC_ZIP_SHA256=%s\n' "$dmg_sha" "$zip_sha"
    printf 'AG_PUBLIC_DISTRIBUTION_PATH=%s\nAG_PUBLIC_DISTRIBUTION_VERSION=%s\n' "$output" "$version"
}

if (( PUBLIC_DISTRIBUTION )); then
    prepare_public_distribution
    exit 0
fi

# An unpinned personal build receives the Cargo-derived app version.
# Accepted builds still require the protected matrix for both architectures.
if [[ $# -eq 1 && "${1:-}" == --personal && -z "${AG_ACCEPTED_RELEASE_RECORD+x}" ]]; then
    EXPECTED_RECEIPT=AG_PRIVATE_APP_VERSION
else
    : "${AG_ACCEPTED_RELEASE_RECORD:?accepted release record required}"
    : "${AG_RELEASE_SOURCE_MANIFEST:?verified release source manifest required}"
    EXPECTED_RECEIPT=AG_VERIFIED_APP_VERSION
fi
BUILD_OUTPUT="$("$DIR/macos/build_app.sh" "$@")"
printf '%s\n' "$BUILD_OUTPUT"
BUILD_RECEIPT="${BUILD_OUTPUT##*$'\n'}"
[[ "$BUILD_RECEIPT" == "$EXPECTED_RECEIPT="* ]] || {
    echo "App build receipt missing ($EXPECTED_RECEIPT)" >&2; exit 1;
}

APP_BUNDLE="$DIR/target/release/Antigravity Unlocker.app"
RELEASE_VERSION="${BUILD_RECEIPT#*=}"
[[ "$RELEASE_VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
    echo "Built app lacks a canonical Cargo version" >&2; exit 1;
}
for KEY in CFBundleShortVersionString CFBundleVersion; do
    [[ "$(/usr/libexec/PlistBuddy -c "Print :$KEY" "$APP_BUNDLE/Contents/Info.plist")" == "$RELEASE_VERSION" ]] || {
        echo "Built app version differs from the build receipt" >&2; exit 1;
    }
done

DIST_DIR="$DIR/dist"
[[ ! -L "$DIST_DIR" ]] || { echo "Package output directory must not be a symbolic link" >&2; exit 1; }
mkdir -p "$DIST_DIR"
PACKAGE_STAGE="$(mktemp -d "$DIST_DIR/.package.XXXXXX")"
PACKAGE_PROMOTED=0

DMG_NAME="Antigravity-Unlocker-$RELEASE_VERSION-macOS.dmg"
ZIP_NAME="Antigravity-Unlocker-$RELEASE_VERSION-macOS.zip"
PACKAGE_NAMES=("$ZIP_NAME")

cleanup_package_stage() {
    if (( PACKAGE_PROMOTED )); then
        rm -f "$PACKAGE_STAGE/previous-$DMG_NAME" "$PACKAGE_STAGE/previous-$ZIP_NAME"
    elif [[ -e "$PACKAGE_STAGE/previous-$DMG_NAME" || -e "$PACKAGE_STAGE/previous-$ZIP_NAME" ]]; then
        printf 'Previous packages remain at %s\n' "$PACKAGE_STAGE" >&2
        return
    fi
    rm -f "$PACKAGE_STAGE/$DMG_NAME" "$PACKAGE_STAGE/$ZIP_NAME"
    rmdir "$PACKAGE_STAGE"
}
trap cleanup_package_stage EXIT

echo "==> Создание ZIP-архива..."
(cd "$DIR/target/release" && zip -r -y -q "$PACKAGE_STAGE/$ZIP_NAME" "Antigravity Unlocker.app")

if command -v create-dmg >/dev/null 2>&1; then
    echo "==> Создание DMG-образа с помощью create-dmg..."
    create-dmg \
      --volname "Antigravity Unlocker" \
      --volicon "$DIR/macos/AppIcon.icns" \
      --window-pos 200 120 \
      --window-size 600 400 \
      --icon-size 128 \
      --text-size 12 \
      --icon "Antigravity Unlocker.app" 150 190 \
      --app-drop-link 450 190 \
      --hide-extension "Antigravity Unlocker.app" \
      --no-internet-enable \
      "$PACKAGE_STAGE/$DMG_NAME" \
      "$APP_BUNDLE"
    PACKAGE_NAMES+=("$DMG_NAME")
else
    echo "==> create-dmg не найден, будет создан ZIP."
fi

python3 -B - "$PACKAGE_STAGE" "$DIST_DIR" "${PACKAGE_NAMES[@]}" <<'PY'
import os
from pathlib import Path
import stat
import sys

stage, destination = map(Path, sys.argv[1:3])
names = sys.argv[3:]
existing = {}
for name in names:
    if not stat.S_ISREG((stage / name).lstat().st_mode):
        raise SystemExit(f"Unexpected staged package type: {name}")
    current = destination / name
    if os.path.lexists(current):
        if not stat.S_ISREG(current.lstat().st_mode):
            raise SystemExit(f"Unexpected existing package type: {name}")
        existing[name] = stage / f"previous-{name}"

try:
    for name, backup in existing.items():
        (destination / name).replace(backup)
    for name in names:
        (stage / name).replace(destination / name)
except BaseException:
    for name in reversed(names):
        if name in existing:
            backup = existing[name]
            if os.path.lexists(backup):
                backup.replace(destination / name)
        elif not os.path.lexists(stage / name):
            (destination / name).replace(stage / name)
    raise
PY
PACKAGE_PROMOTED=1

echo
echo "============================================================"
echo " Пакеты macOS успешно собраны в: $DIST_DIR"
echo "============================================================"
(
    cd "$DIST_DIR"
    ls -lh "${PACKAGE_NAMES[@]}"
    echo
    shasum -a 256 "${PACKAGE_NAMES[@]}"
)
