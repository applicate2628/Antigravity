#!/usr/bin/env bash
# Antigravity Unlocker - macOS App Bundle Builder
# Builds the native release binary and packages it into Antigravity Unlocker.app
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

echo "==> Сборка релизного бинарника для macOS (Apple Silicon + Intel, universal)..."
PERSONAL_BUILD=0
SLICE_ARTIFACTS=()
SLICE_TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)
BASE_VERSION=""
ACCEPTED_RELEASE=0
PREPARE_PUBLIC_APP=0
LIPO=lipo
RELEASE_BUILD_TARGET="$DIR/target"
if [[ "${1:-}" == "--prepare-public-app" ]]; then
    if [[ $# -ne 1 ]]; then
        echo "--prepare-public-app must be used on its own" >&2
        exit 1
    fi
    PREPARE_PUBLIC_APP=1
    shift
    set +x
elif [[ "${1:-}" == "--personal" ]]; then
    PERSONAL_BUILD=1
    shift
fi
if [[ $# -ne 0 ]]; then
    echo "Использование: $0 [--personal | --prepare-public-app]" >&2
    exit 1
fi
if (( PERSONAL_BUILD )); then
    set -- --features personal-build
fi
if (( PREPARE_PUBLIC_APP )) || [[ "${AG_ACCEPTED_RELEASE_RECORD+x}" ]]; then
    : "${AG_ACCEPTED_RELEASE_RECORD:?accepted release record required}"
    : "${AG_RELEASE_SOURCE_MANIFEST:?verified release source manifest required}"
    : "${AG_RELEASE_RECORD_SHA256:?approved release record pin required}"
    : "${AG_RELEASE_SOURCE_SHA256:?approved release source pin required}"
    : "${AG_RELEASE_PROFILE:?approved release profile required}"
    ACCEPTED_RELEASE=1
fi

require_target_directories() {
    local path
    for path in "$DIR/target" "$DIR/target/release"; do
        if [[ -L "$path" || ( -e "$path" && ! -d "$path" ) ]]; then
            echo "App preparation requires ordinary target directories" >&2
            return 1
        fi
    done
}

require_public_signing_identity() (
    local identities line label matches=0
    local identity_row='^[[:blank:]]*[0-9]+\)[[:blank:]]+([0-9a-f]{40})([[:blank:]].*)?$'
    local developer_id_label='^[[:blank:]]+"Developer ID Application: .+"[[:blank:]]*$'
    shopt -s nocasematch
    identities="$(LC_ALL=C /usr/bin/security find-identity -v -p codesigning 2>&1)" || return 1
    while IFS= read -r line; do
        if [[ "$line" =~ $identity_row && "${BASH_REMATCH[1]}" == "$AG_MAC_SIGNING_IDENTITY" ]]; then
            label="${BASH_REMATCH[2]}"
            [[ "$label" =~ $developer_id_label ]] || return 1
            (( matches += 1 ))
        fi
    done <<< "$identities"
    (( matches == 1 ))
)

verify_public_app_requirement() {
    /usr/bin/codesign --verify --deep --strict --all-architectures -R "=$REQUIREMENT" "$APP_DIR" >/dev/null 2>&1
}

verify_public_slice_artifact() {
    local target="$1" artifact="$2" path
    local target_release="$RELEASE_BUILD_TARGET/$target/release"
    [[ "$artifact" == "$target_release/ag_unlocker" ]] || return 1
    for path in "$PREPARED_STAGE" "$RELEASE_BUILD_TARGET" "$RELEASE_BUILD_TARGET/$target" "$target_release"; do
        [[ ! -L "$path" && -d "$path" ]] || return 1
    done
    [[ ! -L "$artifact" && -f "$artifact" ]]
}

verify_public_slice_signature() {
    local arch="$1" details line flags="" timestamp=""
    local code_flags='^CodeDirectory[[:blank:]].*[[:blank:]]flags=0x([0-9a-fA-F]{1,8})\('
    details="$(LC_ALL=C /usr/bin/codesign --display --arch "$arch" --verbose=4 "$APP_DIR" 2>&1)" || return 1
    while IFS= read -r line; do
        if [[ "$line" =~ $code_flags ]]; then
            [[ -z "$flags" ]] || return 1
            flags="${BASH_REMATCH[1]}"
        elif [[ "$line" == Timestamp=* ]]; then
            [[ -z "$timestamp" ]] || return 1
            timestamp="${line#Timestamp=}"
            [[ "$timestamp" =~ [^[:space:]] ]] || return 1
        fi
    done <<< "$details"
    [[ -n "$flags" && -n "$timestamp" ]] && (( (16#$flags & 0x10000) != 0 ))
}

if (( PREPARE_PUBLIC_APP )); then
    [[ "$AG_RELEASE_PROFILE" == public-release ]] || {
        echo "Public app preparation requires the public-release profile" >&2; exit 1;
    }
    [[ "$AG_RELEASE_RECORD_SHA256" =~ ^[0-9a-f]{64}$ && "${AG_RELEASE_RECORD_SHA256//0/}" &&
       "$AG_RELEASE_SOURCE_SHA256" =~ ^[0-9a-f]{64}$ && "${AG_RELEASE_SOURCE_SHA256//0/}" ]] || {
        echo "Public app preparation requires canonical release and source pins" >&2; exit 1;
    }
    [[ "${AG_MAC_SIGNING_IDENTITY:-}" =~ ^[0-9a-fA-F]{40}$ ]] || {
        echo "AG_MAC_SIGNING_IDENTITY must be a 40-hex Developer ID Application certificate fingerprint" >&2; exit 1;
    }
    [[ "$(/usr/bin/uname -s)" == Darwin ]] || {
        echo "Public app preparation requires macOS" >&2; exit 1;
    }
    for TOOL in /usr/bin/codesign /usr/bin/security /usr/bin/lipo /usr/bin/mktemp; do
        [[ -x "$TOOL" ]] || { echo "Required native macOS tools are unavailable" >&2; exit 1; }
    done
    require_target_directories
    require_public_signing_identity || {
        echo "Expected one valid Developer ID Application identity for the selected fingerprint" >&2; exit 1;
    }
    mkdir -p "$DIR/target/release"
    PREPARED_STAGE="$(/usr/bin/mktemp -d "$(pwd -P)/target/release/.public-app.XXXXXX")"
    printf 'Public app preparation stage: %s\n' "$PREPARED_STAGE" >&2
    RELEASE_BUILD_TARGET="$PREPARED_STAGE/cargo-target"
    mkdir "$RELEASE_BUILD_TARGET"
    LIPO=/usr/bin/lipo
fi

for T in "${SLICE_TARGETS[@]}"; do
    if (( ACCEPTED_RELEASE )); then
        AG_RELEASE_BUILD_REQUEST="$(uuidgen | tr '[:upper:]' '[:lower:]' | tr -d '-')"
        export AG_RELEASE_BUILD_REQUEST
        SLICE_RECEIPT="$(cargo build --release --target "$T" "$@" --locked --bin ag_unlocker \
            --target-dir "$RELEASE_BUILD_TARGET" --message-format=json-render-diagnostics \
            | python3 -B "$DIR/build_rust.py" --receive-release-build "$DIR/Cargo.toml" "$T")"
        IFS=$'\t' read -r SLICE_VERSION SLICE_ARTIFACT <<< "$SLICE_RECEIPT"
        [[ -n "$SLICE_VERSION" && -n "$SLICE_ARTIFACT" && ( -z "$BASE_VERSION" || "$BASE_VERSION" == "$SLICE_VERSION" ) ]] || {
            echo "macOS slices lack equivalent accepted release identity" >&2; exit 1;
        }
        BASE_VERSION="$SLICE_VERSION"
        SLICE_ARTIFACTS+=("$SLICE_ARTIFACT")
    else
        cargo build --release --target "$T" "$@"
        SLICE_ARTIFACTS+=("$DIR/target/$T/release/ag_unlocker")
    fi
done

if (( ! ACCEPTED_RELEASE )); then
    # Private bundle metadata keeps the Cargo base. The fragment is either
    # #version or #name@version.
    PACKAGE_ID="$(cargo pkgid --frozen --manifest-path "$DIR/Cargo.toml")"
    [[ "$PACKAGE_ID" == *\#* ]] || { echo "Cargo package ID lacks version fragment" >&2; exit 1; }
    FRAGMENT="${PACKAGE_ID##*#}"
    BASE_VERSION="${FRAGMENT##*@}"
fi
[[ "$BASE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Cargo package ID has invalid base version" >&2; exit 1; }

APP_NAME="Antigravity Unlocker.app"
APP_DEST="$DIR/target/release/$APP_NAME"
require_target_directories
if (( PREPARE_PUBLIC_APP )); then
    for INDEX in "${!SLICE_TARGETS[@]}"; do
        verify_public_slice_artifact "${SLICE_TARGETS[$INDEX]}" "${SLICE_ARTIFACTS[$INDEX]}" || {
            echo "Accepted macOS slice is outside its fresh Cargo target or is not an ordinary file" >&2; exit 1;
        }
    done
    APP_DIR="$PREPARED_STAGE/$APP_NAME"
else
    mkdir -p "$DIR/target/release"
    APP_STAGE="$(mktemp -d "$DIR/target/release/.app-build.XXXXXX")"
    APP_DIR="$APP_STAGE/$APP_NAME"
    PREVIOUS_APP="$APP_STAGE/previous.app"
    APP_PROMOTED=0
    cleanup_app_stage() {
        if (( ! APP_PROMOTED )) && [[ -e "$PREVIOUS_APP" ]]; then
            printf 'Previous app remains at %s\n' "$PREVIOUS_APP" >&2
            return
        fi
        rm -rf -- "$APP_STAGE"
    }
    trap cleanup_app_stage EXIT
fi
CONTENTS="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS/MacOS"
RESOURCES_DIR="$CONTENTS/Resources"

echo "==> Создание структуры бандла $APP_NAME..."
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"

# Копирование исполняемого файла
"$LIPO" -create -output "$MACOS_DIR/ag_unlocker" "${SLICE_ARTIFACTS[@]}"
chmod +x "$MACOS_DIR/ag_unlocker"

# Копирование иконки приложения
if [ -f "$DIR/macos/AppIcon.icns" ]; then
    cp "$DIR/macos/AppIcon.icns" "$RESOURCES_DIR/AppIcon.icns"
fi

# Создание Info.plist
cat > "$CONTENTS/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>Antigravity Unlocker</string>
    <key>CFBundleDisplayName</key>
    <string>Antigravity Unlocker</string>
    <key>CFBundleIdentifier</key>
    <string>com.antigravity.unlocker</string>
    <key>CFBundleVersion</key>
    <string>$BASE_VERSION</string>
    <key>CFBundleShortVersionString</key>
    <string>$BASE_VERSION</string>
    <key>CFBundleExecutable</key>
    <string>ag_unlocker</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSSupportsAutomaticGraphicsSwitching</key>
    <true/>
    <key>NSRequiresAquaSystemAppearance</key>
    <false/>
    <key>NSHumanReadableCopyright</key>
    <string>© 2026 Fuheshka. Open Source.</string>
</dict>
</plist>
EOF

if (( PREPARE_PUBLIC_APP )); then
    ARCHS="$(LC_ALL=C /usr/bin/lipo -archs "$MACOS_DIR/ag_unlocker" 2>/dev/null)" || {
        echo "Cannot verify the staged app architectures" >&2; exit 1;
    }
    case "$ARCHS" in
        "x86_64 arm64"|"arm64 x86_64") ;;
        *) echo "Staged app must contain exactly x86_64 and arm64" >&2; exit 1 ;;
    esac
    REQUIREMENT='anchor apple generic and identifier = "com.antigravity.unlocker"'
    REQUIREMENT+=' and certificate 1[field.1.2.840.113635.100.6.2.6] exists'
    REQUIREMENT+=' and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
    REQUIREMENT+=" and certificate leaf = H\"$AG_MAC_SIGNING_IDENTITY\""
    /usr/bin/codesign --force --options runtime --timestamp=none --sign "$AG_MAC_SIGNING_IDENTITY" "$APP_DIR" >/dev/null 2>&1 || {
        echo "Local Developer ID signing failed for the staged app" >&2; exit 1;
    }
    verify_public_app_requirement || {
        echo "Local signature failed Developer ID verification before timestamping" >&2; exit 1;
    }
    /usr/bin/codesign --force --options runtime --timestamp --sign "$AG_MAC_SIGNING_IDENTITY" "$APP_DIR" >/dev/null 2>&1 || {
        echo "Timestamped Developer ID signing failed for the staged app" >&2; exit 1;
    }
    verify_public_app_requirement || {
        echo "Timestamped signature failed Developer ID verification" >&2; exit 1;
    }
    for ARCH in x86_64 arm64; do
        verify_public_slice_signature "$ARCH" || {
            echo "Staged app lacks verified runtime or timestamp metadata for $ARCH" >&2; exit 1;
        }
    done
    echo "The signed app is awaiting notarization." >&2
    printf 'AG_PREPARED_PUBLIC_APP_PATH=%s\n' "$APP_DIR"
    printf 'AG_PREPARED_PUBLIC_APP_VERSION=%s\n' "$BASE_VERSION"
    exit 0
fi

echo "==> Выполнение ad-hoc подписи (codesign)..."
# Requirement по bundle id, а не по cdhash: macOS сохраняет выданные разрешения между пересборками
codesign --force --deep -s - -r='designated => identifier "com.antigravity.unlocker"' "$APP_DIR"

require_target_directories
if [[ -e "$APP_DEST" || -L "$APP_DEST" ]]; then
    PLIST="$APP_DEST/Contents/Info.plist"
    [[ -d "$APP_DEST" && ! -L "$APP_DEST" && -O "$APP_DEST" &&
       -d "$APP_DEST/Contents" && ! -L "$APP_DEST/Contents" &&
       -f "$PLIST" && ! -L "$PLIST" &&
       "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$PLIST")" == com.antigravity.unlocker ]] || {
        echo "Existing app path is not an owned Antigravity Unlocker bundle" >&2
        exit 1
    }
    mv -- "$APP_DEST" "$PREVIOUS_APP"
fi
if ! mv -- "$APP_DIR" "$APP_DEST"; then
    if [[ -d "$PREVIOUS_APP" && ! -e "$APP_DEST" && ! -L "$APP_DEST" ]]; then
        mv -- "$PREVIOUS_APP" "$APP_DEST"
    fi
    exit 1
fi
APP_PROMOTED=1

echo "==> Готово! Бандл создан в: $APP_DEST"
echo "Для установки в систему выполните: ./macos/install.sh"
if (( ACCEPTED_RELEASE )); then
    printf 'AG_VERIFIED_APP_VERSION=%s\n' "$BASE_VERSION"
elif (( PERSONAL_BUILD )); then
    printf 'AG_PRIVATE_APP_VERSION=%s\n' "$BASE_VERSION"
fi
