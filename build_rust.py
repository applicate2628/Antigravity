import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import stat
import secrets
from contextlib import ExitStack
from functools import wraps

def read_package_version(manifest_path=None):
    """Read the one Cargo package base without entering the build lifecycle."""
    try:
        import tomllib
    except ImportError as error:
        raise RuntimeError("Python 3.11 or newer with tomllib is required") from error
    path = manifest_path or os.path.join(os.path.dirname(os.path.abspath(__file__)), "Cargo.toml")
    try:
        with open(path, "rb") as manifest:
            document = tomllib.load(manifest)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise RuntimeError(f"cannot read Cargo manifest {path}: {error}") from error
    package = document.get("package")
    version = package.get("version") if isinstance(package, dict) else None
    if not isinstance(version, str) or not version:
        raise RuntimeError("Cargo manifest package.version must be a nonempty string")
    return version

# Must match src\auth.rs (LICENSE_VERSION_SEP): the license key is derived from
# base_secret + SEP + version, so keys are unique per release.
LICENSE_VERSION_SEP = "::"


def read_canary_const(name, canary_rs_path=r"src\canary.rs"):
    """Reads a committed const out of src/canary.rs. Same single-source-of-truth
    trick as read_base_secret, so build.rs, the binary, this script and
    tools/canary_check.py cannot drift apart."""
    with open(canary_rs_path, 'r', encoding='utf-8') as f:
        src = f.read()
    m = re.search(r'pub const %s: &str = "([^"]*)"' % re.escape(name), src)
    if not m:
        raise RuntimeError("%s not found in %s" % (name, canary_rs_path))
    return m.group(1)


def release_token(version):
    """Must match canary::token_for() in Rust and token_for() in build.rs."""
    import hashlib
    seed = read_canary_const("CANARY_SEED")
    sep = read_canary_const("CANARY_SEP")
    d = hashlib.sha256((seed + sep + version).encode('utf-8')).hexdigest().upper()
    return "AGU-%s-%s-%s" % (d[0:5], d[5:10], d[10:15])


def record_canary(version, token, exe_path, owned_file=None):
    """Appends this release to CANARIES.md.

    The token is derivable from the sources, so the ledger is a convenience, not
    a secret. Its value is being a dated, committed record of which token belongs
    to which release and which binary hash - i.e. the thing you would actually
    put in front of someone. It therefore lives at the repo root, NOT under
    release/, which is gitignored and would never be committed."""
    import hashlib
    try:
        if owned_file is None:
            with open(exe_path, 'rb') as f:
                sha = hashlib.sha256(f.read()).hexdigest()
        else:
            owned_file.seek(0)
            sha = hashlib.sha256(owned_file.read()).hexdigest()
    except OSError:
        sha = "(unavailable)"

    ledger = "CANARIES.md"
    row = "| %s | `%s` | `%s` | `%s` |\n" % (
        version, token, read_canary_const("STATIC_CANARY"), sha)

    if not os.path.exists(ledger):
        header = (
            "# Release canaries\n\n"
            "Provenance record for every published build. See `src/canary.rs`\n"
            "for what these are and `tools/canary_check.py` for how to scan a\n"
            "suspect file against them. Tokens are derived from the committed\n"
            "seed, so this table is reproducible - it exists so the mapping is\n"
            "dated and committed rather than recomputed after the fact.\n\n"
            "| version | release token | static canary | sha256 of the .exe |\n"
            "|---|---|---|---|\n"
        )
        with open(ledger, 'w', encoding='utf-8') as f:
            f.write(header + row)
        return ledger

    with open(ledger, 'r', encoding='utf-8') as f:
        content = f.read()
    if "| %s |" % version in content:
        # Rebuild of an already-recorded version: refresh its row in place so the
        # hash matches the binary that actually shipped.
        content = re.sub(r'^\| %s \|.*$' % re.escape(version), row.rstrip('\n'),
                         content, flags=re.M)
        with open(ledger, 'w', encoding='utf-8') as f:
            f.write(content)
    else:
        with open(ledger, 'a', encoding='utf-8') as f:
            f.write(row)
    return ledger


CARGO_JSON = "--message-format=json-render-diagnostics"


def expected_release_receiving(env, target):
    inputs = {
        "AG_VERIFIED_RELEASE_REQUEST": "AG_RELEASE_BUILD_REQUEST",
        "AG_VERIFIED_RELEASE_RECORD_SHA256": "AG_RELEASE_RECORD_SHA256",
        "AG_VERIFIED_RELEASE_SOURCE_SHA256": "AG_RELEASE_SOURCE_SHA256",
        "AG_VERIFIED_RELEASE_PROFILE": "AG_RELEASE_PROFILE",
    }
    if any(not env.get(key) for key in inputs.values()):
        raise RuntimeError("approved release record, source and profile pins are required")
    return {**{fact: env[key] for fact, key in inputs.items()}, "AG_VERIFIED_RELEASE_TARGET": target}


class BuildReport:
    """Receive Cargo terminal, root-artifact and build-script records."""

    def __init__(self, lines):
        self.root_artifacts = []
        self.build_env = []
        self.finished_facts = []
        for line in lines:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            reason = msg.get("reason")
            if reason == "build-finished":
                self.finished_facts.append(msg.get("success"))
            elif reason == "compiler-artifact":
                self.root_artifacts.append(msg)
            elif reason == "build-script-executed":
                self.build_env.append(msg)

    def require_root_full_version(self, selected_manifest, selected_bin, manifest_identity, expected_version,
                                  release_receiving=None, helper_digest=None):
        if not self.finished_facts or any(value is not True for value in self.finished_facts):
            raise RuntimeError("Cargo build-finished success was not received")
        matches = []
        for msg in self.root_artifacts:
            target = msg.get("target")
            if not isinstance(target, dict) or target.get("name") != selected_bin:
                continue
            kind = target.get("kind")
            if not isinstance(kind, list) or not all(isinstance(item, str) for item in kind) or "bin" not in kind:
                continue
            if not all(isinstance(msg.get(key), str) and msg[key] for key in ("manifest_path", "package_id", "executable")):
                raise RuntimeError("Cargo root candidate identity malformed")
            same = manifest_identity(selected_manifest, msg["manifest_path"])
            if type(same) is not bool:
                raise RuntimeError("manifest identity receiver did not return a boolean")
            if same:
                matches.append(msg)
        identities = {(msg.get("package_id"), msg.get("executable")) for msg in matches}
        if len(identities) != 1 or not all(isinstance(value, str) and value for value in next(iter(identities), ())):
            raise RuntimeError("Cargo root manifest/bin executable association missing or ambiguous")
        package_id, executable = next(iter(identities))
        values = []
        release_facts = []
        helper_values = []
        for msg in self.build_env:
            if msg.get("package_id") != package_id:
                continue
            env = msg.get("env")
            if not isinstance(env, list) or any(not isinstance(pair, list) or len(pair) != 2 or not all(isinstance(v, str) for v in pair) for pair in env):
                raise RuntimeError("Cargo root build-script environment malformed")
            values.extend(value for key, value in env if key == "AG_FULL_VERSION")
            if release_receiving is not None:
                release_facts.extend((key, value) for key, value in env if key.startswith("AG_VERIFIED_RELEASE_"))
            if helper_digest is not None:
                helper_values.extend(value for key, value in env if key == "AG_WSL_EXPECTED_HELPER_SHA256")
        if not values or any(not value for value in values) or len(set(values)) != 1:
            raise RuntimeError("Cargo root AG_FULL_VERSION missing or ambiguous")
        if values[0] != expected_version:
            raise RuntimeError("Cargo root AG_FULL_VERSION differs from the selected package version")
        if release_receiving is not None:
            proof = dict(release_facts)
            if len(release_facts) != len(proof) or proof != release_receiving:
                raise RuntimeError("Cargo root public release receipt missing or inconsistent")
        if helper_digest is not None and set(helper_values) != {helper_digest}:
            raise RuntimeError("Windows Cargo did not receive the selected WSL helper digest")
        return values[0], executable

def cargo_build(args, env=None):
    """check_call() for a cargo build, plus its JSON messages: progress and
    diagnostics still render on the console, the messages are read off stdout."""
    proc = subprocess.Popen(args + [CARGO_JSON], stdout=subprocess.PIPE, env=env,
                            text=True, encoding="utf-8", errors="replace")
    report = BuildReport(proc.stdout)
    if proc.wait() != 0:
        raise subprocess.CalledProcessError(proc.returncode, args)
    return report


def receive_release_build(lines, manifest, target, env):
    version, executable = BuildReport(lines).require_root_full_version(
        manifest, "ag_unlocker", os.path.samefile, read_package_version(manifest),
        release_receiving=expected_release_receiving(env, target))
    if (not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version)
            or any(ord(char) < 32 for char in executable) or not os.path.isfile(executable)):
        raise RuntimeError("accepted Cargo version or reported artifact invalid")
    return version, executable


# UPX packing is OFF (owner, `_4`). A packed exe is the single biggest source of
# antivirus false positives here, and a user who cannot start the tool at all is a
# worse outcome than a file three times the size. The packer below is deliberately
# kept rather than deleted - set this back to True to ship packed again.
UPX_ENABLED = False


def find_upx():
    """Locate the UPX packer. Returns the executable path or None."""
    import shutil
    found = shutil.which("upx")
    if found:
        return found
    for candidate in (
        r"C:\Program Files\upx\upx.exe",
        r"C:\Program Files (x86)\upx\upx.exe",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "upx.exe"),
    ):
        if os.path.exists(candidate):
            return candidate
    return None


def compress_exe_inplace(exe_path):
    """Shrink the release exe in place with UPX, keeping it a directly-runnable
    .exe (no archive, no separate file).

    UPX is a runtime packer: the file on disk gets ~60-65% smaller, and the exe
    self-decompresses into memory on launch. For a ~1.5 MB binary that unpack is
    single-digit milliseconds - imperceptible - but it is the unavoidable cost of
    compressing the executable itself rather than shipping it in an archive.
    Packed exes also raise more AV false positives (already noted in README).

    Best-effort: if UPX is absent the uncompressed exe still ships.
    """
    upx = find_upx()
    if not upx:
        print("[WARNING] UPX не найден (upx в PATH, C:\\Program Files\\upx или рядом со "
              "скриптом). Сжатие пропущено - будет отгружён несжатый .exe.")
        return

    before = None
    try:
        before = os.path.getsize(exe_path)
    except OSError:
        pass
    try:
        # --best --lzma = maximum compression. UPX rewrites the file in place, so
        # the output stays AG_<ver>.exe.
        subprocess.check_call(
            [upx, "--best", "--lzma", exe_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        print(f"[WARNING] Не удалось сжать exe с помощью UPX: {e}")
        return

    try:
        after = os.path.getsize(exe_path)
        if before:
            print(f"[INFO] exe сжат UPX: {before // 1024} КБ -> {after // 1024} КБ "
                  f"({after / before * 100:.0f}%).")
        else:
            print(f"[INFO] exe сжат UPX: {after // 1024} КБ.")
    except OSError:
        print("[INFO] exe сжат UPX.")


# The Windows package receives its required helper from a native Linux Cargo toolchain.
# The separate Linux desktop bundle remains best-effort.
PREFERRED_WSL_DISTROS = ("Ubuntu-26.04", "Ubuntu", "Ubuntu-24.04", "Ubuntu-22.04")


def _wsl_run(distro, bash_cmd, capture=True, binary=False):
    """Runs a bash command inside a WSL distro (login shell, so ~/.cargo/env is
    reachable via the explicit source below). Returns CompletedProcess.

    `-e`, not `--`: after `--` wsl.exe hands the whole line to the distro's default
    shell first, which expands every `$VAR` before bash sees the command - `$HOME`
    survives that, but a variable the command sets itself arrives empty, and
    `exit $rc` arrives as `exit`, i.e. 0.

    WSL_UTF8: wsl.exe's own notices ("A localhost proxy configuration was detected
    ...", printed on some runs and not others) are UTF-16 otherwise, and their NUL
    bytes land at the start of the next line of the command's output."""
    args = ["wsl.exe", "-d", distro, "-e", "bash", "-lc", bash_cmd]
    env = dict(os.environ, WSL_UTF8="1")
    if "CARGO_NET_OFFLINE" in env:
        wsl_env = env.get("WSLENV", "").split(":")
        if not any(item.partition("/")[0] == "CARGO_NET_OFFLINE" for item in wsl_env):
            env["WSLENV"] = ":".join(filter(None, [*wsl_env, "CARGO_NET_OFFLINE/u"]))
    res = subprocess.run(
        args,
        stdout=subprocess.PIPE if capture else None,
        stderr=(subprocess.PIPE if binary else subprocess.STDOUT) if capture else None,
        env=env,
        **({} if binary else {"text": True, "encoding": "utf-8", "errors": "replace"}),
    )
    if res.stdout and not binary:
        res.stdout = res.stdout.replace("\x00", "")  # a WSL too old for WSL_UTF8
    return res


def wsl_manifest_identity(distro, selected, candidate):
    result = _wsl_run(distro, "builtin test " + shlex.quote(selected) + " -ef " + shlex.quote(candidate), capture=True)
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise RuntimeError(f"WSL manifest identity test failed ({result.returncode}): {result.stdout or ''}")


def find_wsl_distro(native_target=None):
    """The first installed WSL distro that has cargo on PATH (after sourcing the
    rustup env). None if WSL is absent or no distro can build."""
    try:
        listing = subprocess.run(
            ["wsl.exe", "-l", "-q"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-16-le", errors="replace",
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    if not listing:
        return None
    installed = [d.strip() for d in listing.splitlines() if d.strip()]
    # Preferred names first, then whatever else is installed.
    ordered = [d for d in PREFERRED_WSL_DISTROS if d in installed]
    ordered += [d for d in installed if d not in ordered]
    command = '. "$HOME/.cargo/env" 2>/dev/null; command -v cargo >/dev/null'
    if native_target is not None:
        command += (' && command -v cc >/dev/null && rustc -vV | grep -Fxq '
                    + shlex.quote("host: " + native_target))
    for distro in ordered:
        try:
            probe = _wsl_run(distro, command + ' && echo OK')
        except OSError:
            continue
        if probe.returncode == 0 and "OK" in (probe.stdout or "").splitlines():
            return distro
    return None


def _win_to_wsl_path(distro, win_path):
    """Translate a Windows path using the selected distro's mount layout."""
    args = ["wsl.exe", "-d", distro, "-e", "wslpath", "-a", os.path.abspath(win_path)]
    try:
        result = subprocess.run(args, capture_output=True, env=dict(os.environ, WSL_UTF8="1"))
    except OSError as error:
        raise RuntimeError(f"Could not run wslpath in {distro}: {error}") from error
    if result.returncode:
        detail = (result.stderr or result.stdout).decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"wslpath failed in {distro} (exit {result.returncode})"
                           + (f": {detail}" if detail else ""))
    try:
        path = result.stdout.decode("utf-8").removesuffix("\n").removesuffix("\r")
    except UnicodeDecodeError as error:
        raise RuntimeError(f"wslpath returned a non-UTF-8 path in {distro}") from error
    if not path.startswith("/") or any(char in path for char in "\r\n\0"):
        raise RuntimeError(f"wslpath did not return one absolute Linux path in {distro}")
    return path


# The build machine's paths, out of the shipped binaries.
#
# Every panic location a dependency carries - winit, wgpu, ring, naga: hundreds
# of them - is an absolute path into CARGO_HOME, i.e. into the builder's home
# directory, and one reached a user's screen inside a winit error ("os error at
# /home/<builder>/.cargo/registry/src/.../winit-0.30.13/..."). rustc rewrites them
# at compile time: the home directory becomes ~, the checkout /ag_unlocker, the
# cargo home /cargo. The last matching rule wins, so the specific ones come last.
# (`profile.trim-paths` does this in one line, but is unstable in cargo 1.95.)
def remap_prefix_flags(home, repo, cargo_home):
    return ["--remap-path-prefix=%s=%s" % (src, dst)
            for src, dst in ((home, "~"), (repo, "/ag_unlocker"), (cargo_home, "/cargo"))
            if src]


def config_rustflags(triple):
    """The rustflags .cargo/config.toml gives `triple`. An environment
    CARGO_ENCODED_RUSTFLAGS *replaces* that list rather than adding to it, so the
    release build hands it over explicitly - or it would ship without the static
    CRT, and a clean Windows would refuse the exe before main (VCRUNTIME140.dll)."""
    import tomllib
    with open(os.path.join(".cargo", "config.toml"), "rb") as f:
        return list(tomllib.load(f)["target"][triple]["rustflags"])


def check_shipped_binary(path, needles, windows, owned_file=None, output_owner=None):
    """Measured, not assumed: warns when the binary still names the build
    machine, or (Windows) still needs the Visual C++ runtime DLL."""
    def emit(action):
        if output_owner is None:
            action()
        else:
            output_owner.emit_required('binary-check', action)
    try:
        if owned_file is None:
            with open(path, "rb") as f:
                data = f.read().lower()
        else:
            owned_file.seek(0)
            data = owned_file.read().lower()
    except OSError as e:
        emit(lambda: print(f"[WARNING] {path} не прочитан для проверки: {e}"))
        return
    leaked = [n for n in needles if n and n.lower().encode("utf-8") in data]
    if leaked:
        emit(lambda: print(f"[WARNING] {os.path.basename(path)} содержит пути сборочной машины: {', '.join(leaked)}"))
    else:
        emit(lambda: print(f"[INFO] {os.path.basename(path)}: путей сборочной машины нет."))
    if windows and b"vcruntime140.dll" in data:
        emit(lambda: print(f"[WARNING] {os.path.basename(path)} требует VCRUNTIME140.dll - "
              f"статический CRT не применился (.cargo/config.toml)."))


# Oldest glibc the Linux bundle has to start on.
#
# glibc is backward compatible but not forward, and the baseline is decided by
# where the binary is *linked*, not by what it calls. Built natively on Ubuntu
# 26.04 (glibc 2.43), `_4`'s ELF picked up a GLIBC_2.39 version reference for two
# `pidfd_*` symbols out of Rust std's process-spawn fast path. The symbols
# themselves are weak and std falls back without them - but the `.gnu.version_r`
# entry is `Flags: none`, so ld.so refuses to start the file at all on anything
# older: `version 'GLIBC_2.39' not found`, before main. Nothing else in the binary
# asked for more than GLIBC_2.34.
#
# cargo-zigbuild pins the baseline at link time, so this needs no second distro.
# 2.17 is Rust std's own floor, and zig ships stubs for it: against them
# `__libc_start_main`, `dlsym` and the `pthread_*` family link to their pre-2.34
# homes in libpthread/libdl, so the 2.34 an earlier note called "the floor the
# code itself sets" was only where a *modern* glibc had moved those symbols.
# Measured 2026-09-19: a 2.17 build asks for nothing above GLIBC_2.17 and NEEDED
# holds libc, libm, libpthread, libdl - all glibc. Covers CentOS/RHEL 7, Ubuntu
# 14.04+, Debian 8+: the old servers the terminal mode is for, not only desktops.
# Raise it only if a build starts failing to link, never to make a build pass
# quietly: `linux_glibc_baseline` below is what proves the pin held.
LINUX_GLIBC = "2.17"
LINUX_TARGET = "x86_64-unknown-linux-gnu"

# The Linux build's cache, on the WSL distro's own filesystem. It used to be
# target-linux\ beside the sources, where every file rustc wrote crossed the 9P
# bridge onto the Windows drive - and was deleted after every build anyway.
LINUX_CACHE_ROOT = "${XDG_CACHE_HOME:-$HOME/.cache}/ag_unlocker"
LINUX_CACHE = LINUX_CACHE_ROOT + "/target-linux"


def wsl_remap_flags(repo_wsl):
    return (
        'export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$HOME=~"$\'\\x1f\''
        + shlex.quote("--remap-path-prefix=" + repo_wsl + "=/ag_unlocker")
        + '$\'\\x1f\'"--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"; '
    )


def build_windows_wsl_helper(manifest, version):
    distro = find_wsl_distro(native_target=LINUX_TARGET)
    if distro is None:
        raise RuntimeError(
            "Windows WSL package unavailable: no WSL distribution has a native "
            "x86_64 Linux Cargo, rustc and C compiler toolchain."
        )

    repo_wsl = _win_to_wsl_path(distro, os.path.dirname(manifest))
    checkout = hashlib.sha256(repo_wsl.encode("utf-8")).hexdigest()
    cache = f"{LINUX_CACHE_ROOT}/target-wsl-helper/{checkout}"
    helper = "ag_wsl_launch"
    manifest_wsl = repo_wsl + "/Cargo.toml"
    cargo = shlex.join([
        "cargo", "build", "--release", "--locked", "--bin", helper,
        "--target", LINUX_TARGET, "--manifest-path", manifest_wsl, CARGO_JSON,
    ])
    command = (
        '. "$HOME/.cargo/env" 2>/dev/null; '
        'unset AG_ACCEPTED_RELEASE_RECORD AG_FULL_VERSION AG_WSL_HELPER_SHA256; '
        f'cd {shlex.quote(repo_wsl)} && T="{cache}" && mkdir -p -- "$T" || exit 1; '
        + wsl_remap_flags(repo_wsl)
        + 'printf "TARGET_DIR=%s\\n" "$T"; '
        + cargo + ' --target-dir "$T"'
    )
    result = _wsl_run(distro, command)
    lines = (result.stdout or "").splitlines()
    if result.returncode:
        diagnostic = "\n".join(line for line in lines if line.lstrip().startswith("error:"))
        raise RuntimeError(
            f"WSL Cargo could not build {helper} (exit {result.returncode})"
            + (f":\n{diagnostic}" if diagnostic else "")
        )
    target_dirs = [line.removeprefix("TARGET_DIR=") for line in lines if line.startswith("TARGET_DIR=")]
    if len(target_dirs) != 1 or not target_dirs[0].startswith("/"):
        raise RuntimeError("WSL Cargo target directory was not received")
    _, executable = BuildReport(lines).require_root_full_version(
        manifest_wsl, helper,
        lambda selected, candidate: wsl_manifest_identity(distro, selected, candidate),
        version,
    )
    if executable != f"{target_dirs[0]}/{LINUX_TARGET}/release/{helper}":
        raise RuntimeError("WSL Cargo helper differs from the selected build artifact")
    quoted = shlex.quote(executable)
    copied = _wsl_run(distro, f"test ! -L {quoted} && test -f {quoted} && cat -- {quoted}", binary=True)
    data = copied.stdout
    if (copied.returncode or len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01"
            or data[16:18] not in (b"\x02\x00", b"\x03\x00") or data[18:20] != b"\x3e\x00"):
        raise RuntimeError("WSL helper readback is not an x86-64 Linux ELF executable")
    return data


def _version_tuple(v):
    """"2.36" -> (2, 36), so glibc versions compare numerically and 2.9 does not
    outrank 2.36 the way a string compare would."""
    out = []
    for part in str(v).split("."):
        try:
            out.append(int(part))
        except ValueError:
            out.append(0)
    return tuple(out)


def linux_glibc_baseline(distro, elf_wsl_path):
    """The highest GLIBC_x.y the ELF asks ld.so for - i.e. the oldest distro it
    actually starts on. Measured, not assumed: the 2.39 above was invisible until
    someone looked, and a silent baseline creep is exactly the failure that ships.
    Returns the version string, or None when binutils is not there to ask."""
    res = _wsl_run(
        distro,
        "objdump -T '%s' 2>/dev/null | grep -o 'GLIBC_[0-9.]*' | sort -V | tail -1"
        % elf_wsl_path,
    )
    if not res or res.returncode != 0:
        return None
    # The last line: wsl.exe may print a notice of its own ahead of it.
    found = ((res.stdout or "").strip().splitlines() or [""])[-1].strip()
    return found[len("GLIBC_"):] if found.startswith("GLIBC_") else None


def _namespace_operation(function):
    @wraps(function)
    def observed(self, *args, **kwargs):
        try:
            return function(self, *args, **kwargs)
        except BaseException as error:
            self._receive_note(error)
            raise
    return observed


class OutputNamespace:
    """Retain the selected workspace and ordinary output-directory chain."""
    def __init__(self, workspace):
        self.phase = 'constructor'
        self.records = []
        self.closes = []
        self._notes = []
        self.optional_errors = []
        self.close_errors = []
        self.emission_errors = []
        self.note_failures = []
        self._record(os.path.abspath(workspace), 'workspace')
        self.stack = ExitStack()
        self.dirs = []
        self.windows = os.name == 'nt'
        try:
            if self.windows:
                import ctypes
                from ctypes import wintypes
                self.ctypes = ctypes
                self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
                class Info(ctypes.Structure):
                    _fields_ = [('attrs', wintypes.DWORD), ('creation', wintypes.FILETIME),
                                ('access', wintypes.FILETIME), ('write', wintypes.FILETIME),
                                ('volume', wintypes.DWORD), ('size_high', wintypes.DWORD),
                                ('size_low', wintypes.DWORD), ('links', wintypes.DWORD),
                                ('index_high', wintypes.DWORD), ('index_low', wintypes.DWORD)]
                self.Info = Info
                self.create = self.kernel.CreateFileW
                self.create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
                self.create.restype = wintypes.HANDLE
                self.info = self.kernel.GetFileInformationByHandle
                self.info.argtypes = [wintypes.HANDLE, ctypes.POINTER(Info)]
                self.info.restype = wintypes.BOOL
                self.close = self.kernel.CloseHandle
                self.close.argtypes = [wintypes.HANDLE]
                self.close.restype = wintypes.BOOL
            self._pin(os.path.abspath(workspace), None, None, workspace_anchor=True)
        except BaseException as error:
            self._receive_note(error)
            try:
                self.stack.close()
            except BaseException as close_error:
                self.close_errors.append(close_error)
                self.closes.append({'resource': 'constructor exit stack', 'result': 'raised',
                                    'error': self._describe_failure(close_error, 'constructor-close-format')})
            self._receive_note(error)
            raise

    def _record(self, path, role):
        for item in self.records:
            if item['path'] == path and item['role'] == role:
                return item
        item = {'path': path, 'role': role, 'mkdir': 'not-called', 'open': 'not-called',
                'identity': 'unreceived', 'association': 'unconfirmed', 'transfer': 'not-called'}
        self.records.append(item)
        return item

    def _annotate(self, error):
        emissions = [{'site': site, 'type': type(failure).__name__, 'errno': getattr(failure, 'errno', None)}
                     for site, failure in self.emission_errors]
        optional = [{'type': type(failure).__name__, 'errno': getattr(failure, 'errno', None)}
                    for failure in self.optional_errors]
        note = f"output namespace: phase={self.phase}; resources={self.records!r}; closes={self.closes!r}; optional={optional!r}; emissions={emissions!r}"
        for original, index in self._notes:
            if original is error:
                error.__notes__[index] = note
                return
        error.add_note(note)
        self._notes.append((error, len(error.__notes__) - 1))

    def _receive_note(self, error):
        try:
            self._annotate(error)
        except BaseException as failure:
            self.emission_errors.append(('annotation', failure))
            self.note_failures.append(failure)

    def _describe_failure(self, error, site):
        try:
            return repr(error)
        except BaseException as failure:
            self.emission_errors.append((site, failure))
            self.note_failures.append(failure)
            return type(error).__name__

    def emit(self, primary, site, action):
        try:
            action()
        except BaseException as failure:
            self.emission_errors.append((site, failure))
            if primary is None:
                primary = failure
            self._receive_note(primary)
        return primary

    def emit_required(self, site, action):
        failure = self.emit(None, site, action)
        if failure is not None:
            raise failure

    def _close_recorded(self, closer, label, state=None):
        failure = None
        try:
            closer()
        except BaseException as error:
            failure = error
            result = {'resource': label, 'result': 'raised', 'error': self._describe_failure(error, 'close-format')}
            self.close_errors.append(error)
        else:
            result = {'resource': label, 'result': 'returned'}
        if state is not None:
            try:
                result['closed'] = state()
            except BaseException as state_error:
                result['closed'] = 'unknown'
                result['closed_error'] = repr(state_error)
        self.closes.append(result)
        if failure is not None:
            self._receive_note(failure)

    def _register(self, closer, label, state=None):
        holder = {'active': True}
        def settle():
            if holder['active']:
                self._close_recorded(closer, label, state)
                holder['active'] = False
        self.stack.callback(settle)
        return holder

    def _close_temporary(self, handle, label):
        active_error = sys.exc_info()[1]
        before = len(self.close_errors)
        self._close_recorded(lambda: self._close_win(handle), label)
        if len(self.close_errors) != before:
            failure = self.close_errors.pop()
            if active_error is None:
                raise failure
            self._receive_note(active_error)

    def _win_open(self, path, access, share, disposition, flags):
        h = self.create(path, access, share, None, disposition, flags, None)
        if h == self.ctypes.c_void_p(-1).value:
            raise self.ctypes.WinError(self.ctypes.get_last_error())
        return h

    def _win_info(self, handle):
        item = self.Info()
        if not self.info(handle, self.ctypes.byref(item)):
            raise self.ctypes.WinError(self.ctypes.get_last_error())
        return item

    def _close_win(self, handle):
        if not self.close(handle):
            raise self.ctypes.WinError(self.ctypes.get_last_error())

    @_namespace_operation
    def _pin(self, path, parent, name, workspace_anchor=False):
        self.phase = 'directory-open'
        record = self._record(path, 'workspace' if workspace_anchor else 'directory')
        if self.windows:
            flags = 0x02000000 | (0 if workspace_anchor else 0x00200000)
            try:
                handle = self._win_open(path, 0x80000000, 1, 3, flags)
            except BaseException:
                record['open'] = 'returned-failure'
                raise
            record['open'] = 'returned-success'
            self._register(lambda: self._close_win(handle), path)
            self.phase = 'directory-identity'
            info = self._win_info(handle)
            if not info.attrs & 0x10 or (not workspace_anchor and info.attrs & 0x400):
                raise OSError(f"output directory is not ordinary: {path}")
            identity = (info.volume, info.index_high, info.index_low)
        else:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            if not workspace_anchor:
                flags |= os.O_NOFOLLOW
            try:
                handle = os.open(path if parent is None else name, flags, dir_fd=None if parent is None else parent['handle'])
            except BaseException:
                record['open'] = 'returned-failure'
                raise
            record['open'] = 'returned-success'
            self._register(lambda: os.close(handle), path)
            self.phase = 'directory-identity'
            info = os.fstat(handle)
            if not stat.S_ISDIR(info.st_mode):
                raise OSError(f"output directory is not ordinary: {path}")
            identity = (info.st_dev, info.st_ino)
        item = {'path': path, 'parent': parent, 'name': name, 'handle': handle, 'id': identity}
        record['identity'] = identity
        self.dirs.append(item)
        self.recheck()
        record['association'] = 'received'
        return item

    @_namespace_operation
    def recheck(self):
        self.phase = 'association-recheck'
        for item in self.dirs:
            record = self._record(item['path'], 'workspace' if item['parent'] is None else 'directory')
            record['association'] = 'recheck-pending'
            if self.windows:
                held = self._win_info(item['handle'])
                if (held.volume, held.index_high, held.index_low) != item['id'] or held.attrs & 0x400:
                    raise OSError(f"output directory changed: {item['path']}")
                flags = 0x02000000 | (0 if item['parent'] is None else 0x00200000)
                record['recheck_open'] = 'not-called'
                record['recheck_identity'] = 'unreceived'
                try:
                    check = self._win_open(item['path'], 0x80000000, 7, 3, flags)
                except BaseException:
                    record['recheck_open'] = 'returned-failure'
                    raise
                record['recheck_open'] = 'returned-success'
                try:
                    now = self._win_info(check)
                    record['recheck_identity'] = (now.volume, now.index_high, now.index_low)
                    if not now.attrs & 0x10 or (item['parent'] is not None and now.attrs & 0x400) or (now.volume, now.index_high, now.index_low) != item['id']:
                        raise OSError(f"output association changed; partial output retained: {item['path']}")
                finally:
                    self._close_temporary(check, item['path'] + ' recheck')
            else:
                current = (os.stat(item['path']) if item['parent'] is None else
                           os.stat(item['name'], dir_fd=item['parent']['handle'], follow_symlinks=False))
                if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != item['id']:
                    raise OSError(f"output association changed; partial output retained: {item['path']}")
            record['association'] = 'received'

    @_namespace_operation
    def child(self, parent, name, create=False):
        self.recheck()
        path = os.path.join(parent['path'], name)
        record = self._record(path, 'directory')
        if create:
            self.phase = 'directory-mkdir'
            try:
                if self.windows:
                    os.mkdir(path)
                else:
                    os.mkdir(name, dir_fd=parent['handle'])
                record['mkdir'] = 'returned-success'
            except FileExistsError:
                record['mkdir'] = 'collision'
            except BaseException:
                record['mkdir'] = 'returned-failure'
                raise
        return self._pin(path, parent, name)

    @_namespace_operation
    def fresh(self, parent):
        while True:
            name = 'build-' + secrets.token_hex(16)
            path = os.path.join(parent['path'], name)
            prior_record = any(item['path'] == path and item['role'] == 'directory' for item in self.records)
            record = self._record(path, 'directory')
            self.phase = 'directory-mkdir'
            try:
                if self.windows:
                    os.mkdir(os.path.join(parent['path'], name))
                else:
                    os.mkdir(name, dir_fd=parent['handle'])
                record['mkdir'] = 'returned-success'
                break
            except FileExistsError:
                if not prior_record:
                    record['mkdir'] = 'collision'
                    self.records.remove(record)
                continue
            except BaseException:
                record['mkdir'] = 'returned-failure'
                raise
        return self.child(parent, name)

    @_namespace_operation
    def new_child(self, parent, name):
        self.recheck()
        self.phase = 'directory-mkdir'
        record = self._record(os.path.join(parent['path'], name), 'directory')
        try:
            if self.windows:
                os.mkdir(os.path.join(parent['path'], name))
            else:
                os.mkdir(name, dir_fd=parent['handle'])
            record['mkdir'] = 'returned-success'
        except BaseException:
            record['mkdir'] = 'returned-failure'
            raise
        return self.child(parent, name)

    @_namespace_operation
    def file(self, directory, name):
        self.recheck()
        path = os.path.join(directory['path'], name)
        record = self._record(path, 'file')
        self.phase = 'file-create'
        if self.windows:
            import msvcrt
            try:
                handle = self._win_open(path, 0xC0000000, 1, 1, 0x00200000)
            except BaseException:
                record['open'] = 'returned-failure'
                raise
            record['open'] = 'returned-success'
            raw = self._register(lambda: self._close_win(handle), path + ' raw handle')
            self.phase = 'file-identity'
            native = self._win_info(handle)
            record['identity'] = (native.volume, native.index_high, native.index_low)
            self.phase = 'handle-to-fd'
            try:
                fd = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
            except BaseException:
                record['transfer'] = 'handle-to-fd-failed'
                raise
            raw['active'] = False
            record['transfer'] = 'handle-to-fd-returned'
        else:
            try:
                fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory['handle'])
            except BaseException:
                record['open'] = 'returned-failure'
                raise
            record['open'] = 'returned-success'
        raw_fd = self._register(lambda: os.close(fd), path + ' fd')
        if not self.windows:
            self.phase = 'file-identity'
            info = os.fstat(fd)
            record['identity'] = (info.st_dev, info.st_ino)
        self.phase = 'fd-to-file'
        try:
            file = os.fdopen(fd, 'w+b')
        except BaseException as error:
            record['transfer'] = 'fd-to-file-failed'
            raise
        raw_fd['active'] = False
        record['transfer'] = 'fd-to-file-returned'
        self._register(file.close, path + ' file', lambda: file.closed)
        return file

    @_namespace_operation
    def receive(self, directory, name, file):
        path = os.path.join(directory['path'], name)
        record = self._record(path, 'file')
        record['association'] = 'recheck-pending'
        self.phase = 'file-flush-sync'
        file.flush()
        os.fsync(file.fileno())
        self.phase = 'file-association'
        self.recheck()
        self.phase = 'file-association'
        held = os.fstat(file.fileno())
        if self.windows:
            import msvcrt
            held_info = self._win_info(msvcrt.get_osfhandle(file.fileno()))
            record['recheck_open'] = 'not-called'
            record['recheck_identity'] = 'unreceived'
            try:
                handle = self._win_open(os.path.join(directory['path'], name), 0x80000000, 7, 3, 0x00200000)
            except BaseException:
                record['recheck_open'] = 'returned-failure'
                raise
            record['recheck_open'] = 'returned-success'
            try:
                info = self._win_info(handle)
                record['recheck_identity'] = (info.volume, info.index_high, info.index_low)
                if info.attrs & (0x400 | 0x10) or (held_info.volume, held_info.index_high, held_info.index_low) != (info.volume, info.index_high, info.index_low):
                    raise OSError(f"output file association changed: {name}")
            finally:
                self._close_temporary(handle, path + ' recheck')
        else:
            current = os.stat(name, dir_fd=directory['handle'], follow_symlinks=False)
            if not stat.S_ISREG(current.st_mode) or (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino):
                raise OSError(f"output file association changed; partial retained: {name}")
        record['association'] = 'received'
        return path

    def __enter__(self):
        return self

    def __exit__(self, kind, error, tb):
        if error is not None:
            self._receive_note(error)
        try:
            self.stack.close()
        except BaseException as close_error:
            self.closes.append({'resource': 'exit stack', 'result': 'raised', 'error': self._describe_failure(close_error, 'exit-stack-format')})
            self.close_errors.append(close_error)
        primary = error if error is not None else (self.close_errors[0] if self.close_errors else (self.note_failures[0] if self.note_failures else None))
        for original, _ in self._notes:
            self._receive_note(original)
        if primary is None and self.note_failures:
            primary = self.note_failures[0]
        for original in self.optional_errors:
            primary = self.emit(primary, 'linux-finalization', lambda: print(f"[WARNING] Linux output finalization: {original}; " + ' | '.join(getattr(original, '__notes__', ()))))
        for original, _ in self._notes:
            self._receive_note(original)
        if primary is None and self.note_failures:
            primary = self.note_failures[0]
        if primary is not None:
            self._receive_note(primary)
        if primary is not None and error is None:
            self.phase = 'finalization'
            self._receive_note(primary)
            raise primary
        return False


def copy_exclusive(source, owner, directory, name):
    """Copy through the retained output owner, and receive its exact bytes."""
    target = owner.file(directory, name)
    owner.phase = 'file-copy-write'
    with open(source, 'rb') as src:
        expected = hashlib.sha256()
        while True:
            data = src.read(1024 * 1024)
            if not data:
                break
            expected.update(data)
            target.write(data)
        if not owner.windows:
            os.fchmod(target.fileno(), stat.S_IMODE(os.fstat(src.fileno()).st_mode))
    owner.receive(directory, name, target)
    target.seek(0)
    actual = hashlib.sha256()
    while True:
        data = target.read(1024 * 1024)
        if not data:
            break
        actual.update(data)
    if actual.digest() != expected.digest():
        raise OSError(f"output copy readback differs: {name}")
    owner.receive(directory, name, target)
    return target


def write_exclusive_bytes(data, owner, directory, name):
    file = owner.file(directory, name)
    owner.phase = 'file-copy-write'
    file.write(data)
    path = owner.receive(directory, name, file)
    file.seek(0)
    if file.read() != data:
        raise OSError(f"output write readback differs: {name}")
    owner.receive(directory, name, file)
    return file, path


def write_owner_tool(source, application_root=None):
    with OutputNamespace(os.getcwd()) as owner:
        dist = owner.child(owner.dirs[0], 'dist', create=True)
        if application_root is not None and dist['id'] == application_root['id']:
            raise OSError('tool namespace aliases application output')
        parent = owner.child(dist, 'owner-tools', create=True)
        if application_root is not None and parent['id'] == application_root['id']:
            raise OSError('tool namespace aliases application output')
        root = owner.fresh(parent)
        if application_root is not None and root['id'] == application_root['id']:
            raise OSError('tool namespace aliases application output')
        owner.emit_required('tool-root', lambda: print(f"[INFO] Каталог генератора: {root['path']}"))
        data = source.encode('utf-8')
        tool, path = write_exclusive_bytes(data, owner, root, 'dist_keygen.py')
        owner.emit_required('tool-ready', lambda: print(f"Ваш генератор ключей для этой версии: {path}"))
        loader = ("import sys; source=sys.stdin.buffer.read().decode('utf-8'); module={'__name__':'dist_keygen'}; "
                  "exec(compile(source,'<owned-key-tool>','exec'),module); "
                  "[print(module['generate_key']()) for _ in range(5)]")
        subprocess.run([sys.executable, '-I', '-B', '-c', loader], input=source,
                       text=True, encoding='utf-8', check=True)
        owner.receive(root, 'dist_keygen.py', tool)
        return path


def build_linux_bundle(version, output_owner, release):
    """Builds the Linux ELF in WSL and assembles release/AG_<ver>_linux/ (+ .tar.gz)
    with the double-click launcher assets. Best-effort; returns the bundle dir or
    None. Never raises - the Windows build must not depend on it."""
    import tarfile

    try:
        distro = find_wsl_distro()
        if not distro:
            output_owner.emit_required('linux-availability', lambda: print("[i] Linux-сборка пропущена: не найден WSL-дистрибутив с cargo "
                  "(установите rustup в WSL: 'curl https://sh.rustup.rs -sSf | sh')."))
            return None
        output_owner.emit_required('linux-start', lambda: print(f"[INFO] Сборка Linux-версии в WSL ({distro})..."))

        repo_wsl = _win_to_wsl_path(distro, os.getcwd())
        probe = _wsl_run(
            distro,
            '. "$HOME/.cargo/env" 2>/dev/null; '
            "command -v cargo-zigbuild >/dev/null && echo OK",
        )
        has_zigbuild = bool(probe and probe.returncode == 0 and "OK" in (probe.stdout or ""))

        if has_zigbuild:
            cargo_cmd = "cargo zigbuild --release --bin ag_unlocker --target %s.%s" % (
                LINUX_TARGET, LINUX_GLIBC)
            elf_in_cache = "%s/release/ag_unlocker" % LINUX_TARGET
        else:
            # Still build - the bundle is better than no bundle - but say plainly
            # what the fallback costs, because the damage is invisible in the
            # output and lands on the user's machine as a refusal to start.
            output_owner.emit_required('linux-native-warning', lambda: print(f"[WARNING] cargo-zigbuild не найден в WSL - собираю нативно. Бандл "
                  f"потребует glibc сборочной машины, а не {LINUX_GLIBC}, и не запустится "
                  f"на дистрибутивах старше неё."))
            output_owner.emit_required('linux-native-hint', lambda: print("          Поставить: pip3 install --user --break-system-packages ziglang "
                  "&& cargo install cargo-zigbuild"))
            cargo_cmd = "cargo build --release --bin ag_unlocker"
            elf_in_cache = "release/ag_unlocker"

        # Cargo JSON and console output are retained in the cache, and only the
        # log's tail comes back here. No pipe: cargo's own exit status is the one
        # that counts. Through `| tail -3` it used to be tail's, so a failed build
        # was noticed only because target-linux had been wiped - over a kept cache
        # it would have shipped the previous ELF.
        # The paths rewritten are the distro's own ($HOME, CARGO_HOME), and the
        # checkout as WSL sees it. \x1f-separated, so a space in a path is safe.
        remap = wsl_remap_flags(repo_wsl)
        # The Linux build and its package must use the same validated version
        # as the Windows artifact.
        if not re.fullmatch(r"[0-9A-Za-z._-]+", version):
            raise RuntimeError("received native full version is unsafe for Linux transport")
        full_version = 'export AG_FULL_VERSION="%s"; ' % version
        build_cmd = (
            '. "$HOME/.cargo/env"; cd %s || exit 1; T="%s"; mkdir -p "$T" || exit 1; '
            + remap + full_version +
            'echo "TARGET_DIR=$T"; '
            '%s --target-dir "$T" %s >"$T/messages.json" 2>"$T/build.log"; rc=$?; '
            'if [ $rc -eq 0 ]; then tail -n 3 "$T/build.log"; else tail -n 40 "$T/build.log"; fi; '
            'exit $rc'
        ) % (shlex.quote(repo_wsl), LINUX_CACHE, cargo_cmd, CARGO_JSON)
        res = _wsl_run(distro, build_cmd, capture=True)
        lines = [l.rstrip() for l in (res.stdout or "").splitlines() if l.strip()]
        marker = [l.strip() for l in lines if l.strip().startswith("TARGET_DIR=")]
        target_dir = marker[0][len("TARGET_DIR="):] if marker else None
        shown = "\n".join(l for l in lines if not l.strip().startswith("TARGET_DIR="))
        if shown:
            output_owner.emit_required('linux-build-output', lambda: print(shown))
        if res.returncode != 0 or not target_dir:
            output_owner.emit_required('linux-build-failure', lambda: print("[WARNING] Linux-сборка не удалась (см. вывод выше) - отгружён только .exe."))
            return None

        # Use the existing WSL transport; target_dir is the just-received target
        # marker from our own command, not an arbitrary external selector.
        messages = _wsl_run(distro, 'cat -- ' + shlex.quote(target_dir + '/messages.json'), capture=True)
        if messages.returncode != 0:
            raise RuntimeError("Linux Cargo messages could not be received")
        linux_report = BuildReport((messages.stdout or "").splitlines())
        _, linux_executable = linux_report.require_root_full_version(
            repo_wsl + "/Cargo.toml", "ag_unlocker",
            lambda selected, candidate: wsl_manifest_identity(distro, selected, candidate), version)

        elf = "%s/%s" % (target_dir, elf_in_cache)
        if linux_executable != elf:
            raise RuntimeError("Linux Cargo executable differs from selected bundle input")
        if _wsl_run(distro, 'test -f "%s"' % elf).returncode != 0:
            output_owner.emit_required('linux-elf-missing', lambda: print(f"[WARNING] ELF не найден по пути {elf} - Linux-бандл не собран."))
            return None

        # Report the baseline that was actually produced, and complain when it is
        # not the one asked for - the whole point of pinning it is lost if nobody
        # checks (that is how the GLIBC_2.39 bundle shipped).
        baseline = linux_glibc_baseline(distro, elf)
        if baseline is None:
            output_owner.emit_required('linux-baseline-unknown', lambda: print("[i] Планку glibc проверить нечем (нет objdump в WSL)."))
        elif has_zigbuild and _version_tuple(baseline) > _version_tuple(LINUX_GLIBC):
            output_owner.emit_required('linux-baseline-warning', lambda: print(f"[WARNING] ELF требует glibc {baseline}, хотя собирался под "
                  f"{LINUX_GLIBC} - планка не удержана, проверьте цель сборки."))
        else:
            output_owner.emit_required('linux-baseline', lambda: print(f"[INFO] Linux-бандл требует glibc {baseline} и старше."))

        output_root = output_owner.fresh(output_owner.child(release, 'linux', create=True))
        bundle_name = f"AG_{version}_linux"
        bundle = output_owner.new_child(output_root, bundle_name)
        output_owner.emit_required('linux-bundle-start', lambda: print(f"[INFO] Начат Linux-бандл: {bundle['path']}"))

        # The ELF - on the distro's filesystem, so WSL copies it across - plus the
        # launcher assets from linux/.
        elf_file = output_owner.file(bundle, 'ag_unlocker')
        output_owner.phase = 'linux-binary-child'
        copied = subprocess.run(['wsl.exe', '-d', distro, '-e', 'bash', '-lc', 'cat -- ' + shlex.quote(elf)],
                                stdout=elf_file, stderr=subprocess.PIPE, env=dict(os.environ, WSL_UTF8='1'))
        if copied.returncode != 0:
            output_owner.receive(bundle, 'ag_unlocker', elf_file)
            error = RuntimeError(f"ELF copy failed ({copied.returncode}): {copied.stderr!r}")
            output_owner._receive_note(error)
            output_owner.optional_errors.append(error)
            output_owner.emit_required('linux-copy-failure', lambda: print(f"[WARNING] ELF не скопирован в бандл: {error}; " + ' | '.join(error.__notes__)))
            return None
        output_owner.receive(bundle, 'ag_unlocker', elf_file)
        files = [('ag_unlocker', elf_file)]
        for name in ("launch.sh", "install.sh", "Antigravity-Unlocker.desktop", "README.md"):
            src = os.path.join("linux", name)
            if os.path.exists(src):
                files.append((name, copy_exclusive(src, output_owner, bundle, name)))

        # Best-effort icon: convert icon.ico -> icon.png if Pillow is present.
        try:
            from PIL import Image
            ico = "icon.ico"
            if os.path.exists(ico):
                img = Image.open(ico)
                # Largest frame for a crisp menu icon.
                if hasattr(img, "n_frames") and img.n_frames > 1:
                    best, best_area = 0, 0
                    for i in range(img.n_frames):
                        img.seek(i)
                        area = img.size[0] * img.size[1]
                        if area > best_area:
                            best, best_area = i, area
                    img.seek(best)
                icon = output_owner.file(bundle, 'icon.png')
                output_owner.phase = 'icon-write'
                img.convert("RGBA").save(icon, format="PNG")
                output_owner.receive(bundle, 'icon.png', icon)
                files.append(('icon.png', icon))
        except ImportError:
            pass  # Icon is cosmetic; the .desktop falls back to a theme icon.

        # A .tar.gz for easy transfer to the VM, with the exec bits preserved.
        tar_name = bundle_name + '.tar.gz'
        def _exec_bits(tarinfo):
            base = os.path.basename(tarinfo.name)
            if base in ("ag_unlocker", "launch.sh", "install.sh") or base.endswith(".desktop"):
                tarinfo.mode = 0o755
            return tarinfo

        archive = output_owner.file(output_root, tar_name)
        output_owner.phase = 'archive-write'
        with tarfile.open(fileobj=archive, mode="w:gz") as tar:
            directory = tarfile.TarInfo(bundle_name)
            directory.type = tarfile.DIRTYPE
            output_owner.recheck()
            directory_stat = (os.stat(bundle['path']) if output_owner.windows else os.fstat(bundle['handle']))
            directory.mode = stat.S_IMODE(directory_stat.st_mode)
            tar.addfile(directory)
            for name, item in files:
                output_owner.receive(bundle, name, item)
                item.seek(0)
                info = tar.gettarinfo(name=name, arcname=bundle_name + '/' + name, fileobj=item)
                tar.addfile(_exec_bits(info), item)
        for name, item in files:
            output_owner.receive(bundle, name, item)
        tar_path = output_owner.receive(output_root, tar_name, archive)

        wsl_home = _wsl_run(distro, 'printf %s "$HOME"')
        wsl_home = ((wsl_home.stdout or "").strip().splitlines() or [""])[-1].strip() if wsl_home else ""
        check_shipped_binary(os.path.join(bundle['path'], "ag_unlocker"),
                             [wsl_home + "/", "/.cargo/registry"], windows=False, owned_file=elf_file, output_owner=output_owner)

        elf_size = os.fstat(elf_file.fileno()).st_size // 1024
        output_owner.receive(bundle, 'ag_unlocker', elf_file)
        output_owner.emit_required('linux-bundle-ready', lambda: print(f"[УСПЕХ] Linux-бандл: {bundle['path']} (ELF {elf_size} КБ)"))
        output_owner.emit_required('linux-archive-ready', lambda: print(f"        Архив для переноса на машину: {tar_path}"))

        return bundle['path']
    except Exception as e:
        if any(e is failure for _, failure in output_owner.emission_errors):
            raise
        output_owner._receive_note(e)
        output_owner.optional_errors.append(e)
        output_owner.emit_required('linux-optional-warning', lambda: print(f"[WARNING] Linux-сборка пропущена из-за ошибки: {e}; " + ' | '.join(e.__notes__)))
        return None


def read_base_secret(auth_rs_path):
    """Reads the committed base secret straight from src\\auth.rs, so the source
    is the single source of truth for both the binary and the key generator."""
    with open(auth_rs_path, 'r', encoding='utf-8') as f:
        src = f.read()
    m = re.search(r'const\s+LICENSE_BASE_SECRET\s*:\s*&str\s*=\s*"([^"]*)"', src)
    if not m:
        raise RuntimeError("LICENSE_BASE_SECRET not found in src/auth.rs")
    return m.group(1)


def main(personal=False):
    # Set correct working directory to where this script is located
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    print("[INFO] Starting build process...")

    cargo_version = read_package_version()
    manifest = os.path.abspath("Cargo.toml")
    cargo_env = os.environ.copy()
    cargo_env.pop("AG_WSL_HELPER_SHA256", None)
    release_receiving = None
    release_args = []
    if "AG_ACCEPTED_RELEASE_RECORD" in cargo_env:
        if not cargo_env.get("AG_RELEASE_SOURCE_MANIFEST"):
            raise RuntimeError("AG_RELEASE_SOURCE_MANIFEST is required for an accepted release")
        cargo_env["AG_RELEASE_BUILD_REQUEST"] = secrets.token_hex(16)
        target = "x86_64-pc-windows-msvc"
        release_receiving = expected_release_receiving(cargo_env, target)
        release_args.extend(["--locked", "--target", target])
    else:
        kind = "personal candidate" if personal else "candidate"
        print(f"[INFO] Private {kind} build. No accepted release receipt was requested.")
    if personal:
        release_args.extend(["--features", "personal-build"])
    home = os.path.expanduser("~")
    cargo_home = os.environ.get("CARGO_HOME") or os.path.join(home, ".cargo")
    cargo_env.pop("RUSTFLAGS", None)
    cargo_env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(
        config_rustflags("x86_64-pc-windows-msvc") + remap_prefix_flags(home, os.getcwd(), cargo_home))
    helper_bytes = build_windows_wsl_helper(manifest, cargo_version)
    helper_digest = hashlib.sha256(helper_bytes).hexdigest()
    cargo_env["AG_WSL_HELPER_SHA256"] = helper_digest
    installer_path = os.path.join("wsl", "install-helper.sh")
    with open(installer_path, "rb") as installer:
        installer_bytes = installer.read()
    target_dir = os.path.abspath("target")
    print("[INFO] Запуск компиляции (Release mode)...")
    build = cargo_build(["cargo", "build", "--release", "--bin", "ag_unlocker", "--target-dir", target_dir] + release_args, env=cargo_env)
    version, built_exe = build.require_root_full_version(
        manifest, "ag_unlocker", os.path.samefile, cargo_version, release_receiving,
        helper_digest=helper_digest)
    if not os.path.isfile(built_exe):
        raise RuntimeError("cargo не сообщил существующий собранный exe")
    with open(installer_path, "rb") as installer:
        if installer.read() != installer_bytes:
            raise RuntimeError("WSL installer source changed during Windows compilation")
    print(f"[INFO] Build version: {version}")

    # The owner marker enables key generation for builds that use local keys.
    generate_owner_tool = not personal and os.path.exists(".secrets.json")

    if generate_owner_tool:
        # The owner tool uses the same base and version salt as the build.
        base_secret = read_base_secret(r"src\auth.rs")
        key_secret_phrase = f"{base_secret}{LICENSE_VERSION_SEP}{cargo_version}"
        keygen_code = """import sys
import os
import subprocess
import traceback

SECRET_PHRASE = """ + repr(key_secret_phrase) + """

def copy_to_clipboard(text):
    try:
        import ctypes
        if not ctypes.windll.user32.OpenClipboard(None):
            return False
        ctypes.windll.user32.EmptyClipboard()
        hCd = ctypes.windll.kernel32.GlobalAlloc(2, len(text) + 1)
        if not hCd:
            ctypes.windll.user32.CloseClipboard()
            return False
        pCd = ctypes.windll.kernel32.GlobalLock(hCd)
        if not pCd:
            ctypes.windll.user32.CloseClipboard()
            return False
        ctypes.cdll.msvcrt.strcpy(ctypes.c_char_p(pCd), text.encode('ascii'))
        ctypes.windll.kernel32.GlobalUnlock(hCd)
        ctypes.windll.user32.SetClipboardData(1, hCd)
        ctypes.windll.user32.CloseClipboard()
        return True
    except Exception:
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", f"Set-Clipboard -Value '{text}'"],
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            return True
        except:
            return False

def generate_key():
    import hashlib
    import random
    import string
    chars = string.ascii_uppercase + string.digits
    nonce = ''.join(random.choices(chars, k=12))
    data = f"{nonce}{SECRET_PHRASE}".encode('utf-8')
    signature = hashlib.sha256(data).hexdigest().upper()[:12]
    return f"{nonce}{signature}"

def run_gui_tk():
    import tkinter as tk
    from tkinter import messagebox

    def copy_selected():
        try:
            selected_idx = listbox.curselection()
            if not selected_idx:
                messagebox.showwarning("Warning", "Please select a key first!")
                return
            selected_key = listbox.get(selected_idx[0])
            root.clipboard_clear()
            root.clipboard_append(selected_key)
            root.update()
            status_label.config(text="Selected key copied!", fg="#a6e3a1")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def copy_all():
        try:
            all_keys = listbox.get(0, tk.END)
            keys_str = "\\n".join(all_keys)
            root.clipboard_clear()
            root.clipboard_append(keys_str)
            root.update()
            status_label.config(text="All 5 keys copied!", fg="#a6e3a1")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    global root, listbox, status_label
    root = tk.Tk()
    root.title("Antigravity Keygen v""" + version + """")
    root.geometry("450x420")
    root.configure(bg="#1e1e2e")
    root.resizable(False, False)
    
    title_lbl = tk.Label(root, text="Antigravity Key Generator", bg="#1e1e2e", fg="#89b4fa", font=("Segoe UI", 16, "bold"))
    title_lbl.pack(pady=15)
    
    frame = tk.Frame(root, bg="#1e1e2e")
    frame.pack(pady=10)
    
    listbox = tk.Listbox(
        frame, 
        bg="#181825", 
        fg="#a6e3a1", 
        font=("Consolas", 14, "bold"), 
        width=28, 
        height=5, 
        bd=0, 
        highlightbackground="#313244", 
        highlightcolor="#89b4fa", 
        highlightthickness=2,
        selectbackground="#45475a",
        selectforeground="#ffffff",
        activestyle="none"
    )
    listbox.pack(side=tk.LEFT, fill=tk.BOTH)
    
    for _ in range(5):
        listbox.insert(tk.END, generate_key())
    
    listbox.selection_set(0)
    
    status_label = tk.Label(root, text="Select a key to copy", bg="#1e1e2e", fg="#a6adc8", font=("Segoe UI", 10))
    status_label.pack(pady=5)
    
    btn_style = {
        "bg": "#313244",
        "fg": "#cdd6f4",
        "activebackground": "#45475a",
        "activeforeground": "#ffffff",
        "font": ("Segoe UI", 11, "bold"),
        "bd": 0,
        "height": 2,
        "width": 18,
        "cursor": "hand2"
    }
    
    btn_frame = tk.Frame(root, bg="#1e1e2e")
    btn_frame.pack(pady=15)
    
    btn_copy_sel = tk.Button(btn_frame, text="Copy Selected", command=copy_selected, **btn_style)
    btn_copy_sel.pack(side=tk.LEFT, padx=10)
    
    btn_copy_all = tk.Button(btn_frame, text="Copy All", command=copy_all, **btn_style)
    btn_copy_all.pack(side=tk.LEFT, padx=10)
    
    def on_enter(e):
        e.widget.config(bg="#45475a")
    def on_leave(e):
        e.widget.config(bg="#313244")
    
    btn_copy_sel.bind("<Enter>", on_enter)
    btn_copy_sel.bind("<Leave>", on_leave)
    btn_copy_all.bind("<Enter>", on_enter)
    btn_copy_all.bind("<Leave>", on_leave)
    
    root.mainloop()

def run_gui_dpg():
    import dearpygui.dearpygui as dpg

    keys = [generate_key() for _ in range(5)]
    selected_idx = 0

    dpg.create_context()
    dpg.create_viewport(title='Antigravity Keygen v""" + version + """', width=450, height=420, resizable=False)
    dpg.setup_dearpygui()

    def copy_selected_callback():
        nonlocal selected_idx
        text = keys[selected_idx]
        if copy_to_clipboard(text):
            dpg.set_value(status_text, "Selected key copied!")
        else:
            dpg.set_value(status_text, "Failed to copy key.")

    def copy_all_callback():
        text = "\\n".join(keys)
        if copy_to_clipboard(text):
            dpg.set_value(status_text, "All 5 keys copied!")
        else:
            dpg.set_value(status_text, "Failed to copy keys.")

    def listbox_callback(sender, app_data):
        nonlocal selected_idx
        selected_idx = keys.index(app_data)

    with dpg.window(label="Main Window", width=450, height=420, no_title_bar=True, no_move=True, no_resize=True):
        dpg.add_spacer(height=15)
        dpg.add_text("Antigravity Key Generator", color=[137, 180, 250])
        dpg.add_spacer(height=15)
        
        dpg.add_listbox(items=keys, callback=listbox_callback, width=410, num_items=5)
        dpg.add_spacer(height=10)
        
        status_text = dpg.add_text("Select a key to copy", color=[166, 173, 200])
        dpg.add_spacer(height=15)
        
        with dpg.group(horizontal=True):
            dpg.add_button(label="Copy Selected", callback=copy_selected_callback, width=195, height=40)
            dpg.add_button(label="Copy All", callback=copy_all_callback, width=195, height=40)

    with dpg.theme() as global_theme:
        with dpg.theme_component(dpg.mvAll):
            dpg.add_theme_color(dpg.mvThemeCol_WindowBg, [30, 30, 46])
            dpg.add_theme_color(dpg.mvThemeCol_Button, [49, 50, 68])
            dpg.add_theme_color(dpg.mvThemeCol_ButtonHover, [69, 71, 90])
            dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, [137, 180, 250])
            dpg.add_theme_color(dpg.mvThemeCol_FrameBg, [24, 24, 37])
            dpg.add_theme_color(dpg.mvThemeCol_Text, [205, 214, 244])

    dpg.bind_theme(global_theme)
    dpg.show_viewport()
    dpg.start_dearpygui()
    dpg.destroy_context()

def run_console():
    os.system('color 0A' if os.name == 'nt' else 'clear')
    os.system('cls' if os.name == 'nt' else 'clear')
    print("Ключи для v""" + version + """\\n")
    for _ in range(5):
        print(generate_key())
    
    print()
    input("Press Enter to exit...")

def main():
    try:
        run_gui_tk()
        return
    except ImportError:
        try:
            import dearpygui.dearpygui
            run_gui_dpg()
            return
        except ImportError:
            print("GUI module 'tkinter' is missing. Installing 'dearpygui' as alternative...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "dearpygui"])
                import dearpygui.dearpygui
                run_gui_dpg()
                return
            except Exception:
                pass
    except Exception as e:
        pass

    run_console()

if __name__ == "__main__":
    main()
"""

    output_owner = OutputNamespace(os.getcwd())

    try:
        release = output_owner.child(output_owner.dirs[0], 'release', create=True)
        if release_receiving is None:
            release = output_owner.child(release, 'private-candidates', create=True)
        output_root = output_owner.fresh(release)
        for name, data in (
            ('ag_wsl_launch', helper_bytes),
            ('helper.sha256', (helper_digest + '\n').encode('ascii')),
            ('install-helper.sh', installer_bytes),
        ):
            write_exclusive_bytes(data, output_owner, output_root, name)
        out_name = f"AG_{version}.exe"
        # Copy, never move. The exe cargo uplifts is a hardlink to its copy in
        # deps\, which the cache keeps now; moved, the shipped exe would stay one
        # file with the cache's, and whatever touches either touches both.
        out_file = copy_exclusive(built_exe, output_owner, output_root, out_name)
        out_path = output_owner.receive(output_root, out_name, out_file)
        check_shipped_binary(out_path, [home + "\\", "\\.cargo\\registry"], windows=True, owned_file=out_file, output_owner=output_owner)

        # Shrink the exe in place; it stays a runnable AG_<ver>.exe.
        if UPX_ENABLED:
            raise RuntimeError("UPX requires a handle-bound output transformer")
        else:
            output_owner.emit_required('application-compression', lambda: print("[INFO] UPX-сжатие отключено — отгружается несжатый .exe "
                  "(меньше ложных срабатываний антивирусов)."))

        output_owner.receive(output_root, out_name, out_file)

        # Provenance record. Written after compression so the hash is of the file
        # that actually ships.
        # Row keyed by the full shipped version (e.g. 2.8.1.1); the token is
        # derived from cargo_version (2.8.1) to match the value baked into the
        # binary, since a 4th version digit doesn't change the canary salt.
        token = release_token(cargo_version)
        output_owner.emit_required('canary-token', lambda: print(f"\n[i] Канарейка релиза: {token}"))
        if release_receiving is not None:
            ledger = record_canary(version, token, out_path, owned_file=out_file)
            output_owner.emit_required('canary-ledger', lambda: print(f"    Записано в {ledger}. Проверить любой файл/бинарник:"))
        output_owner.emit_required('canary-help', lambda: print(f"    python tools\\canary_check.py <путь>"))

        # The separate Linux desktop bundle is optional for ordinary private builds.
        if release_receiving is None and not personal:
            build_linux_bundle(version, output_owner, release)

        if generate_owner_tool:
            try:
                write_owner_tool(keygen_code, output_root)
            except Exception as error:
                output_owner.emit(error, 'tool-error', lambda: print(f"[ОШИБКА] Генератор не завершён; приложение сохранено: {out_path}: {error}"))
                raise
        elif personal:
            output_owner.emit_required('key-info', lambda: print("\nЛичная сборка: для локального входа ключ не нужен."))
        else:
            output_owner.emit_required('key-info', lambda: print("\nДля работы необходим ключ - получить его можно бесплатно в группе t.me/nova_txt"))
        output_owner.receive(output_root, out_name, out_file)

    except subprocess.CalledProcessError as e:
        output_owner._receive_note(e)
        output_owner.emit(e, 'main-command-error', lambda: print(f"\n[ОШИБКА] Сборка завершилась с ошибкой: {e}; " + ' | '.join(e.__notes__)))
        raise
    except Exception as e:
        output_owner._receive_note(e)
        output_owner.emit(e, 'main-error', lambda: print(f"\n[ОШИБКА] Непредвиденная ошибка сборки: {e}; " + ' | '.join(e.__notes__)))
        raise
    finally:
        pending_info = sys.exc_info()
        pending = pending_info[1]
        finalized_error = None
        try:
            output_owner.__exit__(*pending_info)
        except BaseException as error:
            finalized_error = error
            if pending is not None and error is not pending:
                output_owner.close_errors.append(error)
                output_owner._receive_note(pending)
        finally:
            primary = pending if pending is not None else finalized_error
            if primary is not None:
                output_owner.emit(primary, 'main-final-note', lambda: print("[INFO] Завершение владельца вывода: " + ' | '.join(getattr(primary, '__notes__', ()))))
        if pending is None and finalized_error is not None:
            raise finalized_error
    output_owner.emit_required('application-root', lambda: print(f"[INFO] Каталог результатов: {output_root['path']}"))
    output_owner.emit_required('application-ready', lambda: print("\n[INFO] Пакет Windows с WSL готов:"))
    output_owner.emit_required('application-path', lambda: print(f"Ваш исполняемый файл: {out_path}"))
    output_owner.emit_required('main-completion', lambda: print("[УСПЕХ] Выбранные компоненты сборки завершены."))

if __name__ == "__main__":
    if sys.argv[1:] == ["--print-version"]:
        try:
            print(read_package_version())
        except Exception as error:
            print(str(error), file=sys.stderr)
            sys.exit(1)
    elif sys.argv[1:2] == ["--receive-release-build"]:
        try:
            if len(sys.argv) != 4:
                raise RuntimeError("Cargo receipt receiving requires the manifest path and target")
            version, executable = receive_release_build(sys.stdin, sys.argv[2], sys.argv[3], os.environ)
            print(f"{version}\t{executable}")
        except Exception as error:
            print(str(error), file=sys.stderr)
            sys.exit(1)
    else:
        main(personal=sys.argv[1:] == ["--personal"])
