"""
Making a listing readable: colour by file type.

A pane opened here used to be monochrome, because colour in a terminal is not
the terminal's doing. Two things have to be true and neither is by default:

  1. `LS_COLORS` has to say what each kind of file looks like. An empty one --
     which is what a shell started outside a desktop session usually has --
     means `ls` has nothing to colour with.

  2. `ls` has to be *asked* to colour, with `--color=auto`. That normally comes
     from an alias in the user's shell rc, and plenty of shells do not have one.

So this module supplies both: a palette matched to the suite's theme, and a
small directory of wrapper commands placed first on PATH. The wrappers are the
shell-agnostic half of the trick -- an alias would have to be injected into
bash, zsh and fish separately, and editing somebody's rc files to get colour is
not a trade worth making. A user's own alias still wins, because aliases are
resolved before PATH.

ONE HONEST LIMITATION. GNU `ls` has no notion of a hidden file: `LS_COLORS`
keys are two-letter type codes or `*suffix` patterns, and a leading-dot glob is
rejected outright ("unrecognized prefix"). So dotfiles cannot be coloured as a
class by `ls`, and no amount of scheme-writing changes that. `eza` *does*
accept arbitrary filename globs, so where it is installed the `ll`/`la`
wrappers use it and hidden entries come out dimmed. Where it is not, everything
else is still coloured and hidden files look like ordinary files.
"""

import os
import sys
import shutil
import stat
from pathlib import Path

# --------------------------------------------------------------------------
# The palette, mapped to the terminal's own 16 colours (see XTERM_THEME in
# app.js) so a listing looks like it belongs to the rest of the suite:
#
#   bold cyan     directories          cyan     symlinks
#   bold green    executables          bold red broken links, archives
#   bold magenta  images               magenta  audio and video
#   yellow        documents            green    source code
#   grey          noise: logs, backups, swap files, editor leftovers
#
# Inverted backgrounds are reserved for the two cases that are a *warning*
# rather than a category: setuid/setgid binaries, and world-writable
# directories. Those should be uncomfortable to look at.
# --------------------------------------------------------------------------

_TYPES = [
    ("di", "01;36"),   # directory
    ("ln", "00;36"),   # symbolic link
    ("or", "01;31"),   # orphaned link -- points at nothing
    ("mi", "01;31"),   # the missing target itself
    ("ex", "01;32"),   # executable
    ("fi", "00"),      # regular file: the terminal's own foreground
    ("pi", "01;33"),   # named pipe
    ("so", "01;33"),   # socket
    ("bd", "01;33"),   # block device
    ("cd", "01;33"),   # character device
    ("su", "97;41"),   # setuid  -- runs as its owner
    ("sg", "30;43"),   # setgid
    # Inverted, and legible: bold-blue-on-cyan is what the GNU default gives
    # here and it is genuinely hard to read. These need to be noticed, which
    # is not the same as being painful.
    ("tw", "30;42"),   # sticky and world-writable -- black on green
    ("ow", "30;46"),   # world-writable, not sticky -- black on cyan
    ("st", "97;44"),   # sticky -- white on blue
    ("ca", "00"),      # capabilities: left plain, it is not a category
]

_GROUPS = [
    ("01;31", "tar tgz taz txz tzst tbz2 gz bz2 xz zst lz lzma zip 7z rar "
              "z Z jar war ear rpm deb apk pkg dmg iso img squashfs cpio"),
    ("01;35", "png jpg jpeg gif bmp svg svgz webp avif ico tif tiff xcf psd heic"),
    ("00;35", "mp4 mkv webm mov avi wmv flv m4v mpg mpeg ogv "
              "mp3 flac wav ogg oga opus m4a aac wma mid midi"),
    ("00;33", "md markdown rst txt pdf doc docx odt rtf tex epub csv tsv "
              "xls xlsx ods ppt pptx odp"),
    ("00;32", "py js mjs cjs ts tsx jsx go rs c h cc cpp hpp java kt rb php "
              "pl lua sh bash zsh fish ps1 sql swift scala clj ex exs erl hs"),
    ("00;34", "json yaml yml toml ini cfg conf config env properties xml "
              "lock sum mod dockerfile"),
    ("00;90", "log bak old orig tmp temp swp swo swn part crdownload pyc pyo "
              "class o a so~ rej dpkg-old dpkg-dist rpmsave rpmnew"),
]

# Hidden entries, for the tools that can express them. Not valid in LS_COLORS;
# see the note at the top of this file.
HIDDEN_STYLE = "00;90"


def ls_colors() -> str:
    """A GNU-ls colour scheme. Type codes and *suffix patterns only."""
    parts = [f"{key}={value}" for key, value in _TYPES]
    for value, extensions in _GROUPS:
        parts += [f"*.{ext}={value}" for ext in extensions.split()]
    # Editor leftovers end in a character, not an extension.
    parts += [f"*~={HIDDEN_STYLE}", f"*#={HIDDEN_STYLE}"]
    return ":".join(parts)


def eza_colors() -> str:
    """The same palette for eza, plus the one rule GNU ls cannot express.

    eza treats any key that is not a known two-letter code as a filename glob,
    so `.*` reaches every dotfile. Directories keep the directory colour -- the
    type code wins -- which is what you want: a hidden directory is still a
    directory first.
    """
    return ls_colors() + f":.*={HIDDEN_STYLE}"


# --------------------------------------------------------------------------
# The wrappers
# --------------------------------------------------------------------------

_SHIM_HEADER = """#!/bin/sh
# Written by ARES Terminal Console. Deleting this file only turns the colour back off.
#
# On PATH ahead of the real {name} so that a listing is coloured without an
# alias in your shell rc. --color=auto, never 'always': piped or redirected
# output stays clean, which is the whole reason 'auto' exists.
"""


def _real(name: str, skip_dir: Path) -> str:
    """Where the genuine command lives, ignoring our own shim directory."""
    path = os.pathsep.join(
        p for p in os.environ.get("PATH", "").split(os.pathsep)
        if p and Path(p) != skip_dir
    )
    return shutil.which(name, path=path) or ""


def build_shims(bindir) -> dict:
    """Write the wrapper commands. Returns {name: what it runs}, for the UI.

    Rewritten on every start rather than cached: the absolute paths inside are
    resolved from this machine's PATH, and a cached shim that points at an
    uninstalled tool is worse than no shim.
    """
    if sys.platform == "win32":
        return {}   # the wrappers are sh scripts; Windows shells have their own colour
    bindir = Path(bindir)
    bindir.mkdir(parents=True, exist_ok=True)

    real_ls = _real("ls", bindir)
    eza = _real("eza", bindir) or _real("exa", bindir)
    made = {}

    def write(name: str, body: str, describes: str):
        target = bindir / name
        target.write_text(_SHIM_HEADER.format(name=name) + body, encoding="utf-8")
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        made[name] = describes

    if real_ls:
        write("ls", f'exec {shlex_quote(real_ls)} --color=auto "$@"\n',
              f"{real_ls} --color=auto")

    # ll / la are where hidden files get their own colour, because that is
    # where eza can be used without changing what `ls` means.
    if eza:
        write("ll", f'exec {shlex_quote(eza)} --long --header --group-directories-first '
                    f'--color=auto "$@"\n', f"{eza} --long")
        write("la", f'exec {shlex_quote(eza)} --all --group-directories-first '
                    f'--color=auto "$@"\n', f"{eza} --all  (hidden files dimmed)")
        write("lt", f'exec {shlex_quote(eza)} --tree --level=2 --color=auto "$@"\n',
              f"{eza} --tree")
    elif real_ls:
        write("ll", f'exec {shlex_quote(real_ls)} -lh --color=auto "$@"\n',
              f"{real_ls} -lh")
        write("la", f'exec {shlex_quote(real_ls)} -lhA --color=auto "$@"\n',
              f"{real_ls} -lhA")

    # ssh: share a connection typed into a local pane with the server tools,
    # the way a pane opened with ⇄ connect does (see app/remote.py). Only for
    # an interactive login -- git, rsync and scripts get plain ssh -- and only
    # when the command does not choose its own multiplexing.
    real_ssh = _real("ssh", bindir)
    if real_ssh:
        from app import remote
        target = bindir / "ssh"
        target.write_text(_SSH_SHIM.format(ssh=shlex_quote(real_ssh),
                                           path=shlex_quote(remote.control_path())),
                          encoding="utf-8")
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        made["ssh"] = f"{real_ssh}, sharing an interactive login with the server tools"

    return made


_SSH_SHIM = """#!/bin/sh
# Written by ARES Terminal Console. Deleting this file only stops the server
# tools from reusing a login typed into a local pane.
#
# An interactive `ssh host` becomes the master of a shared connection, so the
# tools (◈ on the pane) run over it without a second login. Anything that is
# not a terminal session, or that sets its own ControlMaster/ControlPath/-S,
# runs the real ssh untouched.
if [ -t 0 ] && [ -t 1 ]; then
  for a in "$@"; do
    case "$a" in
      -S*|*[Cc]ontrol[Mm]aster*|*[Cc]ontrol[Pp]ath*) exec {ssh} "$@" ;;
    esac
  done
  exec {ssh} -o ControlMaster=auto -o ControlPath={path} -o ControlPersist=60 "$@"
fi
exec {ssh} "$@"
"""


def shlex_quote(s: str) -> str:
    import shlex
    return shlex.quote(s)


def environment(bindir) -> dict:
    """The env overlay a session is started with.

    A colour scheme the user has set themselves is left alone -- they have
    already answered this question and a tool that overrules them is a tool
    they will turn off.
    """
    env = {}
    if sys.platform == "win32":
        return env
    if not os.environ.get("LS_COLORS"):
        env["LS_COLORS"] = ls_colors()
    if not os.environ.get("EZA_COLORS"):
        env["EZA_COLORS"] = eza_colors()
    # BSD/macOS ls reads these instead of LS_COLORS.
    env.setdefault("CLICOLOR", "1")

    bindir = str(Path(bindir).resolve())    # a shell may start anywhere: never relative
    path = os.environ.get("PATH", "")
    if bindir not in path.split(os.pathsep):
        env["PATH"] = bindir + os.pathsep + path
    return env


# What the legend in the UI shows. Kept beside the scheme so the two cannot
# drift: a legend that disagrees with the colours is worse than none.
LEGEND = [
    ("Directory",            "01;36"),
    ("Symlink",              "00;36"),
    ("Broken symlink",       "01;31"),
    ("Executable",           "01;32"),
    ("Regular file",         "00"),
    ("Hidden (ll / la)",     HIDDEN_STYLE),
    ("Archive",              "01;31"),
    ("Image",                "01;35"),
    ("Audio / video",        "00;35"),
    ("Document",             "00;33"),
    ("Source code",          "00;32"),
    ("Config / data",        "00;34"),
    ("Logs, backups, swap",  "00;90"),
    ("Device / socket / fifo", "01;33"),
    ("setuid / setgid",      "97;41"),
    ("World-writable dir",   "30;46"),
]
