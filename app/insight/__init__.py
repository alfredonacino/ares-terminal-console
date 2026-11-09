"""
Server insight: health, performance, logs, packages, vulnerabilities, history.

The probe modules here are vendored from ARES Ultimate Console's
``ares/protocols`` (commit 7889d17, 2026-11-07), which carries TractorBeam's
performance check and ARES Server Guardian's health page. They are copied
rather than imported for the same reason ``sso.py`` is: this app has to run on
its own. Change them there first and copy them across, so the two stay one
implementation.

Every probe is read-only: a script sent on stdin to ``sh -s`` over SSH, parsed
here. Nothing is installed on a server to study it. The one action that is
not read-only -- stopping a process from the health page -- runs only on an
explicit click.
"""

import ssl


def tls_context() -> ssl.SSLContext:
    """A context with roots that exist in a frozen build too.

    macOS keeps its roots in the Keychain, where OpenSSL cannot read them, and
    a bundle built on one Linux finds another distribution's paths empty. certifi
    travels with the desktop build; without it, the system's defaults.
    """
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()
