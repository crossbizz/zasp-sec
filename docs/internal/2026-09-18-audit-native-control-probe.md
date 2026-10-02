# Audit native-control preflight, September18

Native audit-export acceptance remains open. This was a small control-path
probe, not another large export preparation and not a product save test.

The Browse skill found Aside unavailable. Its headless fallback cannot establish
OS file-picker behavior, so the native computer-use tool was used on one newly
created owned Chrome tab. Optional configuration and automatic-commit prompts
were not applied. Existing personal tabs were not modified or used as targets.

Browser extension control now responds. A temporary loopback-only Node22 server
served a page titled Zasp native picker probe with one button invoking the real
showSaveFilePicker and no createWritable/file-byte logic. Its origin was
127.0.0.1:57244. Page.bringToFront focused that owned tab, and native window
identity was checked before the button click.

After the click, the page remained awaiting the picker and the native tool
reported a window titled Save. But its accessibility response contained
unrelated context-menu controls, not verifiable Save/Cancel controls; screenshot
was unavailable. An attempted Escape was refused after a focus change and
returned after96.4seconds despite the requested10second tool timeout. No save
or cancel success is inferred from that attempt. Do not operate guessed native
controls or relabel this as nativeSavedBytesVerified.

The owned tab was closed successfully through its exact browser handle. The
owned server PID67264 was verified against the loopback listener, terminated
and joined with exit0. No file-save acceptance or bytes were requested by the
probe, no large fixture was run, and no product source changed. Personal page
contents and tab inventories are deliberately excluded from this report.

The remaining blocker is reliable owned-window native dialog targeting, not
browser extension startup. M7-36 still needs actual native saving, independent
saved-byte/SQL comparison, memory checks and the remaining fault/recovery
matrix. Reattempt only with a materially improved native-control path or a
dedicated controllable window; do not repeat the expensive preparation first.
