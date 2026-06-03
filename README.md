A Windows desktop app that protects files and folders by talking to a minifilter driver. 
While a path is shielded, the driver blocks any DELETE / MOVE / RENAME against it.

Submitting a folder expands to the folder + every file under it, sent in a single batched message.
Submissions are persisted to operations.json.
A copy of every shielded path is also written to policy_snapshot.bin — re-read by the driver on init, so protection survives the app being closed.
When the driver blocks an operation, it pushes a notification to the app; the app coalesces multiple per-file events into one "Unshield this folder?" prompt for the shielded ancestor.

Each shielded file carries two access-right bitmasks: one for **untrusted** callers (the default) and one for **trusted** callers (binaries the app has Authenticode-verified). 
Lock-in-place semantics: untrusted callers can read/write but cannot delete/rename/move; trusted callers can do everything, so apps like Word can still complete their atomic save (delete old → write new) on a shielded document.
Trusted-process state is persisted to trusted_processes.json (for the UI) and to trusted_processes_snapshot.bin (the encrypted+signed file the driver reads at boot before the agent reconnects).

# How to use it?
Launch as administrator. 
The minifilter must already be loaded, and the six key files must exist.

To shield:
- pick a file with File…, pick a folder with Folder…, or type a path and click Shield (Enter also submits).
- The chosen path appears in the Submitted Operations list as Sending… → Sent.

To unshield:
- double-click that path's row in the Submitted Operations list.
- The row toggles back to unshield and the driver removes protection.

When the driver blocks something you tried to delete/move/rename, a Yes/No dialogue appears asking whether to unshield. 
- Yes routes a normal unshield through the same flow;
- No leaves it shielded and won't ask again about the same folder this session.

To manage trusted processes:
- Click **Trusted processes…** in the Submitted Operations header to open the management dialog.
- Add by typing or browsing to an `.exe` and clicking **Trust** (Enter also submits). The path appears as `Sending… → Sent`.
- Remove by double-clicking a row or selecting it and clicking **Remove selected**; the dialog asks for confirmation.
- Adds/removes ship immediately to the driver as encrypted+signed TRUSTED_PROCESS_SYNC messages, and the trusted_processes_snapshot.bin boot file refreshes right away so a reboot soon after the change lands with the correct state.
- On agent startup, every persisted trusted entry is replayed to the driver once both communication ports are up, so the trusted-process table is restored after a restart.

Inspect the actual protection set — click Protected files… to see every path the driver currently protects (folders expanded into their files).
Recover from a crash / external edit — click Refresh (its tooltip shows the JSON path) to re-read operations.json from disk.
Auto-save runs after every operation, so a force-kill won't lose data.
Read kernel logs in the right pane.

That's the whole loop: pick → shielded → driver enforces → if something gets blocked, the app asks whether to unshield.
Trusted-process management runs alongside that loop: add the binaries that need destroy rights on Lock-in-place files (Word, Excel, your own signed installers), and the driver grants them the trusted half of every shielded file's bitmask.
