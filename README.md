A Windows desktop app that protects files and folders by talking to a minifilter driver. 
While a path is shielded, the driver blocks any DELETE / MOVE / RENAME against it.

Submitting a folder expands to the folder + every file under it, sent in a single batched message.
Submissions are persisted to operations.json.
A copy of every shielded path is also written to blacklist.txt — re-read by the driver on init, so protection survives the app being closed.
When the driver blocks an operation, it pushes a notification to the app; the app coalesces multiple per-file events into one "Unshield this folder?" prompt for the shielded ancestor.

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

Inspect the actual protection set — click Protected files… to see every path the driver currently protects (folders expanded into their files).
Recover from a crash / external edit — click Refresh (its tooltip shows the JSON path) to re-read operations.json from disk.
Auto-save runs after every operation, so a force-kill won't lose data.
Read kernel logs in the right pane.

That's the whole loop: pick → shielded → driver enforces → if something gets blocked, the app asks whether to unshield.
