# Snapshots are committed to the repo so CI can run offline without fetching.
# The current/ directory contains the latest snapshot per environment.
# The snapshots/ directory contains timestamped historical snapshots.
#
# Directory layout:
#   .pac-scan/
#     current/
#       dev.json    ← latest dev snapshot (written by: pac-scan fetch --env dev)
#       uat.json    ← latest uat snapshot
#       prod.json   ← latest prod snapshot
#     snapshots/
#       dev/
#         2026-05-06T120000Z.json
#       uat/
#         ...
#       prod/
#         ...

# Do NOT ignore this directory — snapshots must be committed for offline CI.
!.pac-scan/
