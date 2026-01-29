# ⚠️ Deprecated
`pilot_run` and `prototype_v2` versions are deprecated and should not be used for new work.
Use `serial_run` instead.

# Content
This directory contains the full open-source design for Keycard Shell. It includes electronics, mechanical parts, and certification documents grouped by release series.

# Versions
`serial_run` corresponds to the design of Keycard Shell launched officially in January 2026.

# Detail of content 
- electronic design: schematics (PDF and editable files), Gerbers, bill of materials, and PCB data archives
- mechanical design: 3D `.step` files for each part, 2D definitions, and a full `.step` of the assembled Keycard Shell
- list of parts of the full assembly, including reference sub-assemblies like screen, battery, camera, and packaging
- certification: full qualification and regulatory reports covering EMC, safety, and transportation

# How to contribute
- Add new documentation under `serial_run` so the latest release stays central
- Keep filenames lowercase with hyphen separators to prevent whitespace or case issues
- When uploading large binaries, consider Git LFS to avoid push timeouts for files over 50 MB