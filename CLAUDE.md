# tether

## Frontend design direction

All frontend work (the review app in `tether/ui.html` and anything new) follows `docs/DESIGN.md`. It's modeled on the look and feel of https://spacefs.com/: near-monochrome, big tight two-tone type, floating pill controls, glass overlays, generous whitespace and soft motion. Use it as a reference only. Never reuse its assets, copy or branding.

The functional and security rules of the review app still apply. Agent-supplied content is always rendered as text, and the CSP, Host check and token check stay in place.
