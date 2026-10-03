# tether

## Frontend design direction

When working on any frontend (the review app in `tether/ui.html` or anything new), match the look and feel of https://spacefs.com/: clean, smooth and polished. That means generous whitespace, restrained color, refined typography, and subtle, fluid motion. Treat it as the visual reference, not something to copy. Don't reuse its assets, copy or branding.

The functional and security rules of the review app still apply. Agent-supplied content is always rendered as text, and the CSP, Host check and token check stay in place.
