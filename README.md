# party

Static GitHub Pages invite site. The whole party (flyer, title, date, details) is stored **encrypted** (`parties/<slug>/party.enc`); the page decrypts it in the browser with the password.

## Add / update a party
Put `party.json` and the flyer image in `src_private/<slug>/` (gitignored; see instructions.md for the format), then:

    FLYER_PASSWORD='long passphrase' node scripts/encrypt.js <slug>
    git add parties && git commit

## Security notes
Browser-only for now. The failed-attempt limit (5 / 24h) lives in localStorage and is a deterrent, not enforcement. `parties/<slug>/party.enc` is public, so use a long passphrase (offline guessing is possible). Planned: server-side limits, Turnstile, calendar emails.

## TODO
- Calendar feature (email field is a disabled stub).
