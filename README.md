# party

Static GitHub Pages invite site. The flyer is stored **encrypted** (`flyer.enc`); the page decrypts it in the browser with the password.

## Add / update the flyer
Put the plaintext image in `src_private/` (gitignored), then:

    FLYER_PASSWORD='long passphrase' node scripts/encrypt.js src_private/flyer.jpg
    git add flyer.enc && git commit

## Security notes
Browser-only for now. The failed-attempt limit (5 / 24h) lives in localStorage and is a deterrent, not enforcement. `flyer.enc` is public, so use a long passphrase (offline guessing is possible). Planned: server-side limits, Turnstile, calendar emails.

## TODO
- Calendar feature (email field is a disabled stub).
