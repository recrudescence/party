# TODO

## Calendar: consolidate event ID in party.json
Update the Google Apps Script to accept the event ID in the POST body, instead of hardcoding it. Then:
- send `calendar.eventId` from `party.json` along with the email in `app.js` (see the `TODO` in `setupCalendar`)
- each party can then have its own calendar event with a single shared script

## Calendar: CAPTCHA
Add Cloudflare Turnstile to the email form before wider launch. Verify the token server-side in the Apps Script `doPost` via `UrlFetchApp`, not just in the browser.
