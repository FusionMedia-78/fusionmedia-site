# fusionmedia.wtf

Static website plus a free "website check" for visitors.

## Layout

- `public/`: the website exactly as published. Edit the HTML here; images, fonts, CSS and JS live in `public/assets/`.
- `netlify/functions/scan.mjs`: `POST /api/scan`, the public check. It returns only a grade and five plain-English lines. The technical detail stays on the server.
- `netlify/functions/report.mjs`: `GET /api/report?domain=example.com`, the full technical report with fixes. It is password protected (add `&format=json` for raw data).
- `netlify/lib/audit.mjs`: the checks, the scoring and the plain-English wording, shared by both functions.
- `netlify.toml`: tells Netlify to publish `public/` and where the functions are. There is no build step.

## Settings in Netlify

- **Environment variable** `REPORT_PASSWORD`: the password for `/api/report`. Without it, reports are switched off.
- **Form notification**: the `website-check` form sends the lead's name, email, domain, grade and a `full_report` link. Open the link and enter any username plus `REPORT_PASSWORD`.

## Deploying

Every push to `main` deploys automatically.

## Changing the wording visitors see

In `netlify/lib/audit.mjs`:

- `GOOD`: the line shown when an area is strong.
- `LINES`: the lines for problems; the first matching rule wins.
- `UNKNOWN`: the line shown when the site blocked the check.

Keep the wording about business impact, never the technical cause.
