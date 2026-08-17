# Digital Champions Intranet — Flask (Python)

A staff-gated intranet built with Python (Flask). Accounts are stored in a
local SQLite database, passwords are hashed (never stored in plain text),
and every page except sign-in/registration requires an active session.

## Pages

- **About** — about the Digital Champions, what the team does, the team
  itself, and partnership working across the four places.
- **Resource** — news feed, team insights (e.g. the GPAD guide), and the
  Resource Centre / case studies.
- **Contact** — place maps and how to reach each team member.
- **Admin** (`/admin/staff`, only visible to admins) — who has an account,
  with the ability to promote/demote other admins or revoke access.
- A **"Find resources"** chat widget (bottom-right, every page) answers
  wayfinding questions with links to the right page/section.

## Run it

```
pip install -r requirements.txt
copy .env.example .env      REM then edit SECRET_KEY and ADMIN_EMAILS
python app.py
```

Visit http://localhost:5000 — you'll be redirected to sign in.

For production, run through a real WSGI server instead of the dev server,
pointed at `wsgi:app` (e.g. `gunicorn wsgi:app`).

## How user data is kept safe

- Passwords are hashed with Werkzeug's salted PBKDF2-SHA256 before being
  stored — the plain password is never written to disk, and the hash
  can't practically be reversed.
- Sessions are a signed cookie (via `SECRET_KEY`) that expires after 8
  hours, marked `HttpOnly` (not readable by page JavaScript) and
  `SameSite=Lax`.
- Every route except `/login` and `/register` is behind a
  `login_required` check in `app.py`; admin routes additionally require
  `admin_required` or `root_admin_required`.
- State-changing admin actions (delete/promote/demote, sign-out) are
  protected by a CSRF token tied to the session.
- Admin access is rooted in `ADMIN_EMAILS` in `.env` — the one thing about
  who can become an admin that can only be changed by someone with server
  access, never through the website itself. Root admins can promote other
  accounts to admin from the browser; those delegated admins can manage
  staff but can't create more admins.
- `instance/` (the SQLite database) and `.env` are both gitignored —
  don't commit either one.

## Creating accounts

Any member of staff can register at `/register` by giving their name,
work email, a password, and which place (Coventry, Rugby,
Warwickshire-North or South-Warwickshire) and GP practice they're with.
There's no invite code, so anyone who can reach the site can create an
account — see "before this goes anywhere real" below.

## Project layout

```
app.py               Flask app: routes, auth, admin, chat widget logic
wsgi.py               Production entry point (gunicorn wsgi:app)
requirements.txt
.env.example           Copy to .env and fill in
templates/            Jinja2 templates
  base.html             Shared shell: nav, utility bar, chat widget
  about.html, resource.html, contact.html    Main pages
  login.html, register.html                  Auth pages
  admin_base.html, admin_staff.html          Admin section (own layout,
                                              no site nav/chat widget)
  gpad.html             Standalone GPAD guide, linked from Resource
static/
  css/style.css         Site styling (NHS-blue theme)
  assets/               Logo, place maps
  video/                GPAD video
instance/              Runtime data — created automatically, gitignored
  data.sqlite            SQLite database
```

## Before this goes anywhere real

- Registration is open to anyone who reaches `/register` — there's no
  invite code or approval step. If you want to restrict who can create
  an account, easy options are checking the email domain (e.g. must end
  `@nhs.net`) or adding manual approval before an account can sign in.
- Set a long random `SECRET_KEY` in `.env` — don't use the example value.
  Anyone with this key could forge a session cookie.
- Serve it over HTTPS, then set `SESSION_COOKIE_SECURE=true` in `.env`
  so the session cookie is never sent unencrypted.
- This is a standalone login system, separate from any NHS network
  login. If your ICB already runs Microsoft Entra ID / SSO for staff,
  it's usually worth connecting to that instead of maintaining a second
  set of passwords — worth a conversation with IT before this goes into
  real use.
- `instance/data.sqlite` will contain real staff emails and password
  hashes once people register — back it up and restrict access to it
  like any other credential store.
- SQLite is fine for a small team on a single server, but doesn't suit
  environments where the filesystem isn't persistent or the app runs on
  multiple instances (e.g. some cloud App Service configurations) — a
  real database (e.g. PostgreSQL) is worth considering before scaling up.
