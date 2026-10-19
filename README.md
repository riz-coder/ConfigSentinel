# ConfigSentinel Compliance OS

Production-shaped foundation for a tenant-isolated telecom compliance and
network-assurance platform. It does **not** certify PTA compliance and currently
contains no production device collector.

## Windows development

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Open `http://127.0.0.1:8000/`. Create a tenant and membership through Django
admin before opening the dashboard. To initialize honest placeholder slots:

```powershell
python manage.py seed_pending_ctdisr <tenant-slug>
```

This command creates 84 `SOURCE_PENDING` records. It imports no legal text and
makes no compliance claim.

The authenticated API contract is available at `/api/v1/openapi/`; regulatory
sources and regulation slots are exposed below `/api/v1/` and are filtered by
the user's active tenant membership.

Privileged access requires authenticator-app MFA. After a successful password
login, a user without a confirmed device is sent to the enrollment QR screen;
subsequent sessions require a current TOTP code. Five repeated invalid login
attempts for the same username/IP combination trigger a 30-minute lockout.

## Tests

```powershell
python manage.py check
python manage.py test
```

## VPS deployment shape

Copy `.env.example` to `.env`, use a randomly generated production secret,
set `DEBUG=false`, define the public hostname/origin, and use PostgreSQL rather
than SQLite. Then deploy with both Compose files:

```sh
docker compose -f compose.yaml -f compose.production.yaml up -d --build
```

The production override places Caddy in front of Django and does not publish
the application or database port directly. MFA, forced PostgreSQL RLS, separate
database roles, and checksum-verified backup/restore scripts are present.
Encrypted object storage, automated off-host backup scheduling, restore drills,
and worker services remain required before sensitive customer production use.

For Docker-based local development use:

```powershell
docker compose -f compose.yaml -f compose.development.yaml up --build
```

The migration container uses the database-owner role and exits. The web process
uses a separate non-superuser runtime role so forced PostgreSQL RLS applies.
Database role and backup details are in `docs/database-security.md`.

## Legal status

The authenticated complete CTDISR 2025 Gazette is not present. All placeholder
regulations remain `SOURCE_PENDING`. See `PLAN.md` for package boundaries and
known blockers.
