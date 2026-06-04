<div align="center" width="100%">
    <img src="./static/public/logo-vermicelli-w.svg" width="128" alt="" />
</div>

# Vermicelli

Simple self-hosted version control automation to track and manage the versions of your applications.

[![GitHub](https://img.shields.io/badge/GitHub-181717?style=flat&logo=github&logoColor=white)](https://github.com/namig7/vermicelli)
![GitHub Created At](https://img.shields.io/github/created-at/namig7/vermicelli)
![GitHub License](https://img.shields.io/github/license/namig7/vermicelli) ![GitHub last commit](https://img.shields.io/github/last-commit/namig7/vermicelli%2Fdevelop) ![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/namig7/vermicelli) ![GitHub top language](https://img.shields.io/github/languages/top/namig7/vermicelli)
[![CodeFactor](https://www.codefactor.io/repository/github/namig7/vermicelli/badge/develop)](https://www.codefactor.io/repository/github/namig7/vermicelli/overview/develop)

[![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=fff)](https://img.shields.io/docker/image-size/namigg/vermicelli/latest) 
![Docker Image Size (tag)](https://img.shields.io/docker/image-size/namigg/vermicelli/latest)
![Docker Pulls](https://img.shields.io/docker/pulls/namigg/vermicelli)

[![TailwindCSS](https://img.shields.io/badge/Tailwind%20CSS-%2338B2AC.svg?logo=tailwind-css&logoColor=white)](https://github.com/namig7/vermicelli) 
[![GitHub Created At](https://img.shields.io/badge/Shell_Script-121011?style=flat&logo=gnu-bash&logoColor=white)](https://github.com/namig7/vermicelli)

## Features

- **Create Multiple Applications**  
  Manage multiple applications and group them into one or more projects.

- **Version Tracking**  
  Track each application’s Major.Minor.Patch version and increment specific segments (major, minor, patch) as needed.

- **Historical Log**  
  Maintain a version history for each application, including release notes or additional details.

- **CI/CD Integration**  
  Easily integrate with your CI/CD pipelines to automate version updates and streamline releases.

- **Web UI & API**  
  Perform all operations through an intuitive web interface or via a REST API (e.g., using `curl`).

## Getting Started

> [!WARNING]
> `.env` file should be created prior. You can start from `.env.example`.

The minimum content of the `.env`:

```yaml
# JWT & Flask secret keys
JWT_SECRET_KEY=your_jwt_secret_key
SECRET_KEY=your_secret_key
SESSION_TYPE=filesystem

# DB Configuration
DB_ENGINE=sqlite
DB=verdb

# List of users. Please specify using this format: "USERS=username:password;username2:password2"
USERS=admin:password;testuser:testpass
```

Vermicelli targets Python 3.14.5. If you use `pyenv` or another version manager, the repository includes `.python-version`.

Quick start (local, SQLite):

```bash
cp .env.example .env
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/init_db.py
python main.py
```

Then open `http://localhost:8000` and log in using one of the users from `USERS` in your `.env`.

There is no migration step in this setup. The database schema is managed directly from the SQLAlchemy models with these helper scripts:

```bash
python scripts/init_db.py
python scripts/reset_db.py
```

## Build and Deploy

Build the Docker image from this repository:

```bash
docker build -t vermicelli:local .
```

The Dockerfile uses Python 3.14.5 by default. To pin the same version explicitly in CI:

```bash
docker build --build-arg PYTHON_VERSION=3.14.5 -t vermicelli:local .
```

Run the locally built image with SQLite:

```bash
mkdir -p data
docker run -d \
  --name vermicelli \
  -p 8000:8000 \
  --env-file .env \
  -v "$(pwd)/data:/app/data" \
  vermicelli:local
```

When using the SQLite volume above, set `DB=data/verdb` in `.env` so the database is stored at `/app/data/verdb.db` inside the container.

Run the published image instead of a local build:

```bash
docker run -d \
  --name vermicelli \
  -p 8000:8000 \
  --env-file .env \
  -v "$(pwd)/data:/app/data" \
  namigg/vermicelli:latest
```

> [!NOTE]
> Ensure that DB_ENGINE=sqlite is set in your .env if you want to use SQLite.
> Also, if you want to persist the database file outside the container, use a volume or bind mount. **`-v "$(pwd)/data:/app/data"`** is an example of mounting a local folder to store the SQLite database file persistently. When using SQLite make sure that the `DB` path points to `/app/data/verdb.db` (or a similar path), so the data is not lost when the container is removed.

Deploy with PostgreSQL by setting these values in `.env` and using either image run command above:

```yaml
DB_ENGINE=postgres
DB=verdb
DB_USER=postgres
DB_PASSWORD=postgres
DB_HOST=postgres.example.com
DB_PORT=5432
DB_SSLMODE=require
```

Initialize the schema from inside a running container. Use reset only when you intend to drop and recreate all tables:

```bash
docker exec vermicelli python scripts/init_db.py
docker exec vermicelli python scripts/reset_db.py
```

## Advanced Installation

For the advanced installation steps and features(Docker & Non-docker with Postgresql etc.) please proceed to the [wiki](https://github.com/namig7/vermicelli/wiki).

## update.sh - Usage Example

```bash
./update.sh --appid 10 --apikey "$VERMICELLI_API_KEY" --releasenotes "$RELEASE_NOTES" --url http://myapi.example.com
```

The script uses an API key generated from an application release increment and saves `--releasenotes` on the new version.
Use your CI provider's commit message variable for `--releasenotes`, for example `$GITHUB_EVENT_HEAD_COMMIT_MESSAGE` on GitHub, `$CI_COMMIT_MESSAGE` on GitLab, or `$GITEA_COMMIT_MESSAGE` on Gitea. If no release notes are provided, the version stores `No release notes available.`.
