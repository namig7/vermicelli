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
> `.env` file should be created prior.

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

This script runs the container in detached mode, mapping port 8000 and using the `.env` file.

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
> Also, if you want to persist the database file outside the container, use a volume or bind mount. **`-v "$(pwd)/data:/app/data"`**   is an example of mounting a local folder to store the SQLite database file persistently. When using SQLite make sure that the path points to `/app/data/verdb.db` (or a similar path), so the data is not lost when the container is removed.

## Advanced Installation

For the advanced installation steps and features(Docker & Non-docker with Postgresql etc.) please proceed to the [wiki](https://github.com/namig7/vermicelli/wiki).

## update.sh - Usage Example

```bash
./update.sh --version patch --appid 10 --username myuser --password mypass --url http://myapi.example.com
