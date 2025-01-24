<div align="center" width="100%">
    <img src="./static/public/logo-vermicelli-w.svg" width="128" alt="" />
</div>

# Vermicelli

Simple self-hosted version control automation to track and manage the versions of your applications.

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
