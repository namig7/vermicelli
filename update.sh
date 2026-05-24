#!/bin/bash

# Default configuration values
DEFAULT_BASE_URL="http://localhost:8000"
DEFAULT_APP_ID=1
DEFAULT_RELEASE_NOTES="No release notes available."

# Parse arguments and flags
while [[ $# -gt 0 ]]; do
    case $1 in
        --appid)
            APP_ID="$2"
            shift 2
            ;;
        --version)
            VERSION_PART="$2"
            shift 2
            ;;
        --apikey|--api-key)
            API_KEY="$2"
            shift 2
            ;;
        --url)
            BASE_URL="$2"
            shift 2
            ;;
        --releasenotes)
            RELEASE_NOTES="$2"
            shift 2
            ;;
        --prerelease)
            PRERELEASE="$2"
            shift 2
            ;;
        *)
            echo "Error: Invalid argument '$1'"
            exit 1
            ;;
    esac
done

# Apply default values if flags are not provided
BASE_URL=${BASE_URL:-$DEFAULT_BASE_URL}
APP_ID=${APP_ID:-$DEFAULT_APP_ID}
API_KEY=${API_KEY:-${VERMICELLI_API_KEY:-}}
RELEASE_NOTES=${RELEASE_NOTES:-${CI_COMMIT_MESSAGE:-${GITHUB_EVENT_HEAD_COMMIT_MESSAGE:-${GITEA_COMMIT_MESSAGE:-$DEFAULT_RELEASE_NOTES}}}}

# Ensure the required API key is provided
if [ -z "$API_KEY" ]; then
    echo "Error: Missing required flag --apikey. Usage: ./update.sh --apikey <api-key> --appid <id> [--releasenotes <notes>] [--url <base-url>]"
    exit 1
fi
if [ -n "$VERSION_PART" ]; then
    VERSION_PART=$(printf '%s' "$VERSION_PART" | tr '[:upper:]' '[:lower:]')
fi

# API endpoints
UPDATE_ENDPOINT="/app/$APP_ID/update_version"

# Function to update the version
update_version() {
    echo "Updating version for application ID $APP_ID..."
    PAYLOAD=$(jq -n \
        --arg releasenotes "$RELEASE_NOTES" \
        --arg version_part "${VERSION_PART:-}" \
        --arg prerelease "${PRERELEASE:-}" \
        '{releasenotes: $releasenotes}
         + (if $version_part == "" then {} else {version_part: $version_part} end)
         + (if $prerelease == "" then {} else {prerelease: $prerelease} end)')

    RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
        -H "X-API-Key: $API_KEY" \
        -d "$PAYLOAD" \
        "$BASE_URL$UPDATE_ENDPOINT")
    
    echo "Response: $RESPONSE" >&2
    
    NEW_VERSION=$(echo "$RESPONSE" | jq -r '.new_version')
    
    if [ "$NEW_VERSION" == "null" ]; then
        echo "Error: Failed to update version. Response: $RESPONSE" >&2
        exit 1
    fi
    
    echo "Version updated successfully. New version: $NEW_VERSION"
}

# Main script execution
update_version
