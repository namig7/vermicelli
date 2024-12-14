#!/bin/bash

# Default configuration values
DEFAULT_BASE_URL="http://localhost:8000"
DEFAULT_USERNAME="admin"
DEFAULT_PASSWORD="password"
DEFAULT_APP_ID=1

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
        --username)
            USERNAME="$2"
            shift 2
            ;;
        --password)
            PASSWORD="$2"
            shift 2
            ;;
        --url)
            BASE_URL="$2"
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
USERNAME=${USERNAME:-$DEFAULT_USERNAME}
PASSWORD=${PASSWORD:-$DEFAULT_PASSWORD}
APP_ID=${APP_ID:-$DEFAULT_APP_ID}

# Ensure the required flag `--version` is provided
if [ -z "$VERSION_PART" ]; then
    echo "Error: Missing required flag --version. Usage: ./update.sh --version <major|minor|patch> [other flags]"
    exit 1
fi

# API endpoints
LOGIN_ENDPOINT="/api/login"
UPDATE_ENDPOINT="/app/$APP_ID/update_version"

# Function to log in and obtain JWT token
get_jwt_token() {
    echo "Logging in to obtain JWT token..." >&2
    RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
        -d "{\"username\": \"$USERNAME\", \"password\": \"$PASSWORD\"}" \
        "$BASE_URL$LOGIN_ENDPOINT")
    
    echo "Raw login response: $RESPONSE" >&2
    
    TOKEN=$(echo "$RESPONSE" | jq -r '.access_token')
    
    if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
        echo "Error: Failed to obtain token. Response: $RESPONSE" >&2
        exit 1
    fi
    
    echo "$TOKEN"
}

# Function to update the version
update_version() {
    local TOKEN=$1
    echo "Using token: $TOKEN" >&2
    
    echo "Updating $VERSION_PART version for application ID $APP_ID..."
    RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "{\"version_part\": \"$VERSION_PART\"}" \
        "$BASE_URL$UPDATE_ENDPOINT")
    
    echo "Response: $RESPONSE" >&2
    
    NEW_VERSION=$(echo "$RESPONSE" | jq -r '.new_version')
    
    if [ "$NEW_VERSION" == "null" ]; then
        echo "Error: Failed to update $VERSION_PART version. Response: $RESPONSE" >&2
        exit 1
    fi
    
    echo "$VERSION_PART version updated successfully. New version: $NEW_VERSION"
}

# Main script execution
JWT_TOKEN=$(get_jwt_token)
update_version "$JWT_TOKEN"

