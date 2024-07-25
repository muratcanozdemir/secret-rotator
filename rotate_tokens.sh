#!/bin/bash

# Input arguments
SECRETS_MAPPING=$1
GITHUB_APP_ID=$2
GITHUB_APP_PRIVATE_KEY=$3
TEAMS_WEBHOOK_URL=$4

# Function to send a message to Teams
send_teams_message() {
  local message="$1"
  local payload="{\"text\": \"$message\"}"
  curl -H "Content-Type: application/json" -d "$payload" "$TEAMS_WEBHOOK_URL"
}

# Function to generate JWT for GitHub App
generate_github_jwt() {
  local header=$(echo -n '{"alg":"RS256","typ":"JWT"}' | openssl base64 -e -A | tr -d '=' | tr '/+' '_-' )
  local payload=$(echo -n "{\"iat\":$(date +%s),\"exp\":$(($(date +%s) + 600)),\"iss\":\"$GITHUB_APP_ID\"}" | openssl base64 -e -A | tr -d '=' | tr '/+' '_-' )
  local unsigned_token="$header.$payload"
  local signature=$(echo -n "$unsigned_token" | openssl dgst -sha256 -sign <(echo "$GITHUB_APP_PRIVATE_KEY") | openssl base64 -e -A | tr -d '=' | tr '/+' '_-' )
  echo "$unsigned_token.$signature"
}

# Function to generate GitHub App token
generate_github_app_token() {
  local jwt=$(generate_github_jwt)
  local response=$(curl -s -X POST -H "Authorization: Bearer $jwt" -H "Accept: application/vnd.github.v3+json" "https://api.github.com/app/installations")
  local installation_id=$(echo "$response" | jq -r '.[0].id')
  local token_response=$(curl -s -X POST -H "Authorization: Bearer $jwt" -H "Accept: application/vnd.github.v3+json" "https://api.github.com/app/installations/$installation_id/access_tokens")
  echo $(echo "$token_response" | jq -r '.token')
}

# Function to handle API operations
api_operation() {
  local api=$1
  local operation=$2
  local token_type=$3
  local base_url=$4
  local user=$5
  local password=$6
  local auth=$(echo -n "$user:$password" | base64)

  case $api in
    "sonarqube")
      case $operation in
        "check_expiration")
          local existing_token_response=$(curl -s -H "Authorization: Basic $auth" "$base_url/api/user_tokens/search")
          echo $(echo "$existing_token_response" | jq -r ".userTokens[] | select(.name == \"$token_type\") | .expiresAt")
          ;;
        "generate_token")
          local response=$(curl -s -X POST -H "Authorization: Basic $auth" -d "name=$token_type" "$base_url/api/user_tokens/generate")
          echo $(echo "$response" | jq -r '.token')
          ;;
        *)
          echo "Unsupported operation: $operation"
          ;;
      esac
      ;;
    "jfrog")
      case $operation in
        "check_expiration")
          local existing_token_response=$(curl -s -H "Authorization: Basic $auth" "$base_url/api/security/token")
          echo $(echo "$existing_token_response" | jq -r ".tokens[] | select(.name == \"$token_type\") | .expiresAt")
          ;;
        "generate_token")
          local response=$(curl -s -X POST -H "Authorization: Basic $auth" -d "username=$user&scope=member-of-groups:$token_type" "$base_url/api/security/token")
          echo $(echo "$response" | jq -r '.token')
          ;;
        *)
          echo "Unsupported operation: $operation"
          ;;
      esac
      ;;
    "lacework")
      case $operation in
        "check_expiration")
          local existing_token_response=$(curl -s -H "Authorization: Basic $auth" "$base_url/api/v1/access/tokens")
          echo $(echo "$existing_token_response" | jq -r ".data[] | select(.token == \"$token_type\") | .expiryTime")
          ;;
        "generate_token")
          local response=$(curl -s -X POST -H "Authorization: Basic $auth" -H "Content-Type: application/json" -d "{\"keyId\":\"$user\",\"expiryTime\":\"24h\"}" "$base_url/api/v1/access/tokens")
          echo $(echo "$response" | jq -r '.data.token')
          ;;
        *)
          echo "Unsupported operation: $operation"
          ;;
      esac
      ;;
    *)
      echo "Unsupported API: $api"
      ;;
  esac
}

GITHUB_APP_TOKEN=$(generate_github_app_token)

# Read YAML file
secrets=$(yq e '.secrets' "$SECRETS_MAPPING")

for i in $(echo "$secrets" | yq e 'keys' - | sed 's/- //g'); do
  secret=$(echo "$secrets" | yq e ".[$i]" -)

  org_name=$(echo "$secret" | yq e '.org_name' -)
  github_secret_type=$(echo "$secret" | yq e '.github_secret_type' -)
  token_type=$(echo "$secret" | yq e '.token_type' -)
  base_url=$(echo "$secret" | yq e '.base_url' -)
  user=$(echo "$secret" | yq e '.user' -)
  password=$(echo "$secret" | yq e '.password' -)
  api=$(echo "$secret" | yq e '.api' -)
  repo=$(echo "$secret" | yq e '.repo' -)

  # Check the expiration date of the existing token
  expiration_date=$(api_operation "$api" "check_expiration" "$token_type" "$base_url" "$user" "$password")

  if [[ -z "$expiration_date" ]]; then
    send_teams_message "Failed to retrieve expiration date for $token_type"
    continue
  fi

  # Convert expiration date to epoch time and check if it's within 24 hours
  expiration_epoch=$(date -d "$expiration_date" +"%s")
  current_epoch=$(date +"%s")
  diff=$(( (expiration_epoch - current_epoch) / 3600 ))

  if (( diff > 24 )); then
    send_teams_message "Token $token_type is not expiring within 24 hours, skipping rotation."
    continue
  fi

  # Generate a new token
  new_token=$(api_operation "$api" "generate_token" "$token_type" "$base_url" "$user" "$password")

  if [[ -z "$new_token" ]]; then
    send_teams_message "Failed to generate token for $token_type"
    continue
  fi

  # Determine the GitHub secret API endpoint
  if [[ "$github_secret_type" == "org" ]]; then
    secret_url="https://api.github.com/orgs/$org_name/actions/secrets/$i"
    public_key_url="https://api.github.com/orgs/$org_name/actions/secrets/public-key"
  elif [[ "$github_secret_type" == "repo" && -n "$repo" ]]; then
    secret_url="https://api.github.com/repos/$org_name/$repo/actions/secrets/$i"
    public_key_url="https://api.github.com/repos/$org_name/$repo/actions/secrets/public-key"
  elif [[ "$github_secret_type" == "dependabot" && -n "$repo" ]]; then
    secret_url="https://api.github.com/repos/$org_name/$repo/dependabot/secrets/$i"
    public_key_url="https://api.github.com/repos/$org_name/$repo/dependabot/secrets/public-key"
  elif [[ "$github_secret_type" == "dependabot"]]; then
    secret_url="https://api.github.com/orgs/$org_name/dependabot/secrets/$i"
    public_key_url="https://api.github.com/orgs/$org_name/dependabot/secrets/public-key"
  else
    continue
  fi

  # Get the public key for the repository or organization
  public_key_response=$(curl -s -H "Authorization: Bearer $GITHUB_APP_TOKEN" "$public_key_url")
  public_key=$(echo "$public_key_response" | jq -r '.key')
  public_key_id=$(echo "$public_key_response" | jq -r '.key_id')

  if [[ -z "$public_key" || -z "$public_key_id" ]]; then
    send_teams_message "Failed to retrieve public key for $i"
    continue
  fi

  # Encrypt the new token
  encrypted_value=$(echo -n "$new_token" | openssl rsautl -encrypt -pubin -inkey <(echo "$public_key" | base64 -d) | base64)

  # Update the GitHub secret
  update_response=$(curl -s -X PUT -H "Authorization: Bearer $GITHUB_APP_TOKEN" -H "Content-Type: application/json" -d "{\"encrypted_value\":\"$encrypted_value\",\"key_id\":\"$public_key_id\"}" "$secret_url")

  if [[ $(echo "$update_response" | jq -r '.message') == "null" ]]; then
    send_teams_message "Successfully updated secret $i"
  else
    send_teams_message "Failed to update secret $i"
  fi
done

send_teams_message "Tokens have been rotated and GitHub secrets updated successfully."
