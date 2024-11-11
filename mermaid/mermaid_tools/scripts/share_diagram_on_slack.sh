#!/bin/sh
set -e

echo "🎨 Starting diagram generation process..."

# Check required arguments and token
if [ -z "${diagram_content:-}" ] || [ -z "${slack_destination:-}" ]; then
    echo "❌ Error: Both diagram_content and slack_destination are required."
    exit 1
fi

if [ -z "${SLACK_API_TOKEN:-}" ]; then
    echo "❌ Error: SLACK_API_TOKEN environment variable is required."
    exit 1
fi

# Set defaults and sanitize inputs
comment="${comment:-Here is the diagram.}"
output_format="${output_format:-png}"
# Sanitize output format to only allow valid formats
case "${output_format}" in
    png|svg|pdf) ;;
    *) echo "❌ Error: Invalid output format. Must be png, svg, or pdf."; exit 1 ;;
esac
OUTPUT_FILE="/data/diagram.${output_format}"

# Handle optional theme and background color
theme_arg=""
if [ -n "${theme:-}" ]; then
    case "${theme}" in
        default|dark|forest|neutral) theme_arg="--theme ${theme}" ;;
        *) echo "⚠️ Warning: Invalid theme specified, using default" ;;
    esac
fi

bg_arg=""
if [ -n "${background_color:-}" ]; then
    # Validate background color format (#RGB, #RGBA, #RRGGBB, #RRGGBBAA, or 'transparent')
    if echo "${background_color}" | grep -qE '^(#[0-9A-Fa-f]{3,8}|transparent)$'; then
        bg_arg="--backgroundColor ${background_color}"
    else
        echo "⚠️ Warning: Invalid background color format, ignoring"
    fi
fi

# Handle CSS for SVG output
css_arg=""
if [ "$output_format" = "svg" ]; then
    if [ -n "${custom_css:-}" ]; then
        # Create directory if it doesn't exist
        mkdir -p /tmp/styles
        echo "${custom_css}" > /tmp/styles/custom.css
        css_arg="--cssFile /tmp/styles/custom.css"
    else
        # Ensure default CSS file exists
        if [ -f "/tmp/styles/default.css" ]; then
            css_arg="--cssFile /tmp/styles/default.css"
        else
            echo "⚠️ Warning: Default CSS file not found, proceeding without CSS"
        fi
    fi
fi

echo "🖌️ Generating diagram..."
if ! printf '%s' "${diagram_content}" | /home/mermaidcli/node_modules/.bin/mmdc -p /puppeteer-config.json \
    --input - \
    --output "${OUTPUT_FILE}" \
    ${theme_arg} \
    ${bg_arg} \
    ${css_arg}; then
    echo "❌ Failed to generate diagram"
    exit 1
fi

[ ! -f "${OUTPUT_FILE}" ] && echo "❌ Output file was not created!" && exit 1
echo "✅ Diagram generated successfully!"

# First, share in the original thread to get the file URL
file_url=""
thread_ref=""
if [ -n "${SLACK_CHANNEL_ID:-}" ] && [ -n "${SLACK_THREAD_TS:-}" ]; then
    echo "📎 Uploading to original thread..."
    thread_response=$(curl -s \
        -F "file=@${OUTPUT_FILE}" \
        -F "filename=diagram.${output_format}" \
        -F "channels=${SLACK_CHANNEL_ID}" \
        -F "thread_ts=${SLACK_THREAD_TS}" \
        -F "initial_comment=${comment}" \
        -H "Authorization: Bearer ${SLACK_API_TOKEN}" \
        "https://slack.com/api/files.upload")
    
    thread_ok=$(printf '%s' "${thread_response}" | jq -r '.ok // false')
    if [ "${thread_ok}" = "true" ]; then
        echo "✅ Successfully shared in thread"
        file_url=$(printf '%s' "${thread_response}" | jq -r '.file.permalink // ""')
        if [ -n "${file_url}" ]; then
            thread_ref="\n_(shared from <${file_url}|original reference>)_\n\n🔒 _Please note: This is an automated share. For any updates or discussion, please use the original thread where authorized users can manage the conversation._"
        fi
    else
        error=$(printf '%s' "${thread_response}" | jq -r '.error // "Unknown error"')
        echo "⚠️ Failed to share in thread: ${error}"
    fi
fi

# Process multiple destinations
echo "📤 Processing destinations: ${slack_destination}"
# Use read to properly handle commas in strings
printf '%s' "${slack_destination}" | tr ',' '\n' | while IFS= read -r dest || [ -n "$dest" ]; do
    # Clean the destination string and remove any non-printable characters
    dest=$(printf '%s' "$dest" | tr -cd '[:print:][:space:]' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    [ -z "$dest" ] && continue
    
    echo "📤 Processing destination: ${dest}"
    
    channel=""
    full_comment="${comment}${thread_ref}"
    
    # Function to try channel lookup
    try_channel_lookup() {
        local channel_name="$1"
        local response
        response=$(curl -s -H "Authorization: Bearer ${SLACK_API_TOKEN}" \
            "https://slack.com/api/conversations.list")
        printf '%s' "${response}" | jq -r --arg name "${channel_name}" \
            '.channels[] | select(.name==$name) | .id' | head -n 1
    }

    # Function to try user lookup
    try_user_lookup() {
        local username="$1"
        local response
        # Try email lookup first
        response=$(curl -s -H "Authorization: Bearer ${SLACK_API_TOKEN}" \
            "https://slack.com/api/users.lookupByEmail?email=${username}")
        
        if [ "$(printf '%s' "${response}" | jq -r '.ok // false')" = "true" ]; then
            printf '%s' "${response}" | jq -r '.user.id'
            return
        fi
        
        # Try username lookup
        response=$(curl -s -H "Authorization: Bearer ${SLACK_API_TOKEN}" \
            "https://slack.com/api/users.list")
        printf '%s' "${response}" | jq -r --arg name "${username}" \
            '.members[] | select(.name==$name or .real_name==$name) | .id' | head -n 1
    }

    # Handle different destination formats
    if echo "${dest}" | grep -q "^#"; then
        # Channel destination with # prefix
        channel_name=$(echo "${dest}" | sed 's/^#//;s/^[[:space:]]*//;s/[[:space:]]*$//')
        channel=$(try_channel_lookup "${channel_name}")
        
        if [ -z "${channel}" ]; then
            echo "⚠️ Could not find channel #${channel_name}, trying as direct ID..."
            channel="${channel_name}"
        fi
    elif echo "${dest}" | grep -q "^@"; then
        # User destination with @ prefix
        username=$(echo "${dest}" | sed 's/^@//;s/^[[:space:]]*//;s/[[:space:]]*$//')
        channel=$(try_user_lookup "${username}")
        
        if [ -z "${channel}" ]; then
            echo "⚠️ Could not find user @${username}, trying as direct ID..."
            channel="${username}"
        fi
    else
        # Direct ID input - try to validate
        channel="${dest}"
        
        # Check if it's a valid channel ID
        channel_info=$(curl -s -H "Authorization: Bearer ${SLACK_API_TOKEN}" \
            "https://slack.com/api/conversations.info?channel=${channel}")
        
        if [ "$(printf '%s' "${channel_info}" | jq -r '.ok // false')" != "true" ]; then
            # Check if it's a valid user ID
            user_info=$(curl -s -H "Authorization: Bearer ${SLACK_API_TOKEN}" \
                "https://slack.com/api/users.info?user=${channel}")
            
            if [ "$(printf '%s' "${user_info}" | jq -r '.ok // false')" != "true" ]; then
                echo "⚠️ Warning: Could not validate destination ID, attempting to send anyway..."
            fi
        fi
    fi

    # Upload to destination
    echo "📎 Uploading to ${dest}..."
    response=$(curl -s \
        -F "file=@${OUTPUT_FILE}" \
        -F "filename=diagram.${output_format}" \
        -F "channels=${channel}" \
        -F "initial_comment=${full_comment}" \
        -H "Authorization: Bearer ${SLACK_API_TOKEN}" \
        "https://slack.com/api/files.upload")

    ok=$(printf '%s' "${response}" | jq -r '.ok // false')
    error=$(printf '%s' "${response}" | jq -r '.error // "Unknown error"')

    if [ "${ok}" != "true" ]; then
        echo "⚠️ Failed to upload to ${dest}: ${error}"
    else
        echo "✅ Successfully shared to ${dest}"
    fi
done

echo "✨ All sharing operations completed!"