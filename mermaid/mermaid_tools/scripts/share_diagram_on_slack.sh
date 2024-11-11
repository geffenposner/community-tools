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

# Set defaults
comment="${comment:-Here is the diagram.}"
output_format="${output_format:-png}"
OUTPUT_FILE="/data/diagram.${output_format}"

# Handle optional theme and background color
theme_arg=""
[ -n "${theme:-}" ] && theme_arg="--theme ${theme}"
bg_arg=""
[ -n "${background_color:-}" ] && bg_arg="--backgroundColor ${background_color}"

# Handle CSS for SVG output
css_arg=""
if [ "$output_format" = "svg" ]; then
    if [ -n "${custom_css:-}" ]; then
        echo "${custom_css}" > /tmp/styles/custom.css
        css_arg="--cssFile /tmp/styles/custom.css"
    else
        css_arg="--cssFile /tmp/styles/default.css"
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
    
    thread_ok=$(printf '%s' "${thread_response}" | jq -r '.ok')
    if [ "${thread_ok}" = "true" ]; then
        echo "✅ Successfully shared in thread"
        file_url=$(printf '%s' "${thread_response}" | jq -r '.file.permalink')
        thread_ref=" _(shared from <${file_url}|original diagram>)_\n\n🔒 _Please note: This is an automated share. For any updates or discussion, please use the original thread where authorized users can manage the conversation._"
    fi
fi

# Process multiple destinations
IFS=','
for dest in ${slack_destination}; do
    dest=$(echo "$dest" | tr -d ' ')
    echo "📤 Processing destination: ${dest}"
    
    if [ "${dest}" = "#"* ]; then
        # Channel destination
        channel="${dest#"#"}"
        full_comment="${comment}${thread_ref}"
    elif [ "${dest}" = "@"* ]; then
        # DM destination - lookup user
        username="${dest#"@"}"
        user_response=$(curl -s -H "Authorization: Bearer ${SLACK_API_TOKEN}" \
            "https://slack.com/api/users.lookupByEmail?email=${username}" || \
            curl -s -H "Authorization: Bearer ${SLACK_API_TOKEN}" \
            "https://slack.com/api/users.list" | jq -r ".members[] | select(.name==\"${username}\").id")
        
        [ -z "${user_response}" ] && echo "⚠️ Skipping: Could not find user ${username}" && continue
        channel="${user_response}"
        full_comment="${comment}${thread_ref}"
    else
        echo "⚠️ Skipping invalid destination format: ${dest} (use #channel or @user)"
        continue
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

    ok=$(printf '%s' "${response}" | jq -r '.ok')
    error=$(printf '%s' "${response}" | jq -r '.error // empty')

    if [ "${ok}" != "true" ]; then
        echo "⚠️ Failed to upload to ${dest}: ${error:-Unknown error}"
    else
        echo "✅ Successfully shared to ${dest}"
    fi
done

echo "✨ All sharing operations completed!"