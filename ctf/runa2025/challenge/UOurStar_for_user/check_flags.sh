#!/bin/bash

BASE_URL="http://web.runa2025.kr:5005"
USERNAME="checker_$(date +%s)"
PASSWORD="password123"
COOKIE_JAR=$(mktemp)

echo "[*] Checking for flag posts on the server..."

# Register account
curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -X POST "$BASE_URL/auth/register" \
  -d "username=$USERNAME&password=$PASSWORD&age=25&mbti=ISTJ&sex=남" \
  > /dev/null

# Get home page
echo "[1] Fetching home page..."
curl -s -b "$COOKIE_JAR" "$BASE_URL/" > /tmp/home.html

# Extract all post IDs
echo "[2] Extracting post IDs..."
POSTS=$(grep -o "/post/[a-f0-9\-]*" /tmp/home.html | sort -u | sed 's|/post/||')

echo "[3] Found posts:"
echo "$POSTS" | nl

# Check each post
echo ""
echo "[4] Checking each post for flag..."
for POST_ID in $POSTS; do
  echo "[*] Checking post: $POST_ID"
  RESPONSE=$(curl -s -b "$COOKIE_JAR" "$BASE_URL/post/$POST_ID" 2>&1)
  
  # Check if it's accessible (not 403)
  if echo "$RESPONSE" | grep -q "runa2025{"; then
    echo "[+] FLAG FOUND!"
    echo "$RESPONSE" | grep -o "runa2025{[^}]*}"
    break
  elif echo "$RESPONSE" | grep -q "403\|Forbidden"; then
    echo "[-] Post is private (403)"
  elif echo "$RESPONSE" | grep -q "DOCTYPE"; then
    echo "[*] Post accessible but no flag"
  else
    echo "[!] Unexpected response"
  fi
done

rm -f "$COOKIE_JAR"
