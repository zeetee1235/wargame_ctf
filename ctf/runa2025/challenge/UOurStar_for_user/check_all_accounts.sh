#!/bin/bash

BASE_URL="http://web.runa2025.kr:5005"
COOKIE_JAR=$(mktemp)

# Check all previous attacker accounts
for ACCOUNT in attacker1764407332282 attacker1764407383 attacker1764407399 attacker1764407524230; do
  echo ""
  echo "[*] Checking account: $ACCOUNT"
  
  # Login
  curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
    -X POST "$BASE_URL/auth/login" \
    -d "username=$ACCOUNT&password=password123" \
    > /dev/null 2>&1
  
  # Check home page
  HTML=$(curl -s -b "$COOKIE_JAR" "$BASE_URL/")
  
  # Count posts
  POSTCOUNT=$(echo "$HTML" | grep -o "/post/" | wc -l)
  echo "[*] Posts found: $POSTCOUNT"
  
  # Extract and check first post
  FIRSTPOST=$(echo "$HTML" | grep -o "/post/[a-f0-9-]*" | head -1 | sed 's|/post/||')
  if [ ! -z "$FIRSTPOST" ]; then
    echo "[*] First post ID: $FIRSTPOST"
    
    # Fetch the post
    POSTHTML=$(curl -s -b "$COOKIE_JAR" "$BASE_URL/post/$FIRSTPOST")
    
    # Check for flag
    if echo "$POSTHTML" | grep -q "runa2025{"; then
      echo "[+] FLAG FOUND!"
      echo "$POSTHTML" | grep -o "runa2025{[^}]*}"
    else
      echo "[-] No flag in first post"
      echo "[*] Post preview:"
      echo "$POSTHTML" | grep -oE "title|content|Look at me" | head -5
    fi
  fi
done

rm -f "$COOKIE_JAR"
