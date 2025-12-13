#!/bin/bash
# 간단한 HTTP 서버를 8080 포트에서 실행하는 스크립트

PORT=8080

echo "[*] Starting HTTP server on port $PORT..."
python3 -m http.server $PORT
