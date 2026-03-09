#!/bin/bash
FILE="${1:-SystemOut.log}"
> "$FILE"

SEVERITIES=("I" "W" "E" "O")
THREADS=("0000004e" "00000052" "00000053" "00000054" "00000055" "00000060")
COMPONENTS=("WebContainer" "SystemOut" "ThreadMonitor" "ConnectionPool" "SSLChannel" "DataSource")

MESSAGES=(
  "I|SRVE0242I: [app] [/app] Servlet initialized successfully"
  "I|WSVR0001I: Server myServer open for e-business"
  "W|SRVE8094W: WARNING: Cannot set header. Response already committed"
  "W|WSVR0606W: Thread pool usage above 80%"
  "E|SRVE0293E: Servlet Error\n  javax.servlet.ServletException: Request processing failed\n    at com.ibm.ws.webcontainer.webapp.WebApp.handleException(WebApp.java:123)\n  Caused by: java.lang.NullPointerException\n    at com.example.OrderService.getOrder(OrderService.java:88)"
  "E|SESN0066E: Session error occurred\n  java.lang.IllegalStateException: Session is invalid\n    at com.ibm.ws.session.SessionData.getAttributeNames(SessionData.java:99)"
  "E|DSRA0010E: SQL State = 08003, Error Code = -4,499\n  java.sql.SQLException: Connection is closed\n    at com.ibm.db2.jcc.am.Connection.checkIfClosed(Connection.java:612)\n    at com.example.dao.UserDAO.findById(UserDAO.java:45)"
  "E|HMGR0152E: OutOfMemoryError caught, JVM heap exhausted\n  java.lang.OutOfMemoryError: Java heap space\n    at java.util.Arrays.copyOf(Arrays.java:3236)\n    at com.example.cache.LRUCache.put(LRUCache.java:102)"
  "W|WSVR0605W: Thread \"WebContainer : 3\" has been active for 612000 ms and may be hung"
  "I|DCSV1033I: DCS Stack DefaultCoreGroup at Member cell\\\\node\\\\myServer: Started"
  "E|CWWSS0008E: SSL handshake failure\n  javax.net.ssl.SSLHandshakeException: Remote host closed connection during handshake\n    at sun.security.ssl.SSLSocketImpl.a(SSLSocketImpl.java:231)"
  "I|BBOO0222I: Application [MyApp] started successfully"
  "W|J2CA0045W: Connection pool DataSource reached maximum size 50"
)

echo "Generating log events to $FILE (Ctrl+C to stop)..."

while true; do
  MILLIS=$(python3 -c "import time; print(f'{int(time.time()*1000)%1000:03d}')")
  TIMESTAMP=$(date "+%m/%d/%y %H:%M:%S:${MILLIS}")
  TZ_LABEL="CET"
  THREAD=${THREADS[$((RANDOM % ${#THREADS[@]}))]}
  MSG_LINE=${MESSAGES[$((RANDOM % ${#MESSAGES[@]}))]}
  SEV=$(echo "$MSG_LINE" | cut -d'|' -f1)
  MSG=$(echo "$MSG_LINE" | cut -d'|' -f2-)
  COMP=${COMPONENTS[$((RANDOM % ${#COMPONENTS[@]}))]}

  printf "[%s %s] %s %-14s %s %b\n" "$TIMESTAMP" "$TZ_LABEL" "$THREAD" "$COMP" "$SEV" "$MSG" >> "$FILE"

  DELAY=$(awk "BEGIN{printf \"%.1f\", 0.5 + rand() * 2.5}")
  sleep "$DELAY"
done
