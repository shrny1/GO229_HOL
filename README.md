# GO229_HOL

# Module 1 — From Static Credentials to Secretless Auth (30 min)

## The Narrative

NovaCorp's payments pipeline authenticates to Snowflake using a user called `PIPELINE_USER_LEGACY`. Nobody remembers who created it. It has a password. It was never given a proper `TYPE` (so it defaults to `PERSON` — a human user). In practice it's a service account, but Snowflake doesn't know that.

Two Snowflake capabilities converge to surface this risk:

1. **The Strong Authentication Hub** flags this user because it has a password but no MFA. The Hub classifies this as a compliance gap and provides remediation guidance.  
     
2. **Trust Center's Threat Intelligence scanner** independently identifies the same user under "Migrate human users away from password-only sign-in."

The fix: Create a proper `TYPE = SERVICE` user with **Workload Identity Federation** — no password, no key pair, no credential to manage at all.

## Step 1: Discover the Problem — Strong Authentication Hub (UI)

**In Snowsight**: Governance & Security → Trust Center → **Overview** tab → find the **Strong authentication** progress tile → click **View hub**

**What attendees will see:**

- The Hub identifies `PIPELINE_USER_LEGACY` as a human user with **password-only** (no MFA) configuration  
- It classifies this as an at-risk user needing remediation  
- It offers guidance: "Enroll in MFA" or "Convert to a service user with stronger authentication"

---

## Step 2: Validate the Legacy User in CoCo UI or via SQL

Ask CoCo: *“Tell me more about this user PIPELINE\_USER\_LEGACY”*

OR 

```sql
SELECT
    NAME,
    TYPE,
    HAS_PASSWORD,
    HAS_MFA,
    HAS_RSA_PUBLIC_KEY,
    HAS_WORKLOAD_IDENTITY,
    COMMENT
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
WHERE NAME = 'PIPELINE_USER_LEGACY';
```

Notice: `TYPE = PERSON` (default if no type is set up), `HAS_PASSWORD = TRUE`, `HAS_MFA = FALSE`, `HAS_WORKLOAD_IDENTITY = FALSE`.

---

## Step 3: Create the WIF Replacement — Zero Credentials

```sql
-- Create a properly scoped role for the pipeline
CREATE ROLE IF NOT EXISTS PIPELINE_SVC_ROLE;
GRANT USAGE ON DATABASE FINANCE_DB TO ROLE PIPELINE_SVC_ROLE;
GRANT USAGE ON SCHEMA FINANCE_DB.TRANSACTIONS TO ROLE PIPELINE_SVC_ROLE;
GRANT SELECT ON ALL TABLES IN SCHEMA FINANCE_DB.TRANSACTIONS TO ROLE PIPELINE_SVC_ROLE;
GRANT USAGE ON WAREHOUSE LAB_WH TO ROLE PIPELINE_SVC_ROLE;
```

```sql
-- Create the WIF service user — TYPE=SERVICE, no password possible
-- Replace <YOUR_GITHUB_USERNAME> and <YOUR_REPO_NAME> with your values
USE ROLE ACCOUNTADMIN;
CREATE USER IF NOT EXISTS GITHUB_PIPELINE_SVC
    TYPE = SERVICE
    DEFAULT_ROLE = PIPELINE_SVC_ROLE
    WORKLOAD_IDENTITY = (
        TYPE    = OIDC
        ISSUER  = 'https://token.actions.githubusercontent.com'
        SUBJECT = 'repo:<YOUR_GITHUB_USERNAME>/<YOUR_REPO_NAME>:ref:refs/heads/main'
    )
    COMMENT = 'WIF service user — secretless auth via GitHub Actions OIDC';

GRANT ROLE PIPELINE_SVC_ROLE TO USER GITHUB_PIPELINE_SVC;
```

```sql
-- Verify the workload identity configuration
SHOW USER WORKLOAD IDENTITY AUTHENTICATION METHODS FOR USER GITHUB_PIPELINE_SVC;
```

**To verify the workload identity configuration, you can also use CoCo:** 

**“***Give me details about GITHUB\_PIPELINE\_SVC”*

**Key insight**: `TYPE = SERVICE` means this user *cannot have a password*. You cannot set one, reset one, or rotate one — because none exists. The only authentication path is a short-lived OIDC token issued by GitHub when the workflow runs.

**Important**: If your account has an authentication policy that restricts service users to specific methods (e.g., keypair \+ OAuth only), you must add `WORKLOAD_IDENTITY` to the allowed methods. Otherwise you'll get an "Authentication attempt rejected by the current authentication policy." error.

---

## Step 4: Connect from GitHub Actions

### One-Time Setup

1. **A GitHub repo** with the workflow file below (fork the lab repo, or create your own)  
   Link to fork the lab: [https://github.com/shrny1/hol\_test](https://github.com/shrny1/hol_test)

2. **A repository variable**: Settings → Secrets and variables → Actions → Variables → New repository variable  
   - Name: `SNOWFLAKE_ACCOUNT`  
   - Value: your Snowflake account locator (e.g., `pm-pm_dbsec`)

### The Workflow File

Create `.github/workflows/snowflake-connect.yml`:

```
name: Snowflake WIF Demo
on:
  workflow_dispatch:

permissions:
  id-token: write
  contents: read

jobs:
  connect:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Snowflake CLI with OIDC
        uses: snowflakedb/snowflake-cli-action@v2.0
        with:
          use-oidc: true
          cli-version: "3.14.0"
      - name: Query Snowflake
        env:
          SNOWFLAKE_ACCOUNT: ${{ vars.SNOWFLAKE_ACCOUNT }}
          SNOWFLAKE_USER: GITHUB_PIPELINE_SVC
        run: |
          snow sql -q "SELECT '✅ Connected without credentials! Payments count: ' || COUNT(*) AS result FROM FINANCE_DB.TRANSACTIONS.PAYMENTS" -x
```

**How it works**: The `snowflakedb/snowflake-cli-action` with `use-oidc: true` handles everything — it requests an OIDC token from GitHub (using the `id-token: write` permission), sets the correct audience, and passes it to Snowflake. No secrets anywhere in the workflow.

### Trigger It

- Go to **Actions** tab → select "Snowflake WIF Demo" on the left → click **Run workflow** → confirm

### Expected Output

```
+------------------------------------------------------+
| RESULT                                               |
|------------------------------------------------------|
| ✅ Connected without credentials! Payments count: 3  |
+------------------------------------------------------+
```

**Attendee action**: Fork the lab repo → add `SNOWFLAKE_ACCOUNT` variable → run the workflow → see it authenticate with zero secrets in the YAML.

---

## Step 5: Verify in the Audit Trail in CoCo UI or via SQL

Ask CoCo: *“Show me the latest login history for GITHUB\_PIPELINE\_SVC”*

OR 

```sql
SELECT
    USER_NAME,
    FIRST_AUTHENTICATION_FACTOR,
    SECOND_AUTHENTICATION_FACTOR,
    IS_SUCCESS,
    EVENT_TIMESTAMP,
    REPORTED_CLIENT_TYPE
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE USER_NAME = 'GITHUB_PIPELINE_SVC'
ORDER BY EVENT_TIMESTAMP DESC
LIMIT 5;
```

`FIRST_AUTHENTICATION_FACTOR = 'WORKLOAD_IDENTITY'`. Same audit trail, zero credential surface area.

Note: The login make take about \~5 minutes to show up

---

## Step 6: Decommission the Legacy User \+ Close the Loop

```sql
-- Disable the legacy user
ALTER USER PIPELINE_USER_LEGACY SET DISABLED = TRUE;
```

```sql
-- Compare side by side
SELECT
    NAME,
    TYPE,
    HAS_PASSWORD,
    HAS_WORKLOAD_IDENTITY,
    DISABLED,
    COMMENT
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
WHERE NAME IN ('PIPELINE_USER_LEGACY', 'GITHUB_PIPELINE_SVC');
```

Expected result:

| NAME | TYPE | HAS\_PASSWORD | HAS\_WORKLOAD\_IDENTITY | DISABLED |
| :---- | :---- | :---- | :---- | :---- |
| PIPELINE\_USER\_LEGACY | PERSON | TRUE | FALSE | TRUE |
| GITHUB\_PIPELINE\_SVC | SERVICE | FALSE | TRUE | FALSE |

**Return to the Hub**: Trust Center → Overview → Strong authentication → View hub. Once the scanner refreshes, `PIPELINE_USER_LEGACY` will no longer appear as at-risk.

## Module 1 Summary

| Layer | What it does | Role in this module |
| :---- | :---- | :---- |
| **Strong Auth Hub \+ Trust Center** | Identifies at-risk users, shows enforcement timeline, provides remediation steps | Told us *who* needs to fix *what* by *when* — the discovery layer |
| **Workload Identity Federation** | Eliminates credentials entirely — identity proven by platform token | The actual fix — nothing to leak, rotate, or manage |

## Troubleshooting 

| Error | Cause | Fix |
| :---- | :---- | :---- |
| "Authentication attempt rejected by the current authentication policy" | Account-level auth policy doesn't include `WORKLOAD_IDENTITY` in allowed methods | `ALTER AUTHENTICATION POLICY <name> SET AUTHENTICATION_METHODS = ('KEYPAIR', 'OAUTH', 'WORKLOAD_IDENTITY')` |
| "JWT contains an invalid audience" | Using raw Python connector instead of Snowflake CLI action | Switch to `snowflakedb/snowflake-cli-action@v2.0` with `use-oidc: true` |
| Workflow doesn't appear in Actions tab | File not on `main` branch, or path is wrong | Confirm `.github/workflows/snowflake-connect.yml` exists on `main` |
| "token must be provided if workload\_identity\_provider=OIDC" | Python connector doesn't auto-fetch GitHub OIDC token | Use Snowflake CLI action instead, or manually fetch token via `ACTIONS_ID_TOKEN_REQUEST_URL` |
| SUBJECT mismatch | Repo name in CREATE USER doesn't match actual GitHub repo | SUBJECT must be exactly `repo:<user>/<repo>:ref:refs/heads/main` |
| Verification/login or updates not showing up | Latency in the views | Re-try after 5mins |



# Module 2 — Simplified Access for AI Workloads (20 min)

## Demo 1: Access Troubleshooter 

## Demo 2: Access Requests 

## The Narrative

NovaCorp's AI/ML team built an Agentic Fraud Analyst in Snowflake Intelligence. **Alice** (the agent developer) wants to roll it out to the analytics team, but the analytics team's role can't access the underlying data. She pings **Bob** (the data admin who owns `FINANCE_DB`):

*"Hey Bob — can you grant ANALYST\_ROLE read access to FINANCE\_DB.TRANSACTIONS so my team can use the new fintech analytics agent?"*

In a typical company this kicks off a multi-day Slack-and-ticket dance. Bob has to write 14 individual `GRANT` statements, then come back every time the data engineering team adds a new table. Today, you'll watch him resolve it with **3 statements** — and delegate the next request away from himself entirely — using two new RBAC capabilities:

1. **Inherited Grants** (PuPr) — one statement replaces 14+ per-table grants and auto-covers future tables  
2. **Container-level MANAGE GRANTS** (PuPr) — Bob delegates schema-level grant management to Alice so she never has to file a ticket again

You'll play Bob as your primary persona, with quick switches into Alice's role and ANALYST\_ROLE to verify the delegation boundary and future-table coverage.

---

## Personas

| Persona | Role | Goal |
| :---- | :---- | :---- |
| **Bob** | `DB_ADMIN_FINANCE` (owns `FINANCE_DB`) | Manage access to FINANCE\_DB without filing tickets — and stop being a bottleneck |
| **Alice** | `AGENT_DEV_ROLE` | Ship her agent and (later) self-serve access requests for her team |
| `ANALYST_ROLE` | (the target role for Alice's end users) |  |

---

## ⚠️ Important: ACCOUNTADMIN Bypass

Lab attendees have ACCOUNTADMIN granted by default. Without intervention, ACCOUNTADMIN silently authorizes every query through Snowflake's secondary roles mechanism — which means the delegation boundary in Act 3 won't actually be enforceable in the demo.

**The fix**: Disable secondary roles whenever switching into a persona.

### 🎭 Persona Switch Helper

```sql
USE ROLE <PERSONA_ROLE>;
USE SECONDARY ROLES NONE;       -- ← critical: disables ACCOUNTADMIN bypass
USE WAREHOUSE LAB_WH;
SELECT CURRENT_ROLE(), CURRENT_AVAILABLE_ROLES();
```

To return to your normal admin context:

```sql
USE ROLE ACCOUNTADMIN;
USE SECONDARY ROLES ALL;
```

---

## Step 1: Bob Receives Alice's Request 

🎭 **You are Bob**, NovaCorp's database admin for `FINANCE_DB`.

```sql
USE ROLE DB_ADMIN_FINANCE;
USE SECONDARY ROLES NONE;
USE WAREHOUSE LAB_WH;

SELECT CURRENT_ROLE(), CURRENT_AVAILABLE_ROLES();
-- Expected: DB_ADMIN_FINANCE, [DB_ADMIN_FINANCE]
```

You just got a Slack message from Alice:

**Alice → Bob (Slack)**: *"Hey Bob — can you grant ANALYST\_ROLE read access to FINANCE\_DB.TRANSACTIONS? My team is rolling out the new Agentic Fraud Analyst next week and they need to be able to query the data the agent uses. Thanks\!"*

You have a problem. `FINANCE_DB.TRANSACTIONS` already has 12 tables. The data engineering team adds new ones every quarter. If you write per-table GRANT statements today, you'll be back here next quarter, and the quarter after that. Worse — if you forget a new table, Alice's agent breaks for the analytics team and you'll get another Slack message.

You need a fix that covers existing tables AND every future table the data eng team adds.

---

## Step 2: Bob Fixes It with Inherited Grants 

### The "before" picture: what Bob would have to write the old way

```sql
-- ❌ The old way: per-table grants for every existing AND future table
GRANT USAGE ON DATABASE FINANCE_DB TO ROLE ANALYST_ROLE;
GRANT USAGE ON SCHEMA FINANCE_DB.TRANSACTIONS TO ROLE ANALYST_ROLE;

GRANT SELECT ON TABLE FINANCE_DB.TRANSACTIONS.PAYMENTS            TO ROLE ANALYST_ROLE;
GRANT SELECT ON TABLE FINANCE_DB.TRANSACTIONS.ACCOUNTS            TO ROLE ANALYST_ROLE;
GRANT SELECT ON TABLE FINANCE_DB.TRANSACTIONS.FRAUD_SIGNALS       TO ROLE ANALYST_ROLE;
GRANT SELECT ON TABLE FINANCE_DB.TRANSACTIONS.MERCHANT_RISK       TO ROLE ANALYST_ROLE;
GRANT SELECT ON TABLE FINANCE_DB.TRANSACTIONS.AML_FLAGS           TO ROLE ANALYST_ROLE;
GRANT SELECT ON TABLE FINANCE_DB.TRANSACTIONS.DEVICE_FINGERPRINTS TO ROLE ANALYST_ROLE;
GRANT SELECT ON TABLE FINANCE_DB.TRANSACTIONS.LOGIN_HISTORY       TO ROLE ANALYST_ROLE;
GRANT SELECT ON TABLE FINANCE_DB.TRANSACTIONS.GEO_LOOKUPS         TO ROLE ANALYST_ROLE;
GRANT SELECT ON TABLE FINANCE_DB.TRANSACTIONS.VELOCITY_RULES      TO ROLE ANALYST_ROLE;
GRANT SELECT ON TABLE FINANCE_DB.TRANSACTIONS.SANCTIONS_LIST      TO ROLE ANALYST_ROLE;
GRANT SELECT ON TABLE FINANCE_DB.TRANSACTIONS.CARD_BIN_RANGES     TO ROLE ANALYST_ROLE;
GRANT SELECT ON TABLE FINANCE_DB.TRANSACTIONS.CASE_NOTES          TO ROLE ANALYST_ROLE;

-- And tomorrow when the data eng team adds CHARGEBACKS, REFUNDS, KYC_HISTORY,
-- IDENTITY_DOCUMENTS, SCREENING_RESULTS, ALERT_QUEUE, ROUTING_RULES... back here Bob comes.
```

14 grants today. Tomorrow there will be 25, and Bob will be back here. Miss one and Alice's agent breaks for analysts.

### The new way: three inherited grants, current AND future

```sql
-- 🎭 Still as DB_ADMIN_FINANCE with secondaries OFF

GRANT USAGE ON DATABASE FINANCE_DB TO ROLE ANALYST_ROLE;
GRANT INHERITED USAGE  ON ALL SCHEMAS IN DATABASE FINANCE_DB TO ROLE ANALYST_ROLE;
GRANT INHERITED SELECT ON ALL TABLES  IN SCHEMA FINANCE_DB.TRANSACTIONS TO ROLE ANALYST_ROLE;
```

**Three statements. Done.** Every existing table is covered. Every future table is auto-covered. No backfill, no future-grant maintenance, no missed tables.

### Verify the audit trail via CoCo

Ask CoCo: *“What grants does the Analyst\_role have?”*

OR

```sql
-- New SHOW GRANTS columns: IS_INHERITED, INHERITED_FROM, INHERITED_FROM_DATABASE, INHERITED_FROM_SCHEMA
SHOW GRANTS TO ROLE ANALYST_ROLE;

-- New command: list all inherited grants in a container
SHOW GRANTS IN DATABASE FINANCE_DB;
```

**Auditability win**: Every table the analytics team can SELECT traces back to a single inherited grant row instead of N per-table records. Container-wide access reviewable from one row.

### Prove future-table coverage

A week later, the data engineering team adds a new fraud-signal source:

```sql
-- 🎭 Still as DB_ADMIN_FINANCE
CREATE OR REPLACE TABLE FINANCE_DB.TRANSACTIONS.CHARGEBACKS (
    CHARGEBACK_ID VARCHAR,
    PAYMENT_ID VARCHAR,
    REASON_CODE VARCHAR,
    AMOUNT NUMBER(12,2)
);
INSERT INTO FINANCE_DB.TRANSACTIONS.CHARGEBACKS VALUES
    ('CB-001', 'PMT-002', 'FRAUD', 230.50),
    ('CB-002', 'PMT-003', 'DUPLICATE', 9999.99);
```

🎭 **Switch to ANALYST\_ROLE** to verify it auto-inherits SELECT — no new grant needed:

```sql
USE ROLE ANALYST_ROLE;
USE SECONDARY ROLES NONE;
USE WAREHOUSE LAB_WH;

SELECT * FROM FINANCE_DB.TRANSACTIONS.CHARGEBACKS;   -- ✅ works automatically
```

---

## Step 3: Bob Delegates Schema Management to Alice 

🎭 **Switch back to Bob**:

```sql
USE ROLE DB_ADMIN_FINANCE;
USE SECONDARY ROLES NONE;
USE WAREHOUSE LAB_WH;
```

Bob just realized: every time Alice ships a new agent or extends an existing one, an access request will come back to him. He doesn't want to be the bottleneck for the AI team's velocity — but he can't grant Alice account-level `SECURITYADMIN` either. That would let Alice manage access to *every* database in NovaCorp.

**Container-level MANAGE GRANTS** is the answer.

```sql
-- Delegate MG on the TRANSACTIONS schema to Alice's role — bounded least-privilege
GRANT MANAGE GRANTS ON SCHEMA FINANCE_DB.TRANSACTIONS TO ROLE AGENT_DEV_ROLE;
```

That's it. Alice can now manage every grant inside `FINANCE_DB.TRANSACTIONS` — and only that schema. She still cannot touch any other database or schema.

**Key concept**: Until now, the MANAGE GRANTS privilege was account-level only. Anyone who could grant access to *one* table could grant access to *every* table. Container-level MANAGE GRANTS scopes that authority to a database or schema. The "grant master" boundary is now configurable per-container.

### Verify the boundary

🎭 **Switch to Alice**:

```sql
USE ROLE AGENT_DEV_ROLE;
USE SECONDARY ROLES NONE;
USE WAREHOUSE LAB_WH;
```

Alice can now grant access inside `FINANCE_DB.TRANSACTIONS` without filing a ticket:

```sql
-- Alice creates a new role for her next agent and grants it access
CREATE ROLE IF NOT EXISTS AI_PAYMENT_OPS_ROLE;
GRANT INHERITED SELECT ON ALL TABLES IN SCHEMA FINANCE_DB.TRANSACTIONS TO ROLE AI_PAYMENT_OPS_ROLE;
-- ✅ Works — Alice has MG on this schema
```

But Alice cannot escalate beyond her boundary:

```sql
-- Try to grant access on a completely different database — fails
GRANT SELECT ON ALL TABLES IN SCHEMA SNOWFLAKE.ACCOUNT_USAGE TO ROLE AI_PAYMENT_OPS_ROLE;
-- ❌ Insufficient privileges
```

---

## Step 4: Cleanup: The Old Role Sprawl Goes Away

🎭 **Switch to admin context**:

```sql
USE ROLE ACCOUNTADMIN;
USE SECONDARY ROLES ALL;

-- Show the bloat
SHOW ROLES LIKE 'AI_READ_%';

-- Drop them — one inherited grant on ANALYST_ROLE replaces all of these
DROP ROLE IF EXISTS AI_READ_PAYMENTS_V1;
DROP ROLE IF EXISTS AI_READ_PAYMENTS_V2;
DROP ROLE IF EXISTS AI_READ_PAYMENTS_V3;
DROP ROLE IF EXISTS AI_READ_ACCOUNTS_V1;
DROP ROLE IF EXISTS AI_READ_ACCOUNTS_V2;
DROP ROLE IF EXISTS AI_READ_FRAUD_TEMP;

SELECT COUNT(*) AS remaining_ai_read_roles
FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES
WHERE NAME LIKE 'AI_READ_%' AND DELETED_ON IS NULL;
-- Expected: 0
```

---

## Module 2 Summary — Two Capabilities, One Story

| Act | Persona | Capability | What it solved |
| :---- | :---- | :---- | :---- |
| 2 | Bob | **Inherited Grants** | Replaced 14+ per-table grants with 3 statements — current \+ future, no maintenance debt |
| 3 | Bob → Alice | **Container-level MANAGE GRANTS** | Delegated schema-level grant authority to Alice — surgical least-privilege |

**The end-to-end story**: Bob received Alice's access request → resolved it with three inherited-grant statements that cover existing AND future tables → delegated schema-level authority to Alice so she never has to file a ticket again.

**From multi-day ticket dance to minutes — and tomorrow's TRANSACTIONS-scope requests are 30-second self-service for Alice.**

---

## Why `USE SECONDARY ROLES NONE` Matters

By default, Snowflake authorizes queries against **all** of a session's granted roles in parallel. This means an attendee with ACCOUNTADMIN granted will silently bypass every access check — making it impossible to demonstrate the delegation boundary in Act 3 (Alice should fail when trying to grant outside her schema).

`USE SECONDARY ROLES NONE` forces Snowflake to authorize against *only* the active primary role set by `USE ROLE`.

---

## Troubleshooting 

| Issue | Cause | Fix |
| :---- | :---- | :---- |
| Boundary check in Step 3 doesn't fail | Forgot `USE SECONDARY ROLES NONE` after `USE ROLE AGENT_DEV_ROLE` | Run both statements together when switching personas |
| `GRANT INHERITED ... fails: Insufficient privileges` | Executing role lacks MANAGE GRANTS on the container | Bob's role needs MG via the database he owns; ownership alone is not enough |
| `ANALYST_ROLE` gets "Object does not exist" even after inherited SELECT | Missing USAGE on parent schema | Add `GRANT INHERITED USAGE ON ALL SCHEMAS IN DATABASE <db>` |
| Future-table demo doesn't work | Role doesn't have inherited USAGE on parent schema | Verify with `SHOW GRANTS TO ROLE ANALYST_ROLE` — look for `IS_INHERITED = YES` rows |


# Module 3 — Automated Security Posture with Trust Center \+ Cortex Code (25 min)

## The Narrative

Modules 1 and 2 fixed two specific problems: secretless authentication for the payments pipeline, and least-privilege access for the AI team. But how does NovaCorp's security team know **everything else is in good shape**? Are there other legacy users with passwords? Over-privileged roles nobody remembers creating? Missing network policies? Drift that's accumulated since the last audit?

NovaCorp's CISO Maya needs to deliver a security posture report to the board next week. Today, this means a multi-day manual audit across role hierarchies, user lists, network configs, and authentication settings. With Trust Center \+ Cortex Code, you'll watch Bob deliver it in **15 minutes** — using:

1. **Trust Center scanners** (GA) — continuous, automated security posture monitoring with severity-ranked findings  
2. **Trust Center \+ Cortex Code "Begin Remediation"** (GA) — AI-guided, conversational remediation directly inside Snowsight  
3. **Trust Center finding lifecycle management** (GA) — mute, evidence, comments for compliance audit trails

You'll play Bob (acting on behalf of CISO Maya) as the lab attendee throughout this module. No persona switching needed — Trust Center is an admin-level activity.

---

## Personas

| Persona | Role | Goal |
| :---- | :---- | :---- |
| **Bob**  | `ACCOUNTADMIN` | Deliver a security posture report to the CISO without a multi-day audit |
| **Maya (CISO)** | (off-stage) | Get a board-ready security posture report by Friday |

---

## Step 1: Maya's Request and Opening Trust Center 

🎭 **You are Bob**, sitting at your desk Monday morning. CISO Maya pings you in Slack:

**Maya → Bob**: *"Hey Bob — I need a security posture report for the board on Friday. Can you summarize where we are on MFA, over-privileged roles, network policy, and any open security findings? Bonus if you can show resolution velocity."*

In the old world, this was 2-3 days of manual work pulling from `ACCOUNT_USAGE` views, role hierarchy queries, network policy descriptions, and a spreadsheet. Today, you're going to deliver it in 15 minutes.

```sql
USE ROLE ACCOUNTADMIN;
USE WAREHOUSE LAB_WH;
```

**In Snowsight**: Governance & Security → **Trust Center**.

The **Overview tab** gives you the headline numbers immediately:

- Findings by severity (Critical / High / Medium / Low)  
- Strong Authentication progress (from Module 1's coverage)  
- Recent activity

**Click the Violations tab** to see the full list:

You'll see seeded findings like:

- *"Roles with SYSADMIN privileges granted to non-administrative users"* — Medium severity → flags `DATA_TEAM_ADMIN`  
- *"Human users not enrolled in MFA"* — High severity → flags `LEGACY_ANALYST_USER`  
- *"Multiple users with ACCOUNTADMIN role"* — Medium severity → flags `DORMANT_ADMIN_USER`  
- *"No account-level network policy configured"* — Medium severity (possibly)  
- (Plus whatever findings the Strong Auth Hub propagates from Module 1\)

---

## Step 2: Ask Cortex Code for a Posture Summary 

Instead of writing the report by hand, Bob opens **Cortex Code chat** in Snowsight and asks:

*"Summarize the current Trust Center security posture for NovaCorp. Group by severity, highlight the top 3 most urgent findings, and tell me which ones I can remediate today versus which need org-wide coordination."*

CoCo queries `SNOWFLAKE.TRUST_CENTER.FINDINGS` and returns a prose summary like:

**Snapshot**:

- **High severity**: 1 finding — `LEGACY_ANALYST_USER` is a human user with password authentication but no MFA enrollment.  
- **Medium severity**: 3 findings — over-privileged `DATA_TEAM_ADMIN` role with SYSADMIN, multiple ACCOUNTADMIN users, missing account-level network policy.  
- **Low severity**: 2 findings — minor configuration drift.

**Top 3 most urgent**:

1. MFA gap on `LEGACY_ANALYST_USER` — fixable today via Authentication Policy  
2. SYSADMIN on `DATA_TEAM_ADMIN` — fixable today via grant cleanup  
3. Missing network policy — needs org coordination on allowed IP ranges

**Need org-wide coordination**: 1 (network policy) **Self-service remediable**: 5

Try a follow-up:

*"List remediated violations in the past 90 days with the user who resolved each one."*

This turns a 1-hour audit query into a single sentence. Save the output to your worksheet — that's most of Maya's report already drafted.  
---

## Step 3: AI-Guided Remediation

Bob picks the highest-severity finding to fix first: the MFA gap on `LEGACY_ANALYST_USER`.

### Step 3a: Click "Begin Remediation"

**In Snowsight**: Trust Center → Violations tab → click the *"Human users not enrolled in MFA"* finding → in the side panel, click the **blue Cortex AI icon** labeled **"Begin Remediation"**.

CoCo opens with the violation's full context already loaded — entity name, severity, scanner that detected it, remediation guidance, account-specific configuration.

### Step 3b: Have a conversation, not a config matrix

CoCo opens with something like:

*"I see that `LEGACY_ANALYST_USER` is a human user with a password but is not enrolled in MFA. The standard remediation is to require MFA enrollment via an Authentication Policy. I can:*

1. *Apply an existing MFA-enforcing policy at the account level (recommended for org-wide enforcement)*  
2. *Apply an MFA policy to just this user*  
3. *Disable the user if they're no longer active*

*Which path fits your governance model?"*

You can ask follow-ups:

*"What other users would be impacted if I apply this at the account level?"*

CoCo runs the dependency analysis and tells you. You decide:

*"Let's apply it to just this user for now while we coordinate the org rollout. Generate the SQL."*

### Step 3c: Review the generated SQL

CoCo shows:

```sql
-- Generated by Cortex Code
USE ROLE ACCOUNTADMIN;
USE DATABASE FINANCE_DB;
USE SCHEMA TRANSACTIONS;

CREATE OR REPLACE AUTHENTICATION POLICY ENFORCE_MFA_FOR_LEGACY_ANALYST
    AUTHENTICATION_METHODS = ('PASSWORD', 'SAML')
    MFA_ENROLLMENT = REQUIRED
    MFA_AUTHENTICATION_METHODS = ('PASSWORD')
    CLIENT_TYPES = ('SNOWFLAKE_UI', 'DRIVERS', 'SNOWSQL')
    COMMENT = 'Enforce MFA for LEGACY_ANALYST_USER per CISO request 2026-05';

ALTER USER LEGACY_ANALYST_USER SET AUTHENTICATION POLICY ENFORCE_MFA_FOR_LEGACY_ANALYST;
```

Bob reviews it (the human-in-the-loop step) and clicks **Run** directly from the chat.

### Step 3d: Repeat for the over-privileged role

Pick the *"Roles with SYSADMIN privileges"* finding → click **Begin Remediation** again.

CoCo this time:

*"`DATA_TEAM_ADMIN` has been granted `SYSADMIN`, which is broader than its name implies. I can:*

1. *Revoke `SYSADMIN` and replace with the minimum privileges actually needed (recommended)*  
2. *Rename the role to make its scope explicit*  
3. *Restrict who can use the role via authentication policy*

*Looking at the role's recent usage, I see it's only ever been used to read FINANCE\_DB. Let me suggest the minimum-privilege replacement."*

CoCo generates:

```sql
-- Generated by Cortex Code
USE ROLE ACCOUNTADMIN;

-- Revoke SYSADMIN
REVOKE ROLE SYSADMIN FROM ROLE DATA_TEAM_ADMIN;

-- Replace with the minimum privileges DATA_TEAM_ADMIN actually needs
GRANT USAGE ON DATABASE FINANCE_DB TO ROLE DATA_TEAM_ADMIN;
GRANT USAGE ON SCHEMA FINANCE_DB.TRANSACTIONS TO ROLE DATA_TEAM_ADMIN;
GRANT SELECT ON ALL TABLES IN SCHEMA FINANCE_DB.TRANSACTIONS TO ROLE DATA_TEAM_ADMIN;
```

Run it directly from the chat. Two violations fixed without a single hand-written DDL.

---

## Step 4: Manage Finding Lifecycle

Some findings can't be remediated immediately. The missing network policy needs IP ranges from the network team — that's a 2-day coordination effort. Bob doesn't want it cluttering his queue while it's in progress.

### Mute the finding while in progress

**In Snowsight**: Trust Center → Violations tab → *"No account-level network policy"* finding → click **Mute**.

A dialog appears asking for context:

*"Reason for muting"*: `In progress — coordinating with network team for IP allowlist. Target close: 2026-05-22.` *"External reference (optional)"*: `JIRA-NETSEC-4421`

Click Confirm. Muted findings don't generate notifications and don't clutter the active queue, but they remain in the audit trail.

### Add evidence to a remediated finding

For the MFA finding Bob just fixed, click into it → **Add Evidence** → upload a comment:

*"Remediated 2026-05-15 via user-level Authentication Policy. Account-wide MFA policy in progress (target Q2). Owner: Bob Patel."*

This builds the audit trail Maya needs for the board report and for SOC 2 / ISO 27001 evidence.

---

## Step 5: Verify and Report

Re-run the scanner to confirm the fixes:

**In Snowsight**: Trust Center → Manage scanners → **Security Essentials** → click **Run on demand**.

Or via SQL:

```sql
CALL SNOWFLAKE.TRUST_CENTER.RUN_SCANNER_PACKAGE('SECURITY_ESSENTIALS');
```

Wait \~30 seconds, then refresh the Violations tab. The MFA and SYSADMIN findings should now show as **Resolved**.

### Generate Maya's posture summary

Back in Cortex Code chat:

*"Generate a one-page security posture summary for the board, covering: total findings by severity (before vs after), what was remediated this week, what's in progress, and resolution velocity over the past 30 days."*

CoCo synthesizes everything you just did into a structured report — board-ready.  
---

## Module 3 Summary — Trust Center \+ CoCo Skills

| Act | Capability | What it solved |
| :---- | :---- | :---- |
| 1 | Trust Center scanners (GA) | Continuous posture monitoring — Bob walked into Monday with violations already identified, severity-ranked, and waiting |
| 2 | CoCo posture summary | Replaced a multi-hour audit query with a natural-language conversation |
| 3 | AI-guided remediation ("Begin Remediation") | CoCo generated the right SQL for two violations with full context — Bob reviewed and ran |
| 4 | Finding lifecycle (mute, evidence) | Built a clean audit trail for findings that need coordination, plus evidence on resolved ones |
| 5 | On-demand re-scan \+ posture report | Confirmed remediation worked and generated the board report from a single CoCo prompt |

**The end-to-end story**: CISO Maya asked for a security posture report → Bob opened Trust Center → CoCo summarized the posture → Bob remediated two findings via AI-guided conversation → Bob muted one in-progress finding with evidence → Bob re-ran the scanner and exported the board report — all in 15 minutes.

**From multi-day manual audit to minutes — and the same workflow runs continuously, every week.**

---

## Why This Module Builds on Modules 1 and 2

Trust Center sees everything from earlier modules:

- **Module 1's WIF user** (`GITHUB_PIPELINE_SVC`) shows up as a clean `TYPE = SERVICE` user with `WORKLOAD_IDENTITY` — Trust Center *won't* flag it (which is the point — secure config \= clean Trust Center)  
- **Module 1's disabled legacy user** (`PIPELINE_USER_LEGACY`) is excluded from active findings since it's disabled  
- **Module 2's least-privilege roles** (`ANALYST_ROLE`, `DB_ADMIN_FINANCE`) don't appear in over-privileged findings — proper bounded delegation passes Trust Center's checks  
- **The seeded violations in Act 1** (`DATA_TEAM_ADMIN`, `LEGACY_ANALYST_USER`, `DORMANT_ADMIN_USER`) are *separate* anti-patterns the lab introduces specifically for this module to demonstrate the remediation flow

This is intentional: Modules 1 and 2 demonstrated *how to do it right*. Module 3 demonstrates *how to find and fix the things that aren't yet right*.

---

## Troubleshooting 

| Issue | Cause | Fix |
| :---- | :---- | :---- |
| "Begin Remediation" button doesn't appear | Missing `SNOWFLAKE.CORTEX_USER` database role on ACCOUNTADMIN | `GRANT DATABASE ROLE SNOWFLAKE.CORTEX_USER TO ROLE ACCOUNTADMIN` |
| Trust Center page shows "No data" | Scanner packages haven't run yet | Run `CALL SNOWFLAKE.TRUST_CENTER.RUN_SCANNER_PACKAGE('SECURITY_ESSENTIALS')` and wait \~60 seconds |
| CoCo doesn't return a posture summary | `SNOWFLAKE.TRUST_CENTER.FINDINGS` view inaccessible | Confirm `SNOWFLAKE.TRUST_CENTER_ADMIN` or `SNOWFLAKE.TRUST_CENTER_VIEWER` is granted |
| Seeded violations don't appear | Pre-provisioning ran too recently for scanners to pick up | Run `CALL SNOWFLAKE.TRUST_CENTER.RUN_SCANNER_PACKAGE('SECURITY_ESSENTIALS')` after pre-provisioning |
| Threat Intelligence findings missing | Scanner package isn't enabled (it's opt-in) | UI: Trust Center → Manage scanners → Threat Intelligence → Enable |








