---
layout: single
title:  "SQL Injection"
date:   2023-07-26 17:22:22 +0200
categories: ['Web Exploitation']
classes: wide
toc: true
---
# What is SQL injection (SQLi)?
SQL injection (SQLi) vulnerabilities allow an attacker to interfere with the queries that an application makes to its database. It generally allows an attacker to view data that they are not normally able to retrieve. The challenge with SQL injection is that input can come from many places. People are well aware of SQLi in form fields, but also cookies and request headers can be modified by a malicious client which are not directly
set by the web app user. 

An even more tricky form of attack is **second order injection**, where an attacker does the injection
in two steps. This is usually done by placing the input into a database, but no vulnerability arises at the point where the data is stored. Later, when handling a different HTTP request, the application retrieves the stored data and incorporates it into a SQL query in an unsafe way.

## Retrieving data from database tables
In cases where the results of an SQL query are returned within the application's responses, an attacker can leverage an SQL injection vulnerability to retrieve data from other tables within the database. This is done using the `UNION` keyword, which lets you execute an additional `SELECT` query and append the results to the original query. For example, if an application executes the following query containing the user input "Gifts" when browsing to `https://insecure-website.com/products?category=Gifts`:
```sql
SELECT name, description FROM products WHERE category = 'Gifts'
```
An attacker can submit the following input:
```sql
' UNION SELECT username, password FROM users--
```
This will cause the application to return all usernames and passwords along with the names and descriptions of products. The key thing here is that the double-dash sequence `--` is a comment indicator in SQL, and means that the rest of the query is interpreted as a comment.

# SQL injection in different contexts
It's important to note that you can perform SQL injection attacks using any controllable input that is processed as a SQL query by the application. For example, some websites take input in JSON or XML format and use this to query the database. These different formats may even provide alternative ways for you to obfuscate attacks that are otherwise blocked due to WAFs and other defense mechanisms. For example, the following XML-based SQL injection uses an XML escape sequence to encode the S character in `SELECT`:
```xml
<stockCheck>
    <productId>
        123
    </productId>
    <storeId>
        999 &#x53;ELECT * FROM information_schema.tables
    </storeId>
</stockCheck>
```

# Union attacks
The `UNION` keyword lets you execute one or more additional `SELECT` queries and append the results to the original query. For example:
```sql
SELECT a, b FROM table1 UNION SELECT c, d FROM table2
```
This SQL query will return a single result set with two columns, containing values from columns `a` and `b` in `table1` and columns `c` and `d` in `table2`. For a `UNION` query to work, two key requirements must be met:
- The individual queries must return the same number of columns.
- The data types in each column must be compatible between the individual queries.

A method to find out the amount of columns involves submitting a series of `UNION SELECT` payloads specifying a different number of null values:
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
...
```
Having already determined the number of required columns, you can probe each column to test whether it can hold string data by submitting a series of `UNION SELECT` payloads that place a string value into each column in turn.

## Retrieving multiple values within a single column
You can easily retrieve multiple values together within this single column by concatenating the values together, ideally including a suitable separator to let you distinguish the combined values. For example, on Oracle you could submit the input:
```sql
' UNION SELECT username || '~' || password FROM users--
```

# Examining the database
It is often necessary to gather information about the database, including the type and version of the database software, and the contents like which tables and columns it contains.

## Querying the version
Different databases provide different ways of querying their version. For example, you could use a UNION attack with the following input for a MySQL database:
```sql
' UNION SELECT @@version--
```
## Listing the contents of the database
Most database types (with the notable exception of Oracle) have a set of views called the information schema which provide information about the database. You can query information_schema.tables to list the tables in the database:
```sql
SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;
SELECT 1, COLUMN_NAME, TABLE_NAME, TABLE_SCHEMA from INFORMATION_SCHEMA.columns 
SELECT * FROM INFORMATION_SCHEMA.tables
SELECT * FROM INFORMATION_SCHEMA.columns WHERE TABLE_NAME = 'Users'
```
## Viewing user privileges
To be able to find our current DB user, we can use any of the following queries. We can then test if we have super admin privileges.
```sql
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user

SELECT super_priv FROM mysql.user
SELECT grantee, privilege_type FROM information_schema.user_privileges
```
## Read and write files
The [LOAD_FILE()](https://mariadb.com/kb/en/load_file/) function can be used in MariaDB / MySQL to read data from files. The function takes in just one argument, which is the file name. The following query is an example of how to read the `/etc/passwd` file:
```sql
SELECT LOAD_FILE('/etc/passwd');
' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php") --
```
The [secure_file_priv](https://mariadb.com/kb/en/server-system-variables/#secure_file_priv) variable is used to determine where to read/write files from. Within MySQL, we can use the following query to obtain the value of this variable:
```sql
SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"
```
If the result shows that the `secure_file_priv` value is empty, we can read/write files to any location. The `SELECT INTO OUTFILE` statement can be used to write data from select queries into files.
```sql
SELECT * from users INTO OUTFILE '/tmp/credentials';
SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';
```

# Mitigations
Most instances of SQL injection can be prevented by using parameterized queries (also known as prepared statements) instead of string concatenation within the query. For a parameterized query to be effective in preventing SQL injection, the string that is used in the query must always be a hard-coded constant, and must never contain any variable data from any origin. Think about what phase of the development cycle you want to apply countermeasures:
- **At coding time**: the goal is to prevent vulnerabilities when writing code by doing defensive coding
(sanitize input/output, whitelisting allowed inputs, identify input sources, use prepared statements, etc.)
- **At testing time**: the goal is to detect vulnerabilities by doing static, dynamic or hybrid checking of code.
These are based on a combination of “rules” that identify dangerous coding patterns, and an information
flow analysis. If user input can reach a dangerous “sink” without being sanitized, an alarm is given. But
these tools can suffer from false positives and false negatives.
- **At run time**: you detect attacks that exploit remaining vulnerabilities. One technique is **taint-tracking**: whenever input enters the program from an untrustworthy source, it will be tainted and
the strings you create will have this information. The final string highlights potentially dangerous
sources which can be used to detect attacks.
