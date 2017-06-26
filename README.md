# Drill Crypto Functions

This library contains a collection of cryptography-related functions for Apache Drill. It generally mirrors the crypto functions in MySQL.  The package includes:

* **`md5(<text>)`**:  Returns the md5 hash of the text. (https://en.wikipedia.org/wiki/MD5)
Usage:
```sql
> select md5( 'testing' ) from (VALUES(1));
+-----------------------------------+
|              EXPR$0               |
+-----------------------------------+
| ae2b1fca515949e5d54fb22b8ed95575  |
+-----------------------------------+
```
* **`sha(<text>`) / `sha1(<text>)`**: Calculates an SHA-1 160-bit checksum for the string, as described in RFC 3174 (Secure Hash Algorithm). (https://en.wikipedia.org/wiki/SHA-1)  The value is returned as a string of 40 hexadecimal digits, or NULL if the argument was NULL. Note that `sha()` and `sha1()` are aliases for the same function. 
```sql
> select sha1( 'testing' ) from (VALUES(1));
+-------------------------------------------+
|                  EXPR$0                   |
+-------------------------------------------+
| dc724af18fbdd4e59189f5fe768a5f8311527050  |
+-------------------------------------------+
```
* **`sha2(<text>`) / `sha256(<text>)`**: Calculates an SHA-2 256-bit checksum for the string. (https://en.wikipedia.org/wiki/SHA-2)  The value is returned as a string of hexadecimal digits, or NULL if the argument was NULL. Note that `sha2()` and `sha256()` are aliases for the same function. 
```sql
> select sha2( 'testing' ) from (VALUES(1));
+-------------------------------------------------------------------+
|                              EXPR$0                               |
+-------------------------------------------------------------------+
| cf80cd8aed482d5d1527d7dc72fceff84e6326592848447d2dc0b0e87dfc9a90  |
+-------------------------------------------------------------------+
```

## Installing These Functions
This collection of functions does not have any dependencies that are not already included in Drill.  You can build the functions from source by cloning this repository, navigating to the directory and typing: 
`mvn clean package -DskipTests`.
Once you've done that, you'll find two `.jar` files in the `target/` folder.  Copy both these files to `<drill path>/jars/3rdParty`.
