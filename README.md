# Drill Crypto Functions

This library contains a collection of cryptography-related functions for Apache Drill. It generally mirrors the crypto functions in MySQL.  The package includes:


* **`aes_encrypt()`/ `aes_decrypt()`**: implement encryption and decryption of data using the official AES (Advanced Encryption Standard) algorithm, previously known as “Rijndael.”
 `AES_ENCRYPT()` encrypts the string `str` using the key string `key_str` and returns a binary string containing the encrypted output. `AES_DECRYPT()` decrypts the encrypted string `crypt_str` using the key string `key_str` and returns the original cleartext string. If either function argument is NULL, the function returns NULL.

```sql
> SELECT aes_encrypt( 'encrypted_text', 'my_secret_key' ) AS aes FROM (VALUES(1));
+---------------------------+
|            aes            |
+---------------------------+
| JkcBUNAn8ByKWCcVmNrKMA==  |
+---------------------------+

 > SELECT aes_encrypt( 'encrypted_text', 'my_secret_key' ) AS encrypted,
 aes_decrypt(aes_encrypt( 'encrypted_text', 'my_secret_key' ),'my_secret_key') AS decrypted 
 FROM (VALUES(1));
+---------------------------+-----------------+
|         encrypted         |    decrypted    |
+---------------------------+-----------------+
| JkcBUNAn8ByKWCcVmNrKMA==  | encrypted_text  |
+---------------------------+-----------------+
```

* **`md2(<text>)`**:  Returns the md2 hash of the text. (https://en.wikipedia.org/wiki/MD2_(cryptography))
Usage:
```sql
> select md2( 'testing' ) from (values(1));
+-----------------------------------+
|              EXPR$0               |
+-----------------------------------+
| fc134df10d6ecafceb5c75861d01b41f  |
+-----------------------------------+
```

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
Additionally, there are also `sha384(<text>)` and `sha512(<text>)` functions which return SHA-2 hashes with 384 and 512 bit checksums.

## Installing These Functions
This collection of functions does not have any dependencies that are not already included in Drill.  You can build the functions from source by cloning this repository, navigating to the directory and typing: 
`mvn clean package -DskipTests`.
Once you've done that, you'll find two `.jar` files in the `target/` folder.  Copy both these files to `<drill path>/jars/3rdParty`.

These functions will be included in Drill 1.11.
