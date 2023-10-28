JWKS Server with SQLite Integration
This is a basic JWKS (JSON Web Key Set) server with SQLite integration. It serves as a starting point for building a RESTful API that provides public keys for JWT (JSON Web Token) verification and can handle key expiration. It also includes an example of issuing JWTs upon successful authentication.

Python 3.x
SQLite
Required Python libraries (cryptography, urllib, base64, json, jwt)
Installation
Clone this repository to your local machine.

Create a new SQLite database file named totally_not_my_privateKeys.db.

Define the table schema for the keys in your SQLite database. You can use tools like "DB Browser for SQLite" for visual schema creation. The table should have columns for kid, key (BLOB data type), and exp (integer for expiration timestamp).

Modify the code to generate private keys and store them in the SQLite database. You may need to serialize the keys (e.g., to PKCS1 PEM format) for storage.

Usage
Run the server using python your_server_file.py.
The server exposes two endpoints: POST:/auth and GET:/.well-known/jwks.json.
POST:/auth
Use this endpoint for JWT authentication.
It reads a private key from the database and signs a JWT.
You can pass the "expired" query parameter to test with expired keys.

