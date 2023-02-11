# Client-server File **Transfer**

This is a client-server file transfer application. Client is implemented as a simple CLI application, while the server hosts a GRPC service and uses PostgreSQL as the database.

Using the service requires creating an account with username and password. Password is hashed and stored along with the username in the database. User can then login with their credentials. Logging in saves a JWT token locally, which is used for authorization when doing other operations. The token is valid for 1 hour.

After login, user can upload files to the server. At this time, there are no user specific files and all files are stored globally without any user information. User can later download the files from the server.

## Technologies

- GRPC with TLS for client-server communication
- JWT for authorization
- PostgreSQL for database
- Docker (or Podman) for containerization of the server
