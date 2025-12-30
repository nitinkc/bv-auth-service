##### bv-common-auth is only a library:
The bv-common-auth module provides shared authentication **utilities** 
(like UserContext, SecurityContextHolder, and AuthUtils) for use in your other services. 

It **does not** implement actual authentication logic, user storage, or token issuance.

##### What the auth service does:
Exposes REST endpoints (controllers) for login, registration, password reset, etc.

Contains service logic for validating credentials, generating tokens (JWT, etc.), and managing sessions.

Uses repositories to interact with your user database (fetching, storing, updating user records).

Issues tokens or session cookies that your other services can validate using the shared utilities from bv-common-auth.

##### How they work together:
The auth service handles all authentication and user management.

Other services (REST APIs, WebSockets, etc.) use bv-common-auth to validate tokens, extract user 
info, and enforce security, but they do not handle login or user registration themselves.