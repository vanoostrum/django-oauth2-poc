# Client portal Authentication


## Criteria

### Must have

- Client validation with JWT Token signed with EdDSA
- Access Token is a JWT Token

### Nice to have

- Token endpoint with JWT Bearer Grant
- Refresh tokens?

## Options

### 1. Implement separate Authorization Server in FastAPI with Authlib

Use authlib to implement the authorization and token endpoints and
the database actions

Pro: Support for JWT Tokens and JWT Bearer Grant

Pro: FastAPI is easier to work with then Django

Con: Requires a lot of code to implement, including tests

Con: Introduces a new webservice next to the User Service

### 2. Implement in the User Service with Django Oauth Toolkit

Use the already implemented authorization and token endpoints and 
override the code for client validation and implement the JWT Bearer Grant

Pro: Requires less code because the endpoints are already implemented

Pro: Does not introduce a new webservice

Con: Requires a bit of research to know how to override certain parts of the Oauth code.

Con: Django Oauth Toolkit provides ways to override the code,
but it still feels a bit hacky

### 3. Do not implement OAuth, just issue a token after login

If we just issue a token, clients can work with that.

Pro: Easy to implement

Pro: Still uses EdDSA for client validation

Con: No Oauth standard

Con: No refresh tokens, Access token needs a long lifespan

### Note:

When Kate will take over the project, the Authorization Server will go into the 
trash bin, so all work we do will be for a temporary solution. Except off course the
token validation on the Resource Servers (APIs)