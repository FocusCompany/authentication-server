# authentication-server

The server responsible for handling Focus authentication

## Running
### Prerequisites
In order to run the server you'll need the following tools :
 - [NodeJS](https://nodejs.org/en/download/package-manager/)
 - [Docker](https://docs.docker.com/engine/installation/#supported-platforms) (optional)

#### Using npm directly
```sh
npm install
npm run compile
npm run start
```

#### Using docker (optional)
```
git clone https://github.com/FocusCompany/authentication-server.git
cd authentication-server
docker build --tag=auth_server . && docker run -p3000:3000 -d auth_server
```

## API
### Endpoints
#### POST /register
You have to provide this 4 parameters to register a new user
```
- first_name: (ex. Etienne)
- last_name: (ex. Pasteur)
- email: (ex. et.pasteur@hotmail.fr)
- password: (ex. toto42sh)
```
Expected return :
```
{
    "message": "User successfully created"
}
``` 
#### POST /login
You have to provide this 2 parameters to login
```
- email: (ex. et.pasteur@hotmail.fr)
- password: (ex. toto42sh)
```
Expected return :
```
{
    "message": "Success",
    "token": "..."
}
``` 
#### POST /renew_jwt
You have to provide this parameter to renew your JWT token
```
- token: (ex. eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9........)
```
Expected return :
```
{
    "message": "Success",
    "token": "..."
}
``` 
#### DELETE /delete_jwt
You have to provide a JWT token inside the `Bearer Token` in the Authorization Header

Expected return :
```
{
    "message": "Success the token have been deleted"
}
```
#### DELETE /delete_all_jwt
You have to provide a JWT token inside the `Bearer Token` in the Authorization Header

Expected return :
```
{
    "message": "Success all the token have been deleted"
}
```
#### DELETE /delete_user
You have to provide a JWT token inside the `Bearer Token` in the Authorization Header and this parameter
```
- password: (ex. toto42sh)
```
Expected return :
```
{
    "message": "Success user and his jwt tokens have been deleted"
}
```
#### PUT /update_user
You have to provide a JWT token inside the `Bearer Token` in the Authorization Header and this optional parameters
```
- first_name: (ex. Etienne) optional
- last_name: (ex. Pasteur) optional
- email: (ex. et.pasteur@hotmail.fr) optional
- new_password: (ex. focus42sh) optional
- password: (ex. toto42sh) required
```
Expected return :
```
{
    "message": "User updated"
}
``` 

### Error Codes
All of the methods can return an unexpected `500 Internal Server Error`
##### /register
- `403 Forbidden` : {message: "User is already registered"}
- `400 Bad Request` : {message: "Something is missing, please verify your POST parameters"}
##### /login
- `401 Unauthorized` : {message: "User not found"}
- `401 Unauthorized` : {message: "Wrong password"}
- `400 Bad Request` : {message: "Email or Password is missing"}
##### /renew_jwt
- `401 Unauthorized` : {message: "Invalid token"}
##### /delete_jwt
- `401 Unauthorized`
##### /delete_user
- `401 Unauthorized` : {message: "Wrong password"}
##### /update_user
- `403 Forbidden` : {error: "Email already used"}
- `401 Unauthorized` : {message: "Wrong password"}
