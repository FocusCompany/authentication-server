# authentication-server

The server responsible for handling Focus authentication

## Running
### Prerequisites
In order to run the server you'll need the following tools :
 - [NodeJS](https://nodejs.org/en/download/package-manager/)
 - [Docker](https://docs.docker.com/engine/installation/#supported-platforms)

```
git clone https://github.com/FocusCompany/authentication-server.git
cd authentication-server
docker-compose -f compose-<prod|dev>.yml up -d
```

## API
### Endpoints

```
/api/v1/
```

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
You have to provide this an email and a password in parameters to login (optionally you can provide a device_id to authenticate a device)
```
- email: (ex. et.pasteur@hotmail.fr) required
- password: (ex. toto42sh) required
- device_id: (ex. 23) optional
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
    "message": "Success user and his data have been deleted"
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
#### GET /get_devices
You have to provide a JWT token inside the `Bearer Token` in the Authorization Header

Expected return :
```
{
    "code": "SUCCESS",
    "message": "Successfully get info ",
    "devices": [
        {
            "id_devices": 1,
            "devices_name": "MacBook Pro de Etienne",
            "is_deleted": 0,
            "users_uuid": "66ccfbd9-8844-4370-a517-80646dad3820",
            "collections": [
                {
                    "id_collections": 3,
                    "collections_name": "HOME"
                },
                {
                    "id_collections": 4,
                    "collections_name": "WORK"
                }
            ]
        },
        {
            "id_devices": 2,
            "devices_name": "Test",
            "is_deleted": 0,
            "users_uuid": "66ccfbd9-8844-4370-a517-80646dad3820",
            "collections": []
        }
    ]
}
```
#### POST /register_device
You have to provide a JWT token inside the `Bearer Token` in the Authorization Header and this parameter
```
- devices_name: (ex. MacBook Pro de Etienne)

```
Expected return :
```
{
    "message": "Success the device has been registered",
    "deviceId": 1
}
```
#### DELETE /delete_device
You have to provide a JWT token inside the `Bearer Token` in the Authorization Header and this parameter
```
- device_id: (ex. 1)
- keep_data: (ex. true/false)

```
Expected return :
```
{
    "message": "Device deleted, Data deleted/kept"
}
```
#### POST /create_group
You have to provide a JWT token inside the `Bearer Token` in the Authorization Header and this parameter
```
- collections_name: (ex. HOME)
```
Expected return :
```
{
    "message": "Success the group has been created",
    "groupId": 1
}
```
#### DELETE /delete_group
You have to provide a JWT token inside the `Bearer Token` in the Authorization Header and this parameter
```
- collections_name: (ex. HOME)
```
Expected return :
```
{
    "message": "Group deleted"
}
```
#### GET /list_group
You have to provide a JWT token inside the `Bearer Token` in the Authorization Header
Expected return :
```
{
    "code": "SUCCESS",
    "message": "Success",
    "collections": [
        {
            "id_collections": 3,
            "collections_name": "HOME"
        },
        {
            "id_collections": 4,
            "collections_name": "WORK"
        }
    ]
}
```
#### POST /add_device_to_group
   You have to provide a JWT token inside the `Bearer Token` in the Authorization Header and this parameter
   ```
   - collections_name: (ex. HOME)
   - device_id: (ex. 1)
   ```
   Expected return :
   ```
   {
       "message": "Success the device has been added to group",
       "deviceId": 1,
       "collectionId": 1
   }
   ```
#### DELETE /remove_device_from_group
You have to provide a JWT token inside the `Bearer Token` in the Authorization Header and this parameter
```
- collections_name: (ex. HOME)
- device_id: (ex. 1)
```
Expected return :
```
{
    "message": "Device deleted from group"
}
```

### Error Codes
```
MISSING_PARAMETERS: "MISSING_PARAMETERS",
WRONG_PARAMETERS: "WRONG_PARAMETERS",
ALREADY_REGISTERED: "ALREADY_REGISTERED",
DATABASE_ERROR: "DATABASE_ERROR",
SUCCESS: "SUCCESS"
```
