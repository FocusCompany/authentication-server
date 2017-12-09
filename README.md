# identity-server

The server responsible for handling Focus authentication

## Running
### Prerequisites
In order to run the server you'll need the following tools :
 - nodejs
 - docker (optional)


#### Using npm directly
```sh
npm run compile
npm run start
```

#### Using docker
```
docker build --tag=auth_server . && docker run -p3000:3000 -d auth_server
```