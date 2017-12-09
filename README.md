# identity-server

The server responsible for handling Focus authentication

## Running
### Prerequisites
In order to run the server you'll need the following tools :
 - [NodeJS](https://nodejs.org/en/download/package-manager/)
 - [Docker](https://docs.docker.com/engine/installation/#supported-platforms) (optional)


#### Using npm directly
```sh
npm run compile
npm run start
```

#### Using docker
```
git clone https://github.com/FocusCompany/authentication-server.git
cd authentication-server
docker build --tag=auth_server . && docker run -p3000:3000 -d auth_server
```