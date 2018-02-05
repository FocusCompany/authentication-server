FROM node:9

WORKDIR /app

## INSTALL DEPENDENCIES
# doing this in a separate manner allows npm deps caching
COPY package.json package-lock.json ./

# TODO: should be : RUN npm install --production
RUN npm install


## COMPILE
# Copy local src/ to  docker src/
COPY ./src ./src
COPY ./keys ./keys

RUN mkdir dist/ && npm run compile

EXPOSE 3000
EXPOSE 3306

## RUN
CMD ["npm", "run", "start"]
