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

RUN mkdir dist/ && npm run compile

EXPOSE 3000

## RUN
CMD ["npm", "run", "start"]