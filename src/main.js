const express = require('express');
const app = express();
app.listen(3000);


app.get('/', (req, res) => res.send("Hello World"));

app.post('/signup', (req, res) => {
    console.log(req);
    res.send('Hitting /signup');
});
