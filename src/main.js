import db_session from "./database";
import express from "express";

const app = express();
app.listen(3000);

app.get('/', (req, res) => res.send("Hello World"));
app.post('/signup', (req, res) => {
    console.log(req);
    res.send('Hitting /signup');
});



db_session.query('SELECT 1 + 1 AS solution', function (error, results, fields) {
    if (error) throw error;
    console.log('The solution is: ', results[0].solution);
});

db_session.end();