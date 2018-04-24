import mysql from 'mysql';

const db_session = mysql.createPool({
    host     : 'localhost',
    user     : 'root',
    password : 'focus42sh',
    database : 'authentication_server'
});

export default db_session;

