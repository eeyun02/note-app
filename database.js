const mysql =require("mysql2")
const dotenv =require("dotenv")
dotenv.config()

const pool = mysql.createPool({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE
}).promise()

 async function getNotes(userId) {
  const [rows] = await pool.query('SELECT * FROM notes where userId =?',[userId]);
  return [rows];
}

async function getUserbyUsername(username){
    const [result] =await pool.query(
      `SELECT * FROM users WHERE username = ? `,[username]
    )
    return result[0];
}
  
//NO LONGER USED AFTER IMPLEMENT THE BCRYPT
async function login(username,password){
  const [result] =await pool.query(
    `SELECT * FROM users WHERE username = ? AND password = ? `,[username,password]
  )
  return result.length > 0;
}


async function signupNewUser(username,email,password){
    await pool.query(
      `INSERT INTO users(email,username,password) 
      VALUES(?,?,?)`,[email,username,password]
    )
    
  }

 async function getuserId(username){
  const [userId]=await pool.query(`
  SELECT userId FROM users
  WHERE username = ?
  `,[username])
  console.log(userId[0].userId);
  return userId[0].userId;   
}


 async function checkDuplicateEmail(email) {
  const [results] = await pool.query(`
    SELECT EXISTS(
        SELECT * FROM users 
        WHERE email = ?
    ) AS recordExists
    `, [email]);
  return results[0].recordExists === 1;
}

async function checkDuplicateUsername(username) {
  const [results] = await pool.query(`
    SELECT EXISTS(
        SELECT * FROM users 
        WHERE username = ?
    ) AS recordExists
    `, [username]);
  return results[0].recordExists === 1;
}


// Function to create a new note
async function createNote(userId, contents) {
  const [result] = await pool.query(`
      INSERT INTO notes (userId, contents)
      VALUES (?, ?)
  `, [userId, contents]);
  return result.insertId;
}

// Function to update an existing note
async function updateNote(noteId, contents) {
   await pool.query(`
      UPDATE notes
      SET contents = ?
      WHERE id = ? 
  `, [contents, noteId]);
  
}

// Function to delete a note
async function deleteNote(noteId) {
   await pool.query(`
  DELETE FROM notes WHERE id = ?`
  , [noteId]);
  
}




module.exports={getUserbyUsername,getNotes,getuserId,signupNewUser,checkDuplicateEmail,checkDuplicateUsername,updateNote,createNote,deleteNote}