
const express = require("express")
const app = express()
const flash = require("express-flash")
const session = require("express-session")
const { body, validationResult } = require('express-validator');
const bcrypt = require("bcrypt") 
const path = require("path")
const { getUserbyUsername,getNotes,signupNewUser,getuserId,checkDuplicateEmail,checkDuplicateUsername,updateNote,createNote,deleteNote } =require("./database.js")



app.use(express.static(path.join(__dirname , "public")));
app.use(express.urlencoded({extended:false}))
app.set('view engine', 'ejs'); // Set the template engine to ejs
app.set('views', path.join(__dirname, 'views')); // Set the views directory
app.use(flash())
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        maxAge:  30 * 60 * 1000 // 30 minites
    }
}));
app.use(express.json()); // for parsing application/json




app.post("/signup" ,[
    // Sanitize and validate the username
    body('username')
      .trim() // Remove any whitespace
      .isLength({ min: 3, max: 30 }).withMessage('Username must be between 3 and 30 characters.')
      .matches(/^\S*$/).withMessage('Username must not contain spaces.')
      .escape(), // Sanitize to prevent XSS attacks

    // Sanitize and validate the email
    body('email')
      .trim()
      .normalizeEmail() // Normalize the email address
      .isEmail().withMessage('Must be a valid email address'),

    // Validate the password
    body('password')
      .trim()
      .isLength({ min: 8, max: 16 }).withMessage('Password must be between 8 and 16 characters.')
      .matches(/^\S*$/).withMessage('Username must not contain spaces.')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?!.*[;'"/\\|<>{}]).*$/)
      .withMessage('Password must include at least one uppercase letter, one lowercase letter, and one number, and must not include sensitive symbols like ;\'"/\\|<>{}'),
  ],async (req,res)=>{
    const errors = validationResult(req);
    console.log(errors);
        if (!errors.isEmpty()) {
            // Return only the first error message
            const firstError = errors.array({ onlyFirstError: true })[0];
            return res.render('signup', { errors: [firstError] });
        }
        try {
            const result = await checkDuplicateEmail(req.body.email)
            if (result)
            {
                
                req.flash('notification', 'Email duplicated!');
            
                return res.redirect('/signup');
                
            }else{
                const result = await checkDuplicateUsername(req.body.username)
                if (result){
                    req.flash('notification', 'Username duplicated!');
            
                    return res.redirect('/signup');
                }else{
                    const hashedPassword = await bcrypt.hash(password, 10)
                    await signupNewUser(username, email,hashedPassword)
                    req.flash('notification', 'SUCCESSFULLY SIGN UP!');
                    res.redirect("/login2")
                }
            }
            
            
        } catch (error) {
            console.log(error)
            res.redirect("/signup")
        }

})

//session check
function checkAuthenticated(req, res, next) {
    if (!req.session.userId) {
        return res.redirect('/login2');
    }
    next();
}

//broken access control
function checkAuthorization(req, res, next) {
    const requestedUserId = req.params.userId;
    const sessionUserId = req.session.userId.toString();

    if (sessionUserId !== requestedUserId) {
        return res.status(403).send("Access Denied: You are not authorized to view these notes.");
    }
    next();
}

app.post("/login2" ,[
    // Sanitize and validate the username
    body('username')
      .trim() // Remove any whitespace
      .isLength({ min: 3, max: 30 }).withMessage('Username must be between 3 and 30 characters.')
      .escape(), // Sanitize to prevent XSS attacks
    
    // Validate the password
    body('password')
      .isLength({ min: 8, max: 16 }).withMessage('Password must be between 8 and 16 characters.')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?!.*[;'"/\\|<>{}]).*$/)
      .withMessage('Password must include at least one uppercase letter, one lowercase letter, and one number, and must not include sensitive symbols like ;\'"/\\|<>{}'),
  ],async (req,res)=>{
    const errors = validationResult(req);
    console.log(errors);
        if (!errors.isEmpty()) {
            // Return only the first error message
            const firstError = errors.array({ onlyFirstError: true })[0];
            return res.render('login2', { errors: [firstError] });
        }
    try {
        const userN=req.body.username;
        const pass=req.body.password;
        if (!userN.trim() || !pass.trim()) {
            console.log("Invalid input!");
            req.flash('notification', 'Invalid input!');
            res.redirect('/login2');
        } else {
            const user = await getUserbyUsername(userN)
            if (user && await bcrypt.compare(pass, user.password)) {
                console.log("Login successful, redirecting...");
                req.flash('notification', 'SUCCESSFULLY LOGIN!');
               
                const userId=await getuserId(userN);
                if (userId) {
                    req.session.userId = userId;  // Set user-specific session data
                    // req.flash('notification', 'SUCCESSFULLY LOGIN!');
                    console.log("Environment:", process.env.NODE_ENV);

                    res.redirect(`/notes2/${userId}`);  // Redirect to the notes page
                } else {
                    throw new Error('User ID not found after successful login');
                }
                // res.redirect(`/notes2/${userId}`);
            } else {
                console.log("Login failed");
                req.flash('notification', 'Incorrect username/password!');
                res.redirect("/login2");
            }
            console.log("Login handler finished");
        }
         
    } catch (error) {
        console.log(error);
        req.flash('notification', 'Login failed due to server error');
        res.redirect("/login2");
    }

})





// force logged out
app.get('/session-active-check', (req, res) => {
    if (req.session.userId) {
        res.json({ sessionActive: true });
    } else {
        res.json({ sessionActive: false });
    }
});

app.get('/notes2/:userId',checkAuthenticated,checkAuthorization, async (req, res) => {
    const userId = req.params.userId;
    const [notes]=await getNotes(userId);
  res.render('notes2', { userId:userId,notes:notes,messages: req.flash('notification') });
});

function escapeHTML(text) {
    if (text === null || text === undefined) return '';
    return text.replace(/&/g, '&amp;')
               .replace(/</g, '&lt;')
               .replace(/>/g, '&gt;')
               .replace(/"/g, '&quot;')
               .replace(/'/g, '&#039;')
               .replace(/\//g, '&#x2F;') 
               .replace(/`/g, '&#x60;'); 
}


function escapeJavaScript(text) {
    return JSON.stringify(text); // This will escape quotes, backslashes, and control characters
}





// Route to handle note creation
app.post('/create-note/:userId', async (req, res) => {
    
    let noteContent  = req.body.noteContent;
  const userId = req.params.userId;
  noteContent = escapeHTML(noteContent);
  
  await createNote(userId,noteContent);
  res.redirect(`/notes2/${userId}`);
});

// Route to update a note
app.post('/update-note/:id', async (req, res) => {
  const id = req.params.id;
  let  noteContent  = req.body.noteContent;
  noteContent = escapeHTML(noteContent);
  const userId = req.params.userId;
  await updateNote(id,noteContent);
  res.redirect(`/notes2/${userId}`);
});

// Route to delete a note
app.post('/delete-note/:id', async (req, res) => {
  const  id  = req.params.id;
  const userId = req.params.userId;
  await deleteNote(id);
  res.redirect(`/notes2/${userId}`);
});


app.get('/check-session', (req, res) => {
    if (!req.session.userId) {
        res.json({ isLoggedIn: false });
    } else {
        res.json({ isLoggedIn: true });
    }
});


app.get('/login2',(req,res)=>{
    res.render('login2', { errors: [] })
})


app.get('/signup',(req,res)=>{
    res.render('signup', { errors: [] })
    
})

app.get('/logout', (req, res) => {
    const userId = req.session.userId;
    req.session.destroy(err => {
        if (err) {
            console.log('Session destruction error:', err);
        }
        // res.clearCookie('connect.sid', { path: `/notes2/${userId}`, secure: true });
        console.log("cookie");
        res.clearCookie('connect.sid'); // Adjust according to your session cookie name
        setTimeout(() => {
            res.redirect('/login2');
        }, 1000); 
    });
});

  

app.listen(3000)
