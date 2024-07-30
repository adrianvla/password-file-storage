const express = require('express');
const exphbs = require('express-handlebars');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');
const app = express();
const path = require('path');
const fileUpload = require('express-fileupload');
const port = process.env.PORT || 5002;
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(fileUpload());
let authTokens = {};
app.use(express.json());
let FILES = {};

fs.readFile(process.cwd()+'/files.json', 'utf8', (err, data) => {
    if (err) {
        console.error(err);
        return;
    }
    FILES = JSON.parse(data);
});
const users = [
    {
        username: 'admin',
        password: 'wjvLrQF2y7DVeJywm+4lKSIS4ShNEqrWRFe3qWH1McI='
    }
];
app.engine('hbs', exphbs.engine({
    extname: '.hbs',
    defaultLayout: 'main',
    layoutsDir: path.join(__dirname, 'views', 'layouts')
}));
app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));

app.set('view engine', 'hbs');
const generateAuthToken = () => {
    return crypto.randomBytes(30).toString('hex');
}

const generateFileUUID = () => {
    return crypto.randomBytes(20).toString('hex');
}

const getHashedPassword = (password) => {
    const sha256 = crypto.createHash('sha256');
    const hash = sha256.update(password).digest('base64');
    return hash;
}  
app.get('/admin', (req, res) => {
    if(req.user){
        res.redirect('/');
        return;
    }
    res.render(process.cwd()+'/views/'+'layouts/login.hbs');
});

app.post('/admin', function (req, res) {
    const { username, password } = req.body;
    const hashedPassword = getHashedPassword(password);

    const user = users.find(u => {
        return u.username == username && hashedPassword == u.password
    });

    if (user) {
        const authToken = generateAuthToken();

        // Store authentication token
        authTokens[authToken] = user;

        // Setting the auth token in cookies
        res.cookie('AuthToken', authToken);

        // Redirect user to the protected page
        res.redirect('/');
    } else {
        res.render(process.cwd()+'/views/'+'layouts/login.hbs', {
            message: 'Invalid username or password',
            messageClass: 'alert-danger'
        });
    }
});
app.get('/logout', (req, res) => {
    // Clear the authentication token from cookies
    res.clearCookie('AuthToken');

    // Remove the authentication token from the server
    delete authTokens[req.cookies['AuthToken']];

    // Redirect user to the login page
    res.redirect('/');
});
app.use((req, res, next) => {
    // Get auth token from the cookies
    const authToken = req.cookies['AuthToken'];

    // Inject the user to the request
    req.user = authTokens[authToken];

    next();
});
const requireAuth = (req, res, next) => {
    // console.log(req,res)
    if (req.user) {
        //check if user is in auth tokens
        //check if user is in auth tokens
        if(!users.find(u => u.username == req.user.username)){
            res.render(process.cwd()+'/views/'+'layouts/login.hbs', {
                message: 'Please login to continue',
                messageClass: 'alert-danger'
            });
            return;
        }

        next();
    } else {
        res.render(process.cwd()+'/views/'+'layouts/login.hbs', {
            message: 'Please login to continue',
            messageClass: 'alert-danger'
        });
    }
};
app.get('/',(req, res) => {
    // let files = fs.readdirSync(process.cwd()+'/storage');
    let files = {};
    // console.log(files);
    //for each in files, delete password and required
    for(let i = 0; i < Object.keys(FILES).length; i++){
        let file = FILES[Object.keys(FILES)[i]];
        files[i] = {name:file.name, to_download:Object.keys(FILES)[i]};
    }
    let toSend = {files:files};
    if(req.user){
        toSend.user = true;
    }
    // console.log(toSend);
    res.render(process.cwd()+'/views/'+'layouts/home.hbs',toSend);
});
app.post('/upload', requireAuth, (req, res) => {
    if (!req.files || !req.files.files) {
        return res.status(400).send('No files were uploaded.');
    }

    // Get the uploaded file
    let file = req.files.files;
    let fileName = file.name;
    let fileUUID = generateFileUUID();
    let password = req.body.password;
    let required = req.body.require === 'on'; // Checkbox value is 'on' if checked

    // Store file information
    FILES[fileUUID] = {
        name: fileName,
        password: password,
        required: required
    };

    // Save FILES to a JSON file
    fs.writeFile(process.cwd() + '/files.json', JSON.stringify(FILES), (err) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error saving file information.');
        }
    });

    // Move the uploaded file to the storage directory
    file.mv(process.cwd() + '/storage/' + fileName, function(err) {
        if (err) {
            return res.status(500).send(err);
        }
        // res.send('File uploaded successfully.');
        res.redirect('/');
    });
});
app.get('/upload', requireAuth, (req, res) => {
    res.render(process.cwd()+'/views/'+'layouts/upload.hbs');
});
app.get('/file/*', function (req, res) {
    // const filePath = process.cwd() + req.url;
    let fileName = req.url.split("/").pop();
    //remove everything after ?
    fileName = fileName.split("?")[0];
    

    const password = FILES[fileName].password;
    const filepath = FILES[fileName].name;
    //require password defined in FILES.fileName




    //if password is correct
    if(FILES[fileName].required){
        if(req.query.password != password){
            res.render(process.cwd()+'/views/'+'layouts/pass.hbs',{file:filepath,
                message: 'You have entered an incorrect password, or you just haven\'t entered any password at all',
                messageClass: 'alert-danger'
            });
            return;
        }
    }


    if(FILES[fileName]){
        res = res.status(200);
        // res.setHeader('Content-Type', 'application/pdf');
        // res.send(fs.readFileSync(process.cwd()+'/storage/'+fileName));
        res.download(process.cwd()+'/storage/'+filepath,filepath);
    }   
    else{
        res.status(404).send('File not found');
    }
});

// app.get('/pass/*', function (req, res) {
//     const fileName = req.url.split("/").pop();
//     res.render(process.cwd()+'/views/'+'layouts/pass.hbs',{file:fileName});
// });



app.get('/style.css', function (req, res) {
    res.sendFile(process.cwd() + "/views/css/style.css");
});
app.get('/main.js', function (req, res) {
    res.sendFile(process.cwd() + "/views/scripts/main.js");
});

app.listen(port,"0.0.0.0", () => {
    console.log(`Server listening at http://localhost:${port}`);
});
