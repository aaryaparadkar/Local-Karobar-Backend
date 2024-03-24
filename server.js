const express  = require('express')
const cors = require('cors')
const router = require('./services/userController.js')
const cookieParser = require("cookie-parser");
const {notFound, errorHandler} = require("./middleware/errorMiddleware.js");
//const {authenticate} = require("./middleware/authenticate.js");

const dotenv = require('dotenv')
dotenv.config()

const connectDB = require('./config/db.js')
connectDB()

const app = express()

app.use(express.json({limit: '50mb'}));

app.use(express.urlencoded({
    extended: true,
    limit: '50mb'
}))

//app.use(notFound)
//app.use(errorHandler)
app.use(cookieParser())


app.use(cors({
    origin:"http://localhost:3000",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    credentials: true
}))

const PORT = process.env.PORT

app.use("/api/", router)

app.listen(PORT, () => {
    console.log("Running at", PORT)
})