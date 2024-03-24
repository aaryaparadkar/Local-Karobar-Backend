const express = require('express')
const router = express.Router()
const {Signup, authLogin, uploadpart1, uploadpart2, generateOTP, verifyOTP, forgotpassword, resetPassword, insertPhotosInMongo,logout, saveEditMyKarobar, getkarobarData, deleteKarobar, viewKarobar, displayKarobar, getAllKarobarsOfUser, filtereddata } = require('./functions.js')
const authenticate = require('../middleware/authenticate.js')

router.get("/", (req,res) => {
   res.json({message : "hii atd "})
    
})

// signup
router.post("/signup" , Signup)

// login
router.post("/login" , authLogin)

//mykarobars
router.get("/mykarobars", authenticate,(req, res) => {res.send(req.rootUser)} )

 //uploadstep1
router.route("/uploadstep1process")
.get(authenticate,(req,res) => {res.send(req.rootUser)})
.post( uploadpart1 )


 //uploadstep2
 router.route("/uploadstep2process")
 .get(authenticate,(req,res) => {
    res.status(200).json({rootUser:req.rootUser,  Id:req.userId, token: req.cookies.jwtoken})
})
 .post(uploadpart2 )

//uploadstep2
//multerStorage
const multer = require('multer')

const storage = multer.diskStorage({
    destination: (req,file,cb) => {
        cb(null, "./client-frontend/public/serverImages")
        //cb(null, "./uploads/")
    },
    filename: (req,file,cb) => {
        const nameofFile = file.fieldname + "_" + Date.now() 
        cb(null, nameofFile + file.originalname )
    }
})
        
const upload = multer({ storage })

const cpUpload = upload.fields([
    { name:"profilephoto", maxCount: 1 }, 
    { name:"karobarphotos", maxCount: 30 } 
])

router.post("/uploadInUploads", cpUpload, insertPhotosInMongo)

router.post("/generateotp", generateOTP)
router.post("/verifyotp", verifyOTP)
router.post("/sendemail", forgotpassword)
router.post("/resetOperations", resetPassword)
router.get("/logout", logout)
router.post("/viewkarobar", viewKarobar)
router.get("/exploredata", displayKarobar)

//additions
router.post("/karobarData", authenticate, getkarobarData)
router.post("/saveEditMyKarobar", saveEditMyKarobar)
router.post("/saveEditMyKarobarPhotos", cpUpload, insertPhotosInMongo)
router.delete("/deleteKarobar", deleteKarobar)
router.post("/getAllKarobarsOfUser", getAllKarobarsOfUser)
router.post("/filtereddata", filtereddata)

module.exports = router