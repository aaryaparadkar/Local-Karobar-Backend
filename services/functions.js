require('../config/db.js')
const USER = require('../models/userModel.js')
const bcrypt = require('bcryptjs')
const crypto = require('crypto');
const otpGenerator = require('otp-generator')
const nodemailer = require("nodemailer");
const {google} = require('googleapis')
const dotenv = require('dotenv');
const { ObjectId } = require('mongodb');

dotenv.config()

exports.Signup = async(req,res) => {
    try{
        const {username , email , password , cpassword} = req.body

        if(!username || !email || !password || !cpassword){
            return res.json({status:400, msg : "Please fill"})
            
        }
        if(cpassword != password){
            return res.json({status: 401, msg:"Passwords do not match"})
        }
        const userExist = await USER.findOne({email:email})
        if (userExist){
            return res.json({status:422 ,msg:"User already exists"})
        }
        //change req.body
        const newUser = new USER({username:username, email:email, password:password})
       
        await newUser.save()
        if(!newUser){
            res.json({status:500 ,msg:"Error creating user "})
        }
        res.json({status:201, msg:"User added succesfully"})

    }catch (error){
        console.log(error)
    }
}

exports.authLogin = async(req,res) => {
    
    const {username , email , password} = req.body
    
    if ( !username || !email || !password ){
        console.log("1", username, email, password)
        return res.json({
            status: 400,
            msg : "Please enter credentials properly"
        })
    }

    const userExist = await USER.findOne({ username:username, email: email})

    if(!userExist){
        return res.json({msg : "Account not found"})
    }
    const isMatch = bcrypt.compare(password, userExist.password)
    if(!isMatch) 
    {
        return res.json({ msg: "Invalid Password"})
    }
    const token = await userExist.generateAuthToken(res)
    console.log("Your generated token is: ",token)
    return res.json({status:200, msg:"Logged in", token:token, userExist:userExist})

    // if (( !username && username =="" || !email && email=="" ) && !password && password=="" ){
    //     console.log("1", username, email, password)
    //     return res.json({
    //         status: 400,
    //         msg : "Please enter credentials properly"
    //     })
    // }

    // else if(username && email && password){
    //     console.log("2", username, email, password)

    //     const userExist = await USER.findOne({ username:username, email: email})

    //     if(!userExist){
    //         return res.json({msg : "Account not found"})
    //     }
    //     const isMatch = await bcrypt.compare(password, userExist.password)
    //     if(!isMatch) 
    //     {
    //         return res.json({ msg: "Invalid Password"})
    //     }
    //     else{
    //         const token = await userExist.generateAuthToken(res)
    //         console.log("Your generated token is: ",token)
    //         return res.json({status:200, msg:"Logged in", token:token, userExist:userExist})
    //     }
    // }
    // else if(!email && username && password){
    //     console.log("3", username, email, password)

    //     const userExist = await USER.findOne({username:username})

    //     if(!userExist){
    //         return res.json({msg : "Username not found"})
    //     }
    //     const isMatch = await bcrypt.compare(password, userExist.password)
    //     if(!isMatch) 
    //     {
    //         return res.json({ msg: "Invalid Password"})
    //     }
    //     else{
    //         const token = await userExist.generateAuthToken(res)
    //         console.log("Your generated token is: ",token)
    //         return res.json({status:200, msg:"Logged in", token:token, userExist:userExist})
    //     }
    // }

    // else if(!username && email && password){
    //     console.log("4", username, email, password)

    //     const userExist = await USER.findOne({email:email})

    //     if(!userExist){
    //         return res.json({msg : "Email not found"})
    //     }
    
    //     const isMatch = await bcrypt.compare(password, userExist.password)
    
    //     if(!isMatch) 
    //     {
    //         return res.json({ msg: "Invalid Password"})
    //     }
    //     else{
    //         const token = await userExist.generateAuthToken(res)
    //         console.log("Your generated token is: ",token)
    //         return res.json({status:200, msg:"Logged in", token:token, userExist:userExist})
    //     }
    // }
}

exports.uploadpart1 = async (req,res) => {
    const {ownerName, orgEmail, category, user} = req.body
   
    if(!ownerName || !orgEmail|| !category){
        return res.json({status:401, msg: "Please fill all fields"})
    }
    
    try{
        //AAAAAAAADDDDDDDDDDDDDTTTTTTTTTTTT
        let karobarExist = await USER.findOne({_id:user._id, 'karobars.category': category, "karobars.orgEmail": orgEmail})

        if(karobarExist){
            return res.json({status:403, msg:"Your karobar already exists"})
        }
        
        else{
            return res.json({status:200, msg:"Data stored !"})
        }
    }
    catch(error){
        console.log("UPLOAD 1 ERROR: ", error)
    }
}


exports.uploadpart2 = async (req,res) => {

    const { 
        orgName     , 
        noOfPeople  , 
        orgEmail    , 
        otp         , 
        gender      , 
        brContact   , 
        brLat       ,
        brLng       ,
        brAddress   , 
        addTag      , 
        addDesc     , 
        counter     , 
        username    , 
        ownerName   , 
        category    , 
        userId 
    } = req.body

    //AAAAAAAADDDDDDDDDDDDDTTTTTTTTTTTT
    if(
        orgName        =="" || 
        noOfPeople     =="" || 
        orgEmail       =="" || 
       // otp            =="" ||
        gender         =="" ||
        brContact      =="" ||
        brAddress      =="" ||
        counter        =="" 
        ) {
        return res.json({status:401, msg:"Please fill necessary (starred) fields."})
    }
    
    //AAAAAAAAAAAADDDDDDDDDDDTTTTTTTTTTTTTT
    const user = await USER.findOne(
        {_id: userId, 
        'karobars.category': category , 
        'karobars.orgName': orgName }
    );
    if (user) {
      return res.status(400).json({ msg: 'Same Organization Name under same category cannot be formed, try adding branches to your already created karobar instead.' });
    }

    const newKarbar =  
    {
        ownerName      : ownerName,
        orgEmail       : orgEmail,
        category       : category ,
        orgName        : orgName,
        no_of_people   : noOfPeople,
        gender         : gender ,
        no_of_branches : counter,
        branchData :{
            brContact      : brContact,
            brAddress      : brAddress,
            lat            : brLat,
            long           : brLng,
            additionalInfo : {
                tag         : addTag,
                description : addDesc
            }
        }
    }


    const updatedUser = await USER.findOneAndUpdate(
        { _id: userId },
        { $push: { karobars: newKarbar } },
        { new: true } 
      );
    
      //AAAAAAAAAAADDDDDDDDTTTTTTTTTTT
    
    const karobarIndex = updatedUser.karobars.length - 1
    
    const appendedKarobar = updatedUser.karobars[karobarIndex]
    //const karobarId = appendedKarobar._id.toString();

    const branchIndex = appendedKarobar.branchData.length - 1
    //const branchId = appendedKarobar.branchData[branchIndex]._id.toString();


  /*  const karobarId = await user.registerKarobar(
        orgName     , 
        noOfPeople  , 
        orgEmail    , 
        gender      , 
        brContact   , 
        brLat       ,
        brLng       ,
        brAddress   , 
        addTag      , 
        addDesc     , 
        counter     , 
        ownerName   , 
        category    ,   
    )*/

console.log("kIndex",karobarIndex,branchIndex )
    return res.status(200).json({karobarIndex, status:200, branchIndex,  msg:"Karobar Sucessfully Uploaded !!!"});

}

//ADDITION 2
exports.insertPhotosInMongo = async (req, res) =>{

    try{
        const userId = req.body.userId;
        let karobarIndex ;
       // const branchIndex  = req.body.branchIndex;

       if(req.body.karobarIndex){
        karobarIndex = req.body.karobarIndex;
       }
       else if(req.body.karobarId){
        const userExist = await USER.findById(userId)
        karobarIndex = userExist.karobars.findIndex(karobar => karobar._id.equals(req.body.karobarId));
       }

        //console.log("kbc: ", req.files.karobarphotos)
       
        if(req.files.profilephoto!=null || req.files.profilephoto!=""){

            let profileImage;
            req.files.profilephoto.map((file)=>{
                profileImage = file.filename
            })

            const result = await USER.updateOne(
                { _id: new ObjectId(userId) },
                {
                    $set: {
                    [`karobars.${karobarIndex}.profilephoto`]: profileImage,
                    }
                },
                {new: true}
            )
    
            // if (result) {
            //     console.log('Profile photo updated');
            // } 
            // else {
            //     console.log("Error occured while uploading profile photo. Rest data saved." )
            //     return res.status(200).json({ msg:"Error occured while uploading profile photo. Rest data saved." });
            // }
        }
        else{
            console.log("Profile photo not provided.")
        }

        if(req.files.karobarphotos!=null && req.files.karobarphotos && req.files.karobarphotos!=" " && req.files.karobarphotos!=""){

            let result;
            let karobarImage;

            const reset = await USER.updateOne(
                { _id: new ObjectId(userId) },
                {
                    $set: {
                    [`karobars.${karobarIndex}.karobarphotos`]: [],
                    }
                },
                {new: true}
            )

            req.files.karobarphotos.map(async(file)=>{
                karobarImage = file.filename
                console.log("karobarImage: ", karobarImage)

                result = await USER.updateOne(
                    { _id: new ObjectId(userId) },
                    {
                        $push: {
                        [`karobars.${karobarIndex}.karobarphotos`]: karobarImage,
                        }
                    },
                    { new: true }
                )
            })
    
            // if (result) {
            //     console.log('Karobar photos updated');
            // } 
            // else {
            //     console.log("Error occured while uploading gallery photos. Rest data saved." )
            //     return res.status(200).json({ msg:"Error occured while uploading gallery photos. Rest data saved." });
            // }
        }
        else{
            console.log("Karobar photos not provided.")
        }
        
        return res.status(200).json({ status:200, msg:"Karobar Sucessfully Uploaded !!!" });

    }
    catch(err){
        console.log(err)
        return res.json({status:404, msg:err})
    }
}


let generatedOTP
const CLIENT_ID = process.env.CLIENT_ID
const CLIENT_SECRET = process.env.CLIENT_SECRET
const REDIRECT_URI = process.env.REDIRECT_URI
const REFRESH_TOKEN = process.env.REFRESH_TOKEN

const oAuth2Client = new google.auth.OAuth2(CLIENT_ID,CLIENT_SECRET, REDIRECT_URI)
oAuth2Client.setCredentials({refresh_token: REFRESH_TOKEN})

exports.generateOTP = async(req,res) => {
    const {orgEmail} = req.body
    
    const accessToken = await oAuth2Client.getAccessToken()

    const transporter = nodemailer.createTransport({
        service: 'gmail',           
        auth: {
          type: 'oAuth2',
          user:process.env.GMAIL,
          pass: process.env.PASSWORD,
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          refreshToken : REFRESH_TOKEN,
          accessToken : accessToken 
        },
      });
    

    if(orgEmail){
        const OTP = await otpGenerator.generate(4,{lowerCaseAlphabets: false, upperCaseAlphabets: false, specialChars: false})
        generatedOTP = OTP

        const mailOptions = {
            from:process.env.GMAIL,
            to: orgEmail,
            subject: 'One-Time Password (OTP) for Local Karobar Registration.',
            text: `Dear user,

            You have requested a One-Time Password (OTP) and here is your OTP: ${OTP}.
            
            Please use this OTP within the next 5 minutes to complete your registration.
            
            If you did not request this OTP or have any concerns, please contact our support team.
            
            Thank you for choosing Local Karobar.
            
            Sincerely, 
            
            Team Local Karobar `,
            //html : '<h1> Hello you have email from LocalKarobar</h1>',
          };

        transporter.sendMail(mailOptions, (error) => {
        if (error) {
            console.error(error);
          return res.json({ status: 500, msg: 'Error sending OTP'});
        }
        return res.json({status: 201,  msg: "OTP send to email address"})
        });

    }
}

exports.verifyOTP = async(req,res) => {
    const {otp} = req.body;
    // console.log("otp iss", otp)
    // console.log("generatedot iss ", generatedOTP)
    if(otp === generatedOTP){
        generatedOTP=null
        console.log("null otp", generatedOTP)
        return res.json({status:201, msg: "Verified"})
    }
    res.json({status:400, msg: "Invalid otp"})

}

exports.forgotpassword = async(req,res) => {
    const {email} = req.body
    //console.log("Email received", email)

    const accessToken = await oAuth2Client.getAccessToken()

    const transporter = nodemailer.createTransport({
        service: 'gmail',           
        auth: {
          type: 'oAuth2',
          user:process.env.GMAIL,
          pass: process.env.PASSWORD,
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          refreshToken : REFRESH_TOKEN,
          accessToken : accessToken 
        },
      });



    if(!email){
        return res.json({status:400, msg: "Please enter email"})
    }
    const userExist = await USER.findOne({email:email})
    if(!userExist){
        return res.json({status:404, msg: "Email not found"})
    }

    const generated = crypto.randomBytes(20).toString('hex');
    const expiry = Date.now() + 300000 ; //60 minutes
    console.log("Generated token are", generated)
    console.log("Generated expiry are", expiry)

    // const updateFields = {
    //     generatedToken : generatedToken,
    //     resetTokenExpiry : resetTokenExpiry,
    // }

    // userExist.generatedToken = generatedToken
    // userExist.resetTokenExpiry = resetTokenExpiry
    // console.log("Generated token of user", userExist.generatedToken)
    
    const result = await userExist.updateOne({generatedToken: generated, resetTokenExpiry:expiry});
    console.log('Matched:', result.matchedCount);
    console.log('Modified:', result.modifiedCount);
    const resetLink = `http://localhost:3000/resetpspage/${generated}`;
       

    const mailOptions = {
        from:process.env.GMAIL,
        to: email,
        subject: 'Local Karobar - Password Reset Request',
        text: `
        Dear [User's Name],

        We have received a request to reset your password for your account with Local Karobar. To proceed with the password reset, please follow the instructions below:

        1. Click on the following link to reset your password:
        ${resetLink}

        2. You will be directed to a page where you can enter a new password for your account.

        Please note that this password reset link is valid for a 5 minutes. If you did not request this password reset, please ignore this email.

        If you continue to have trouble accessing your account or believe this request is unauthorized, please contact our support team.

        Thank you for choosing Local Karobar.

        Sincerely,

        Team Local Karobar
        `,
        //html : '<h1> Hello you have email from LocalKarobar</h1>',
      };

    transporter.sendMail(mailOptions, (error) => {
    if (error) {
        console.error(error);
      return res.json({ status: 500, msg: 'Error sending link'});
    }
    return res.json({status: 201,  msg: "Link send to email address"})
    });



}


exports.resetPassword = async(req,res) => {
    const {uniqueToken,password,cpassword } = req.body;
    
    const userExist = await USER.findOne({generatedToken:uniqueToken})
    const expiry = userExist.resetTokenExpiry
    const currentTime = Date.now()
    if(!userExist || expiry < currentTime ){
        return res.status(400).send({msg:"Invalid or expired url"})
    }

    if(!password || !cpassword){
        return res.status(403).send({ msg:"Please enter credentials"})
    }
    if(cpassword != password){
        return res.status(401).send({ msg:"Passwords do not match"})
    }

    newHashedPs = await bcrypt.hash(password, 12)
    const result = await userExist.updateOne({password:newHashedPs,generatedToken:null, resetTokenExpiry:null });
    
    res.status(200).send({ msg:"Password reset successful"})

}

exports.logout = async (req, res) => {
    res.clearCookie('jwtoken')
    //navigate("/")
    return res.status(200).send({ msg: "Logged out !"});
};

exports.viewKarobar = async(req,res) => {
    const {userId,karobarId} = req.body
    const userData = await USER.findById(userId)
    //const karobarData = await USER.findOne({_id:userId},{karobars : {$elemMatch :{_id : karobarId} }})
    //const karobarIndex = userData.karobars.findIndex(karobar => karobar._id.equals(karobarId));  
    const karobarExist = await USER.findOne(
        { _id: userId, 'karobars._id': karobarId },
        { 'karobars.$': 1 }
    )
      //  console.log("karobarExist", karobarExist.karobars)
    return res.status(200).send({ karobar:karobarExist.karobars, user:userData})
}

exports.displayKarobar = async(req,res) => {
    const users = await USER.find()
    return res.status(200).send({msg:"documents are sent", doc:users})
}

//addition 2
exports.getkarobarData = async(req, res) =>{
 
    const { karobarId } = req.body;
    if( karobarId.length < 24 )
    {
        return res.json({status:404, msg: "ObjectId is corrupted" })
    }
    try{
        const karobarExist = await USER.findOne(
            { _id: req.rootUser._id, 'karobars._id': karobarId },
            { 'karobars.$': 1 }
        )
        //const karobarExist = await userExist.karobars.findOne({_id: karobarId})

        if(!karobarExist){
            return res.json({ status:404, msg: "Not found "})
        }
        else{
            return res.json({ status:200, karobar:karobarExist, user:req.rootUser})
        }  
    }
    catch(e){
        console.log(e)
    }

}

exports.saveEditMyKarobar = async(req, res) =>{
    const { userId, karobarId, newKarobar } = req.body
    try{ 
        const userExist = await USER.findById(userId)
       
        const karobarIndex = userExist.karobars.findIndex(karobar => karobar._id.equals(karobarId));  

        if (karobarIndex >= 0 && karobarIndex < userExist.karobars.length) {
            userExist.karobars[`${karobarIndex}`] = newKarobar;
      
            await userExist.save(); 

            res.json({ status:200, msg: 'Updated successfully' });
          } else {
            res.status(404).json({ error: 'Invalid object index' });
          }

    }
    catch(err){
        console.log(err)
    }
}

exports.deleteKarobar = async(req, res) => {
    const { userId, karobarId } = req.body
    try {
        const userExist = await USER.findOne({ _id: userId });

        const karobarExist = userExist.karobars.findIndex(
            (karobar) => karobar._id.toString() === karobarId
        );;

        if (karobarExist !== -1) {
            userExist.karobars.splice(karobarExist, 1);
        
            userExist.save();
            return res.status(200).json({ status:200, msg: 'Deleted Successfully.' });
             
        } 
        else {
            console.error('Karobar not found');
        }
    } 
    catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
    }
}

exports.getAllKarobarsOfUser = async(req, res) => {
    const { userId } = req.body;

    const userExist = await USER.findById(userId)

    if(userExist)
    {
        return res.json({ status:200, user:userExist})
    }
    return
}

exports.filtereddata = async(req,res) => {

    const {category, city, locality} = req.body
    
    if(category=="" && city=="" && locality=="")
    {
        const allKarobars = await USER.find()
        return res.status(201).send({ karobars:allKarobars })
    }

    else if(category!=="" && city==="" && locality==="" ){
        //const matchedCategory = await USER.find({"karobars.category": category});
        const matchedCategory = await USER.find(
            { "karobars.category": category}, 
            {
              username: 1, // Include the email field from the user document
              "karobars.$": 1, // Include the matching karobar in the projection
            }
        )
        console.log("matchedCategory", matchedCategory)
        return res.status(202).send({category:matchedCategory})
    }

    else if(category!="" && (city!="" || locality!="") ){
        const filteredCategory = await USER.find({
            'karobars': {
                $elemMatch: {
                  'category': category,
                  'branchData.brAddress': {
                        $regex: new RegExp(city, 'i'),
                        $regex: new RegExp(locality, 'i')
                    },
                },
              },
            },
            {
              username: 1, // Include the email field from the user document
              "karobars.$": 1, // Include the matching karobar in the projection
            }
        )

          console.log(filteredCategory)
        return res.status(203).send({filteredCategory: filteredCategory})
    }

    else if(category=="" && (city!="" || locality!="") ){
        const filteredAddress = await USER.find({
                'karobars.branchData.brAddress': {
                    $regex: new RegExp(city, 'i'),
                    $regex: new RegExp(locality, 'i')
                },
            },
            {
              username: 1, // Include the email field from the user document
              "karobars.$": 1, // Include the matching karobar in the projection
            }
        )
        console.log(filteredAddress)
        return res.status(204).json({filteredAddress: filteredAddress})
    }
}