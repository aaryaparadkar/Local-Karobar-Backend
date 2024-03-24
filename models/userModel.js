const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const userSchema = new mongoose.Schema({
    username: {
        type: String,
    },
    email: {
        type: String,
    },
    password: {
        type: String, 
    },

    generatedToken: {
        type:String,
    },
    resetTokenExpiry:{
        type:String,
    },

    karobars: [{
        ownerName: {
            type: String,
        },
        orgEmail: {
            type: String, 
        },
        category: {
            type: String, 
        },
        orgName: {
            type: String, 
        },
        no_of_people: {
            type: Number, 
        },
        gender: {
            type: String, 
        },
        profilephoto: {
           type: String 
        },
        karobarphotos :[{
            type: String 
        }],
        no_of_branches: {
            type: Number, 
        },
        branchData: [{
            brContact:{
                type: String, 
            },
            brAddress:{
                type: String, 
            },
            lat:{
                type: String, 
            },
            long: {
                type: String,
            },
            additionalInfo: [{
                tag : {
                    type: String,
                },
                description : {
                    type : String,
                }
            }]
        }]
    }]
},)

userSchema.pre('save', async function(next){
    if(this.isModified('password')){
        this.password = await bcrypt.hash(this.password,12)
        }
    next()
})

userSchema.methods.generateAuthToken = async function (res){
    try{
        let token = jwt.sign({_id:this._id}, process.env.SECRET_KEY)
        
        res.cookie('jwtoken', token, {
            httpOnly: true,
            secure: false,
            sameSite: 'strict', //ssr attcaks
            maxAge: 30*24*60*60*1000 //30 days
        })

        return token
        
    }catch(error){
        console.log("Token Db error: ",error)
    }
}

//NOT IN USE BY ANY PAGE
userSchema.methods.registerKarobar = async function(
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
){

    try{

        this.karobars = this.karobars.concat({
            ownerName      : ownerName,
            orgEmail       : orgEmail,
            category       : category ,
            orgName        : orgName,
            no_of_people   : noOfPeople,
            gender         : gender ,
            no_of_branches : counter,
            brContact      : brContact,
            profilephoto   : "",
            brAddress      : brAddress,
            lat            : brLat,
            long           : brLng,


            //karobarphotos  : {},
            // brAddress      : {
            //     lat    : brLat,
            //     long   : brLng,
            //     text   : brAddress,
            // },
            additionalInfo : {
                tag         : addTag,
                description : addDesc
            },
        })
        
       await this.save()

       const karobarId = updatedUser.karobars[updatedUser.karobars.length - 1]._id.toString();
       console.log(karobarId)

        return this.karobarId;
    }
    catch(error){
        console.log("register karobar error: ", error)
        return null;
    }
}

// this.karobars.brAddress = this.karobars.brAddress.concat({
//     lat    : brLat,
//     long   : brLng,
//     text   : brAddress,
// })

// this.karobars.additionalInfo = this.karobars.additionalInfo.concat({
//     tag         : addTag,
//     description : addDesc
// })

const USER = mongoose.model('2signup', userSchema)

module.exports = USER;