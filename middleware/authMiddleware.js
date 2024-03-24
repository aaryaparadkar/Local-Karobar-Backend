// import jwt from "jsonwebtoken";
// import asyncHandler from 'express-async-handler';
// import User from '../models/userModel.js';

// const protect = asyncHandler( async (req, res, next) => {
//     let token;
//     token = req.cookies.jwt;
//     if(token)
//     {
//         try{
//             const decoded = jwt.verify(token, process.env.JWT_SECRET)
//             req.user = await User.findById(decoded.userId).select('-userpwd') 
//             //userId is payload // minus userpwd doesnt return pwd field
//             next(); // VERYYYY IMPORTANTTTTT
//         }
//         catch(err){
//             res.status(401)
//             throw new Error('invalid auth')
//         }
//     }
//     else{
//         res.status(401);
//         throw new Error('Not auth')
//     }
// })

// export { protect }