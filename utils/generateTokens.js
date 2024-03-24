import jwt from 'jsonwebtoken'

const generateToken = (res, userId) => {
    const token = jwt.sign({userId}, process.env.JWT_SECRET, { //userId is payload
        expiresIn: '1d'
    });

    res.cookie('jwt', token, {
        httpOnly: true,
        secure: false,
        sameSite: 'strict', //ssr attcaks
        maxAge: 30*24*60*60*1000 //30 days
    })
};

export default generateToken;