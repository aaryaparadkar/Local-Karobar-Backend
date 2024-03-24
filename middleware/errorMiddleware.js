// by default error comes in HTML so to convert it in json object middleware is used

exports.notFound = (req, res, next) => {
    const error = new Error(`Not Found - ${req.originalUrl}`);
    res.status(404);
    next(error);
}

exports.errorHandler = (e, req, res, next)=>{
    let statusCode = res.statusCode === 200 ? 500 : res.statusCode;
    let msg = e.message;

    if (e.name === 'CastError' && e.kind === 'ObjectId'){
        statusCode = 404;
        msg = "Resourse Not Found";
    }

    res.status(statusCode).json({
        msg,
        stack: e.stack,
    });
    next()
}