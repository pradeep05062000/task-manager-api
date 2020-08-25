const express = require('express')
require('./db/mongoose')
const taskRouter = require('./routers/task')
const userRouter = require('./routers/user')

const app = express()
const port = process.env.PORT

app.use(express.json())
app.use(taskRouter)
app.use(userRouter)


const multer = require('multer')

const upload = multer({
	dest: 'images',
	limits: {
        fileSize: 1000000
    },
    fileFilter(req,file,cb) {
        if(!file.originalname.match(/\.(jpg|png)$/)) {
            return cb(new Error('Please upload a jpg or png file'))
        }

        cb(undefined,true)
    }
})

app.post('/upload', upload.single('upload') ,(req,res) => {
	res.send()
}, (error,req,res,next) => {
    res.status(400).send({'error':error.message})
})


app.listen(port, () => {
    console.log('Server is up on port ' + port)
})


