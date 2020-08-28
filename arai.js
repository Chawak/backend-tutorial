const express=require("express")
const app=express()
const mongoose=require("mongoose")
const User=require("./model/user")
const bcrypt=require("bcrypt")
const jwt=require("jsonwebtoken")

const accessTokenSecret="accesstoanythingyeah"
const refreshTokenSecret="refreshyourfuckingtoken"

let refreshTokenlist=[]

app.use(express.json())

mongoose.connect('mongodb://localhost:27017/login-test',{
    useNewUrlParser: true
})

app.post('/register',async(req,res)=>
{
    
    const {username,password}=req.body
    const user=await User.findOne({username})

    if(user)
        res.json("This username is used!!!!!")
    else
    {
        const hashPassword=bcrypt.hashSync(password,10)
        const usersave=new User({username,password:hashPassword})
        await usersave.save()
        res.json('Register Complete')
        res.status(201).end()
        
    }
})

app.post('/login',async(req,res)=>{
    const {username,password}=req.body
    const hashPassword=bcrypt.hashSync(password,10)
    const user=await User.findOne({username})
    if(!user)
        res.json("Wrong Username")
    else
    {
        if(bcrypt.compareSync(password,user.password))
        {
            const accessToken=jwt.sign({username:user.username},accessTokenSecret,{expiresIn:"2m"})
            const refreshToken=jwt.sign({username:user.username},refreshTokenSecret)

            refreshTokenlist.push(refreshToken)

            res.status(200)
            res.json({message:"Login successful",accessToken,refreshToken,refreshTokenlist})
    
        }
        else
        {
            res.json('wrong password')
        }
    }
})

app.post("/logout",(req,res)=>{

    const {token}=req.body
    refreshTokenlist=refreshTokenlist.filter(t=>t!==token)

    res.json({message:"Logout Successful",refreshTokenlist})

})

const authenticateJWT=(req,res,next)=>
{
    const authHeader=req.headers.authorization

    if(authHeader)
    {
        const token=authHeader.split(' ')[1]
        jwt.verify(token,accessTokenSecret,(err,user)=>
        {
            if(err)
                return res.sendStatus(403).send("please Login")
                
            req.user=user

            next()
        })
    }
    else
        return res.sendStatus(401)
    
}

app.get('/user',authenticateJWT,async(req,res)=>{
    const user=await User.find({})
    res.json(user)
})

app.post('/token',(req,res)=>
{
    const {token}=req.body
    if(!token)
        res.status(401).end()
    else if(!refreshTokenlist.includes(token))
        res.status(403).end()
    else{
        jwt.verify(token,refreshTokenSecret,(err,user)=>
        {
            if(err)
                res.status(403).end()
            const accessToken=jwt.sign({username:user.username},accessTokenSecret,{expiresIn:"2m"})
            res.json(accessToken)
        })      
    }
})



app.listen(3000)


  