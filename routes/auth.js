const router = require("express").Router();
const User = require("../models/User");
const bcrypt = require("bcrypt");
 
const secretKey  = 'kite1874';
 
 
//REGISTER
router.post("/register", async (req, res) => {
  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPass = await bcrypt.hash(req.body.password, salt);
    const newUser = new User({
      username: req.body.username,
      email: req.body.email,
      password: hashedPass,
    });
    

    const user = await newUser.save();
     
     
      
     res.status(200).json({user});
  } catch (err) {
    res.status(500).json(err);
  }
});

//LOGIN
router.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username });
    if (!user) {
      return res.status(400).json("Wrong credentials!");
    }

    const validated = await bcrypt.compare(req.body.password, user.password);
    if (!validated) {
      return res.status(400).json("Wrong credentials!");
    }
  
    const { password, ...others } = user._doc;
    res.status(200).json(others);
    const token = jwt.sign({  username,password }, secretKey, { expiresIn: '1h' }); // Set your own secret key and expiration time
   
    res.cookie('token', token, { httpOnly: true, expires: new Date(Date.now() + 3600000) }); 
    res.json({token});
  } catch (err) {
    res.status(500).json(err);
  }
});

 
module.exports = router;