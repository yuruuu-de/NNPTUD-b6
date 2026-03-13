var express = require('express');
var router = express.Router();
let userController = require('../controllers/users')
let { RegisterValidator, handleResultValidator } = require('../utils/validatorHandler')
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
let { checkLogin } = require('../utils/authHandler')
let fs = require('fs');
let path = require('path');

let privateKey;
try {
    privateKey = fs.readFileSync(path.join(__dirname, '../keys/private.key'), 'utf8');
} catch (err) {
    console.error('Cannot read RSA private key file. Please create keys/private.key');
}
/* GET home page. */
router.post('/register', RegisterValidator, handleResultValidator, async function (req, res, next) {
    let newUser = userController.CreateAnUser(
        req.body.username,
        req.body.password,
        req.body.email,
        "69aa8360450df994c1ce6c4c"
    );
    await newUser.save()
    res.send({
        message: "dang ki thanh cong"
    })
});
router.post('/login', async function (req, res, next) {
    let { username, password } = req.body;
    let getUser = await userController.FindByUsername(username);
    if (!getUser) {
        res.status(403).send("tai khoan khong ton tai")
    } else {
        if (getUser.lockTime && getUser.lockTime > Date.now()) {
            res.status(403).send("tai khoan dang bi ban");
            return;
        }
        if (bcrypt.compareSync(password, getUser.password)) {
            await userController.SuccessLogin(getUser);
            let token = jwt.sign(
                {
                    id: getUser._id
                },
                privateKey,
                {
                    algorithm: 'RS256',
                    expiresIn: '30d'
                }
            )
            res.send(token)
        } else {
            await userController.FailLogin(getUser);
            res.status(403).send("thong tin dang nhap khong dung")
        }
    }

});
router.get('/me', checkLogin, function (req, res, next) {
    res.send(req.user)
})

router.post('/change-password', checkLogin, async function (req, res, next) {
    try {
        let { oldpassword, newpassword } = req.body;

        if (!oldpassword || !newpassword) {
            return res.status(400).send({ message: "oldpassword và newpassword là bắt buộc" });
        }

        // validate newpassword: tối thiểu 6 ký tự, có cả chữ và số
        let passwordRegex = /^(?=.*[A-Za-z])(?=.*\d).{6,}$/;
        if (!passwordRegex.test(newpassword)) {
            return res.status(400).send({
                message: "newpassword phải tối thiểu 6 ký tự và chứa cả chữ và số"
            });
        }

        let currentUser = req.user;

        if (!bcrypt.compareSync(oldpassword, currentUser.password)) {
            return res.status(400).send({ message: "oldpassword không đúng" });
        }

        currentUser.password = newpassword;
        await currentUser.save();

        res.send({ message: "Đổi mật khẩu thành công" });
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
})


module.exports = router;
