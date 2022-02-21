import { sign, verify } from "jsonwebtoken";
import { Request, Response } from 'express';
import { readFile } from "fs";
import { join } from 'path';
import mongoose from "mongoose";
import { UserSchema } from "../Models/User";


const PATH_PRIAVTE_KEY = join(__dirname, '..', 'auth-rs256.key');
const PATH_PUBLIC_KEY = join(__dirname, '..', 'public', 'auth-rs256.key.pub');

const X5U = 'http://localhost:3000/auth-rsa256.key.pub';

const usersConnection = mongoose.createConnection('mongodb://localhost:27017/users');
const userModel = usersConnection.model('User', UserSchema);

export const authenticate = async (req: Request, res: Response) => {
    const { email, password } = req.body;
    let user = await userModel.findOne( { email }).exec();
    if(user) {
        if(await user.password.isPasswordValid(password)) {
            readFile(PATH_PRIAVTE_KEY, (err, privateKey) => {
                if(err){
                    res.senStatus(500);
                } else {
                    sign({email, admin: true }, privateKey, {expiresIn: '1h', header: {alg: 'RS256', x5U: X5U} }, (err, token) => {
                        if(err) {
                            res.status(500).json({
                                message: err.message
                            })
                        } else {
                            res.json({token})
                        }
                    })
                }
            })
        } else {
            res.sendStatus(403);
        }
    } else {
        res.sendStatus(400);
    }
}

export const check = (req: Request, res: Response) => {
    const { token } = req.body;
    readFile(PATH_PUBLIC_KEY, (err, publicKey) => {
        if(err) {
            res.sendStatus(500);
        } else {
            verify(token, publicKey, {complete: true}, (err,decoded) => {
                if(err) {
                    res.status(400).json({
                        message: err.message
                    })
                } else {
                    res.json(decoded);
                }
            })
        }

    })
}