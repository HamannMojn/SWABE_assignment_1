import { Schema } from 'mongoose';
import { DIGEST, ITERATIONS, KEY_LENGTH, pbkdf2 } from '../utils/auth-crypto'

export interface User {
    Name: Name,
    Password: Password,
    Role: Role,
    Email: string
}


export interface Name {
    first: string;
    middle?: string;
    last?: string;
}

export interface Password {
    hash: string;
    salt: string;
    setPassword(hash: string, salt: string): void;
    isPasswordValid(Password: string): boolean;
}

export enum Role {
    Guest = "Guest",
    Clerk = "Clerk",
    Manager = "Manager"
}

export const NameSchema = new Schema<Name> ({
    first: {type: String, required: true},
    middle: {type: String},
    last: {type: String}
})

export const PasswordSchema = new Schema<Password> ({
    hash: { type: String, required: true},
    salt: { type: String, required: true}
})

export const UserSchema = new Schema<User> ({
    Name: {type: NameSchema, required: true},
    Password: {type: PasswordSchema, required: true},
    Role: ["Guest", "Clerk", "Manager"],
    Email: { type: String, required: true}
})

PasswordSchema.methods.isPasswordValid = async function(password: string) {
    const hash = await pbkdf2(password, this.salt, ITERATIONS, KEY_LENGTH, DIGEST);
    return this.hash === hash.toString('hex');
}

PasswordSchema.methods.setPassword = function(hash: string, salt: string){
    this.hash = hash;
    this.salt = salt;
}