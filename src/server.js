import express from 'express';
import cors from 'cors';
import { MongoClient } from 'mongodb';
import dotenv from 'dotenv';
import joi from 'joi';
import bcrypt from 'bcrypt';
import { v4 as uuid } from 'uuid';

dotenv.config();

/*
    {
        "name": "joão",
        "email": "joão@gg.com",
        "password": "1234",
        "confirmPassword": "1234"
    }
*/

const server = express();
const PORT = 5000;
const mongoClient = new MongoClient(process.env.DATABASE_URL);
let db;

try{
    await mongoClient.connect();
    db = mongoClient.db();
}
catch(error){
    console.log('Erro na conexão do servidor');
}

server.use(cors());
server.use(express.json());
server.listen(PORT);

/*server.get('/users', async(req, res) => {
    try{
        const gettingUsers = await db.collection('users').find().toArray();
        return res.send(gettingUsers);
    }
    catch(error){
        return res.status(500).send(error.message);
    }
});*/

server.post('/sign-in', async(req, res) => {
    const {email, password} = req.body;

    const schema = joi.object(
        {
            email: joi.string().email().required(),
            password: joi.string().required()
        }
    );

    const userData = {
        email: email,
        password: password
    };

    const validation = schema.validate(userData, {abortEarly: false});

    if (validation.error) {
        const errors = validation.error.details.map((detail) => detail.message);
        return res.status(422).send(errors);
    };

    try{
        const gettingUser = await db.collection('users').findOne({email: email});

        if(!gettingUser) return res.status(404).send('E-mail e/ou senha incorreto(s)');

        if(gettingUser && bcrypt.compareSync(password, gettingUser.password)){
            const token = uuid();
        
			await db.collection('sessions').insertOne(
                {
                    userId: gettingUser._id,
                    token: token
			    }
            )
            return res.status(200).send({token, name:gettingUser.name});
        }
        else{
            return res.status(404).send('E-mail e/ou senha incorreto(s)');
        }
    }
    catch(error){
        return res.status(500).send(error.message);
    }
});

server.post('/sign-up', async(req, res) => {
    const { name, email, password, confirmPassword } = req.body;

    const schema = joi.object(
        {
            name: joi.string().required(),
            email: joi.string().email().required(),
            password: joi.string().required(),
            confirmPassword: joi.string().valid(joi.ref('password')).required()
        }
    );

    const userData = {
        name: name,
        email: email,
        password: password,
        confirmPassword: confirmPassword
    };

    const validation = schema.validate(userData, {abortEarly: false});

    if (validation.error) {
        const errors = validation.error.details.map((detail) => detail.message);
        return res.status(422).send(errors);
    };

    try{
        const gettingUser = await db.collection('users').findOne({email: email});

        if(gettingUser) return res.status(409).send('E-mail já cadastrado');

        const passwordHash = bcrypt.hashSync(password, 10);

        await db.collection('users').insertOne(
            {
                name: name,
                email: email,
                password: passwordHash
            }
        );

        return res.sendStatus(201);
    }
    catch(error){
        return res.status(500).send(error.message);
    }
});