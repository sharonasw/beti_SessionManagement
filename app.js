import 'dotenv/config';
import {createClient} from 'redis';
import express from 'express';
import helmet from 'helmet';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { findUser } from './user-management/user.service.js';
import {logger} from './core.js';


const app = express();

app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const redisClient = createClient({
  host:process.env.REDIS_HOST,
  port:process.env.REDIS_PORT  
});
redisClient.connect().catch(logger.error)

const secretKey = process.env.JWT_SECRET;

const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, secretKey);
    req.user = decoded.userId; 
    next();
  } catch (error) {
    return res.status(403).json({ message: 'Invalid token' });
  }
};

const userActivityExpireMS = process.env.USER_ACTIVITY_EXPIRATION*1000;
const userBlockingMS = process.env.USER_BLOCKING*60*1000;
 

const blockUserCheck = async (req, res, next) => {    
  const userId = req.user;
  if (await isUserBlocked(userId)) {
    return res.status(403).json({ message: 'User is blocked' });
  }
  else
    return res.json({message:'unblocked activity'});
  
  next();
};

 
app.post('/api/login',async (req, res) => {
  try 
  {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    if (!/\S+@\S+\.\S+/.test(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }
   
    const user = await findUser(email);

    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    
    const isPasswordValid = bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    const token = jwt.sign( { userId: user.id } , secretKey, { expiresIn: '1h' });
    
    try {
      const hValue = {
        token: token, 
        lastActive: Date.now(), 
        blocked: 0, 
      };
    
    await redisClient.hSet(`user:${user.id}`, hValue);
    }
    catch(error)
    {
      logger.error('Error updating user:',error);
    }
    return res.json({ token });
  }
  catch (error) {
    logger.error(error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});



async function isUserBlocked(userId) {
  const userEntry = await redisClient.hGetAll(`user:${userId}`);
  if (!userEntry) {
    return false; 
  }
  const currentTime = Date.now();
  const lastActive = parseInt(userEntry.lastActive);
  let isBlocked = !!parseInt(userEntry.blocked);
  if(isBlocked)
  {
    if((currentTime - lastActive) > userBlockingMS)
      isBlocked = false;    
  }
  else
  {
    if((currentTime-lastActive)>userActivityExpireMS)
      isBlocked = true;
  }
  userEntry.lastActive = currentTime;
  userEntry.blocked = parseInt(isBlocked);
  await redisClient.hSet(`user:${userId}`, userEntry);  
  return isBlocked;
}

app.get('/api/activity', verifyToken ,async (req, res,next) => {
    await blockUserCheck(req, res, next);
});


const port = process.env.PORT || 3000;

app.listen(port, () => {
  logger.info(`Server listening on port ${port}`);
});