import User from './models/user.model.js';
import bcrypt from 'bcrypt';

export const SALT_ROUNDS = 10; 

export const users = [
  
    new User(
      1,
      'user1@example.com',
      await bcrypt.hash('password1', SALT_ROUNDS), 
    ),

    new User(
      2,
      'user2@example.com',
      await bcrypt.hash('password2', SALT_ROUNDS), 
    )
  ];
  
