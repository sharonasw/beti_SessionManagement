import {users,SALT_ROUNDS} from './users_mock.js'

export const findUser = async (email) => {
  return users.find(user => user.email === email);
};  


