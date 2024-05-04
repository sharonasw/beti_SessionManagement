# Users Sessions Management System

This project implements a user authentication and activity management system using Node.js, Express, Redis, and JWT.

## Prerequisites

- Node.js installed on your machine
- Redis server running locally or remotely
- An environment file named `.env` containing the necessary configuration variables

## Installation

1. Clone this repository:

```
git clone https://github.com/yourusername/user-authentication.git
```

2. Navigate into the project directory:
```
cd user-authentication
```
3. Install dependencies:
```
npm install
```
4. Create a .env file in the root directory and configure the following variables:
```
REDIS_HOST=your_redis_host
REDIS_PORT=your_redis_port
JWT_SECRET=your_jwt_secret
USER_ACTIVITY_EXPIRATION=your_activity_expiration_time_in_seconds
USER_BLOCKING=your_user_blocking_time_in_minutes
```
## Features
- Secure user authentication using bcrypt for password hashing and JWT for token-based authentication
- User activity management with Redis to track user sessions and block users based on inactivity.

## Usage
1. Start the server:
```
npm start
```
2. Access the API endpoints:
- **POST /api/login**: Authenticates users and generates a JWT token for 
- Body:
```
{
  "email": "user@example.com",
  "password": "your_password"
}
```
Response:
 - Success (200 OK):
```
{
  "token": "your_generated_jwt_token"
}  
```
- Error (400 Bad Request):
```
    {
     "error": "Email and password are required""
    }
```
```
    {
      "message": "Invalid email format"
    }
```




- **GET /api/activity**: Retrieves user activity, requires a valid JWT token.
- Request:
   - Headers:
	Authorization: `Bearer your_generated_jwt_token`
- 	Response:
  - Success:
```
    {
  "message": "unblocked activity"
    }
```

  - Error (401 Unauthorized):
```
{
  "message": "Unauthorized"
}
```
  - Error (403 Forbidden):
```
{
  "message": "User is blocked"
}
```
  - Error (500 Internal Server Error):
  ```
  {
  "message": "Internal server error"
 }
  ```

.