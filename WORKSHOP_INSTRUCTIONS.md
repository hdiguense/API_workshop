# API Workshop Instructions

Welcome to the API Workshop! This guide will walk you through learning basic CRUD operations with a REST API.

## Prerequisites
- The API server is running at `http://localhost:5000`
- You have been provided with an email address and API key
- You have a tool to make HTTP requests (curl, Postman, etc.)

## Workshop Overview
You will complete 4 tasks that teach you the four main HTTP methods:
1. **GET** - Retrieve data
2. **POST** - Create new data
3. **PUT** - Update existing data
4. **DELETE** - Remove data

Each task builds on the previous one, so complete them in order!

## Getting Started

### Step 1: Get Your Authentication Token
Before you can complete any tasks, you need to get an authentication token using your API key.

**Request:**
```bash
curl -X POST http://localhost:5000/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "YOUR_API_KEY_HERE"}'
```

**Expected Response:**
```json
{
  "status": 200,
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "expires_at": "2023-07-18T15:30:00Z",
  "message": "Token generated successfully"
}
```

⚠️ **Important:** Your token expires in 5 minutes! If it expires, just request a new one with the same API key.

---

## Task 1: GET Request - Retrieve Your Task ID

Use the token you received to get your unique task ID.

**Request:**
```bash
curl -X GET http://localhost:5000/api/task1 \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

**Expected Response:**
```json
{
  "status": 200,
  "task_id": "abcd1234efgh567",
  "email": "your@email.com",
  "next_endpoint": "/api/task2",
  "description": "Use POST request to save this task_id to the tasks table"
}
```

✅ **Success Criteria:** You receive a `task_id` and instructions for the next step.

---

## Task 2: POST Request - Save Your Task

Now use the `task_id` from Task 1 to create a new record in the tasks table.

**Request:**
```bash
curl -X POST http://localhost:5000/api/task2 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{"task_id": "TASK_ID_FROM_TASK_1"}'
```

**Expected Response:**
```json
{
  "status": 201,
  "task_record_id": 123,
  "message": "Task saved successfully",
  "next_endpoint": "/api/task3/123",
  "description": "Use PUT request to update this record by task_record_id"
}
```

✅ **Success Criteria:** You receive a `task_record_id` and instructions for the next step.

---

## Task 3: PUT Request - Update Your Record

Update the record you created in Task 2 by providing its `task_record_id`.

**Request:**
```bash
curl -X PUT http://localhost:5000/api/task3/TASK_RECORD_ID_FROM_TASK_2 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{"data": "My updated task data"}'
```

**Expected Response:**
```json
{
  "status": 200,
  "action_id": "act123456",
  "message": "Task updated successfully",
  "next_endpoint": "/api/task4",
  "description": "Use DELETE request with action_id to complete the workshop"
}
```

✅ **Success Criteria:** You receive an `action_id` and instructions for the final step.

---

## Task 4: DELETE Request - Complete the Workshop

Complete the workshop by deleting your task record using the `action_id` from Task 3.

**Request:**
```bash
curl -X DELETE http://localhost:5000/api/task4 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{"action_id": "ACTION_ID_FROM_TASK_3"}'
```

**Expected Response:**
```json
{
  "status": 200,
  "certification_id": "cert_abcd1234567890123456",
  "message": "Task completed successfully! You have finished the workshop."
}
```

🎉 **Congratulations!** You've successfully completed the API Workshop and learned the four main CRUD operations!

---

## Common Error Codes

| Error Code | Description | Solution |
|------------|-------------|----------|
| `TOKEN_MISSING` | No Authorization header provided | Add `Authorization: Bearer YOUR_TOKEN` header |
| `TOKEN_EXPIRED` | Your token has expired | Request a new token with your API key |
| `TOKEN_INVALID` | Token is malformed or invalid | Request a new token with your API key |
| `INVALID_API_KEY` | API key not found | Check your API key with the instructor |
| `TASK_ID_REQUIRED` | Missing required field | Include the required field in your request body |
| `TASK_NOT_FOUND` | Task doesn't exist or doesn't belong to you | Verify the ID and ensure you're using your own token |

---

## Additional Resources

- **Swagger Documentation:** http://localhost:5000/hidden/swagger
- **Home Page:** http://localhost:5000/ (shows basic info)

## Tips for Success

1. **Copy-paste carefully** - Small typos in IDs or tokens will cause errors
2. **Check your token expiration** - Tokens expire in 5 minutes
3. **Use the exact field names** - JSON is case-sensitive
4. **Complete tasks in order** - Each task depends on the previous one
5. **Read the error messages** - They'll help you fix issues quickly

Good luck! 🚀
