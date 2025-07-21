# API Workshop - Flask CRUD API

This project is a simple, beginner-friendly API built with Flask, Flask-RESTX, and SQLite. It is designed for hands-on workshops to teach CRUD operations, authentication, and API best practices.

## Features
- **JWT Authentication**: Secure endpoints with short-lived tokens.
- **CRUD Workflow**: Four-step task workflow demonstrating GET, POST, PUT, DELETE.
- **Automatic Field Generation**: Unique API keys, task IDs, certification IDs, and action IDs.
- **Audit Logging**: All API calls are logged for traceability.
- **Swagger Documentation**: Interactive API docs at `/hidden/swagger/`.
- **Admin User Creation**: Hidden endpoint to add users.
- **Comprehensive Error Handling**: Consistent error responses for all endpoints.

## Endpoints

### 1. Welcome
- `GET /`
  - Returns a welcome message and instructions.

### 2. Swagger Docs
- `GET /hidden/swagger/`
  - Interactive API documentation.

### 3. Admin: Add User
- `POST /admin/add_user`
  - Headers: `X-Admin-Password: workshop_admin_pass`
  - Body: `{ "email": "user@example.com" }`
  - Returns API key for the new user.

### 4. Auth: Get Token
- `POST /api/auth/token`
  - Body: `{ "api_key": "<API_KEY>" }`
  - Returns JWT token (valid for 5 minutes).

### 5. Task 1: Get Task ID
- `GET /api/task1`
  - Header: `Authorization: Bearer <JWT_TOKEN>`
  - Returns generated task ID and next endpoint.

### 6. Task 2: Save Task
- `POST /api/task2`
  - Header: `Authorization: Bearer <JWT_TOKEN>`
  - Body: `{ "task_id": "<TASK_ID>" }`
  - Returns task record ID and next endpoint.

### 7. Task 3: Update Task
- `PUT /api/task3/<TASK_RECORD_ID>`
  - Header: `Authorization: Bearer <JWT_TOKEN>`
  - Body: `{ "data": "Updated task data" }`
  - Returns action ID and next endpoint.

### 8. Task 4: Delete Task
- `DELETE /api/task4`
  - Header: `Authorization: Bearer <JWT_TOKEN>`
  - Body: `{ "action_id": "<ACTION_ID>" }`
  - Returns certification ID and completion message.

## Models
- **User**: Stores email, API key, task/certification IDs.
- **Token**: Stores JWT tokens and expiry.
- **Task**: Stores task records and status.
- **AuditLog**: Stores logs of all API actions.

## Setup & Usage
1. Install dependencies:
   ```bash
   pip install flask flask-restx flask-sqlalchemy pyjwt
   ```
2. Run the app:
   ```bash
   python app.py
   ```
3. Use the provided `api_curl_examples.txt` for example requests.

## Security Notes
- This app is for educational/workshop use only. Do **not** use in production.
- The admin password and secret key are hardcoded for simplicity.

## Troubleshooting
- If you get 404 on `/`, ensure the route is registered **before** Flask-RESTX initialization in `app.py`.
- For any errors, check the audit logs in the database.

## License
MIT (for workshop/demo use)
