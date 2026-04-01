# User Authentication System

A Flask + SQLite authentication app built around the Task 2 requirements: signup, login, password hashing, session-based authentication, a protected dashboard, and logout.

## Features

- User Registration (Signup)
- User Login
- Password Hashing using `generate_password_hash` and `check_password_hash`
- Session-based Authentication
- Protected Dashboard Page
- Safe Logout Functionality

## Tech Stack

- Python 3
- Flask
- SQLite
- Werkzeug security helpers
- HTML, Jinja templates, and CSS

## Project Structure

```text
user_auth_app/
|-- app.py
|-- database.db
|-- requirements.txt
|-- static/
|   `-- style.css
`-- templates/
    |-- base.html
    |-- dashboard.html
    |-- login.html
    `-- register.html
```

## Setup

1. Create and activate a virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the app:

```bash
python app.py
```

4. Open:

```text
http://127.0.0.1:5000
```

## Main Routes

- `/register` - register a new user
- `/login` - login page
- `/dashboard` - main dashboard
- `/logout` - logout

## Database Table

### `users`

- `id`
- `name`
- `email`
- `password`
