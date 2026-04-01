# Student Management System

A Flask + SQLite web application for managing students with secure authentication, user roles, and admin controls.

## Features

- User registration with password validation
- Account verification flow (`/verify`) before login
- Secure login/logout using hashed passwords
- Password reset by email match (`/reset`)
- Role-based access control (`admin` and `user`)
- Student CRUD:
  - Add student
  - View/search students
  - Edit student
  - Delete student
- Admin panel to manage users:
  - View/search users
  - Edit role/name/verification
  - Delete users (except currently logged-in admin)
- Dashboard with summary stats (users, verified users, admins, students)
- Profile page for updating logged-in user name

## Tech Stack

- Python 3
- Flask
- SQLite
- Werkzeug security helpers
- HTML templates + CSS

## Project Structure

```text
student_management_system/
├── app.py
├── database.db
├── static/
│   └── style.css
└── templates/
    ├── base.html
    ├── login.html
    ├── register.html
    ├── verify.html
    ├── dashboard.html
    ├── students.html
    ├── edit_student.html
    ├── admin.html
    ├── edit_user.html
    ├── profile.html
    └── reset_password.html
Setup and Run
Clone the repository:

git clone <your-repo-url>
cd student_management_system
Create and activate virtual environment:

Windows (PowerShell):

python -m venv venv
.\venv\Scripts\Activate.ps1
macOS/Linux:

python3 -m venv venv
source venv/bin/activate
Install dependencies:

pip install flask werkzeug
Run the app:

python app.py
Open in browser:

http://127.0.0.1:5000
Default Admin Account
The app auto-creates one admin account if no admin exists:

Email: admin@task3.local
Password: Admin123
After first login, update credentials/password for safety.

Main Routes
/register - Create new account
/verify - Verify account
/login - Login
/dashboard - App stats
/students - Student list + create/search
/students/edit/<id> - Edit student
/students/delete/<id> - Delete student
/profile - Update profile
/admin - User management (admin only)
/edit/<id> - Edit user (admin only)
/delete/<id> - Delete user (admin only)
/reset - Reset password
/logout - Logout
Database
SQLite file: database.db

Tables:

users
id, name, email, password, role, is_verified, created_at
students
id, full_name, roll_number, course, year_level, email, phone, created_by, created_at
### Author -- by Vishva ####
