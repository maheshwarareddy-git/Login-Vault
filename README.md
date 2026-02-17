# 🔐 LoginVault - Enterprise Secure Login System

LoginVault is a robust, enterprise-scale authentication system built with Node.js and Express. It features advanced security measures, Firebase integration, and a sleek frontend.

## 🚀 Features

- **Multi-Factor Shield**: Integrated with Firebase Authentication for secure email/password management.
- **Advanced Security**: 
  - Progressive account lockout (3 failed attempts).
  - Brute force protection via rate limiting.
  - Helmet.js for secure HTTP headers.
  - JWT session management with `httpOnly` cookies.
  - Input sanitization and validation.
- **Admin Portal**: Dedicated administrative routes for user oversight and account management.
- **Email Service**: Automated notifications for account approvals and password resets using Nodemailer.
- **Modern UI**: Fully responsive frontend with dashboard, settings, and secure password reset flows.

## 🛠️ Tech Stack

- **Backend**: Node.js, Express.js
- **Auth**: Firebase Admin SDK, JWT, bcrypt
- **Database**: JSON-based persistent storage
- **Email**: Nodemailer
- **Frontend**: HTML5, CSS3 (Vanilla), JavaScript

## 📦 Installation

1. **Clone the repository**:
   ```bash
   git clone <your-repo-url>
   cd LoginValut
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Configure Environment Variables**:
   Create a `.env` file in the root directory and add the following:
   ```env
   PORT=3000
   JWT_SECRET=your_jwt_secret_key
   FIREBASE_PROJECT_ID=your_project_id
   FIREBASE_CLIENT_EMAIL=your_client_email
   FIREBASE_PRIVATE_KEY="your_private_key"
   EMAIL_USER=your_email@gmail.com
   EMAIL_PASS=your_app_password
   ```

4. **Run the application**:
   ```bash
   npm start
   ```
   Open [http://localhost:3000](http://localhost:3000) in your browser.

## 📂 Project Structure

- `backend/`: Server-side logic, routes, and middleware.
- `frontend/`: Client-side interface and assets.
- `data/`: Local storage for user and system data.
- `server.js`: Application entry point.

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.
