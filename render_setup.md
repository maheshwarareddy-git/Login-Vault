# 🌐 Deploying to Render

Since LoginVault requires a Node.js backend and a persistent JSON database, Render is the perfect place to host it.

## 1. Create a Render Account
Go to [Render.com](https://render.com/) and sign up with your GitHub account.

## 2. Create a New Web Service
1. Click **New +** and select **Web Service**.
2. Connect your GitHub repository (`LoginVault`).

## 3. Configure the Service
Set the following values:
- **Name**: `login-vault`
- **Region**: Select the one closest to you (e.g., Singapore or Oregon).
- **Branch**: `main`
- **Root Directory**: (Leave blank)
- **Runtime**: `Node`
- **Build Command**: `npm install`
- **Start Command**: `npm start`

## 4. Add Environment Variables
Click on the **Environment** tab and add the variables from your `.env` file:
- `JWT_SECRET`
- `FIREBASE_PROJECT_ID`
- `FIREBASE_CLIENT_EMAIL`
- `FIREBASE_PRIVATE_KEY` (Make sure to wrap this in double quotes)
- `EMAIL_USER`
- `EMAIL_PASS`
- `ADMIN_EMAIL`: `berserk41355@gmail.com`
- `ADMIN_PASS`: `Mahesh*3033`
- `PORT`: `3000`

## 5. Deploy!
Click **Create Web Service**. Render will now build and start your application.

> [!NOTE]
> Since we use a local `users.json` file, your data will reset if the server restarts. For a permanent database, you would eventually want to use a managed database like MongoDB or PostgreSQL.
