// src/index.ts

import { Hono } from 'hono';
import { Context } from 'hono';
import { cors } from 'hono/cors';
import bcrypt from 'bcryptjs';
import { jwtVerify, SignJWT } from 'jose';

type Env = {
  DB: D1Database;
  PLUGIN_BUCKET: R2Bucket;
  SECRET_KEY: string;
  DISCORD_CLIENT_SECRET: string;
  DISCORD_CLIENT_ID: string;
};

type Variables = {
  userId: string;
};

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

const DISCORD_API_URL = 'https://discord.com/api';

const DEBUG_MODE = true;
//debug mode ternary operator
const DISCORD_REDIRECT_URI = DEBUG_MODE ? 'http://localhost:3000/auth/callback' : 'https://pet.pm/auth/callback';


// Helper function to log in debug mode
const debugLog = (message: string) => {
  if (DEBUG_MODE) {
    console.log(`[DEBUG]: ${message}`);
  }
};

// Enable CORS for all routes
app.use(
  '*',
  cors({
    origin: '*', // In production, restrict this to your plugin's origin.
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowHeaders: ['Content-Type', 'Authorization'],
  })
);

// Middleware to verify JWT
app.use('/protected/*', async (c, next) => {
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    debugLog('Unauthorized access attempt without token.');
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const token = authHeader.substring(7); // Remove 'Bearer ' prefix

  try {
    const { payload } = await jwtVerify(token, new TextEncoder().encode(c.env.SECRET_KEY));
    c.set('userId', payload.userId as string);
    debugLog(`Authenticated user: ${payload.userId}`);
    await next();
  } catch (err) {
    debugLog(`Invalid or expired token: ${err}`);
    return c.json({ error: 'Invalid or expired token' }, 401);
  }
});

// Login route (POST /login)
app.post('/login', async (c) => {
  try {
    const { userId, password } = await c.req.json();

    if (!userId || !password) {
      debugLog('Login attempt with missing userId or password.');
      return c.json({ error: 'Missing userId or password' }, 400);
    }

    let user;
    try {
      user = await c.env.DB.prepare('SELECT password FROM users WHERE id = ?')
        .bind(userId)
        .first();
    } catch (dbError) {
      debugLog(`Database error: ${dbError}`);
      return c.json({ error: 'Internal server error' }, 500);
    }

    if (!user) {
      debugLog(`Login attempt for non-existent user: ${userId}`);
      return c.json({ error: 'User not found' }, 404);
    }

    const isValidPassword = bcrypt.compareSync(password, user.password as string);
    if (!isValidPassword) {
      debugLog(`Invalid password attempt for user: ${userId}`);
      return c.json({ error: 'Invalid password' }, 401);
    }

    // Generate JWT token
    const secret = new TextEncoder().encode(c.env.SECRET_KEY);
    const jwt = await new SignJWT({ userId })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      // .setExpirationTime('2h') // You can set an expiration if desired
      .sign(secret);

    debugLog(`User logged in successfully: ${userId}`);

    return c.json({ message: 'Login successful', token: jwt });
  } catch (error) {
    debugLog(`Unexpected error in /login: ${error}`);
    return c.json({ error: 'Internal server error' }, 500);
  }
});

// Protected route to get user info
app.get('/protected/user', async (c) => {
  try {
    const userId = c.get('userId');

    let user;
    try {
      user = await c.env.DB.prepare('SELECT id, username, avatar FROM users WHERE id = ?')
        .bind(userId)
        .first();
    } catch (dbError) {
      debugLog(`Database error: ${dbError}`);
      return c.json({ error: 'Internal server error' }, 500);
    }

    if (!user) {
      debugLog(`User info requested for non-existent user: ${userId}`);
      return c.json({ error: 'User not found' }, 404);
    }

    debugLog(`User info retrieved for user: ${userId}`);

    return c.json(user);
  } catch (error) {
    debugLog(`Unexpected error in /protected/user: ${error}`);
    return c.json({ error: 'Internal server error' }, 500);
  }
});

// Protected route to get user's plugins
app.get('/protected/plugins', async (c) => {
  try {
    const userId = c.get('userId');

    debugLog(`Retrieving plugins for user: ${userId}`);

    let list;
    try {
      list = await c.env.PLUGIN_BUCKET.list({ prefix: `plugins/${userId}/` });
    } catch (r2Error) {
      debugLog(`R2 error: ${r2Error}`);
      return c.json({ error: 'Internal server error' }, 500);
    }

    const plugins = list.objects.map((obj) => ({
      key: obj.key,
      size: obj.size,
      lastModified: obj.uploaded,
    }));

    debugLog(`Plugins retrieved for user: ${userId}`);

    return c.json({ plugins });
  } catch (error) {
    debugLog(`Unexpected error in /protected/plugins: ${error}`);
    return c.json({ error: 'Internal server error' }, 500);
  }
});

// Protected route to upload plugin
app.post('/protected/upload-plugin', async (c) => {
  try {
    const userId = c.get('userId');

    debugLog(`Upload plugin attempt by user: ${userId}`);

    // Ensure the content-type is correct for a file upload
    if (!c.req.header('content-type')?.startsWith('multipart/form-data')) {
      debugLog('Upload failed: Expected form-data.');
      return c.json({ error: 'Expected form-data' }, 400);
    }

    const form = await c.req.formData();
    const file = form.get('file') as File | null;

    if (!file) {
      debugLog('Upload failed: No file uploaded.');
      return c.json({ error: 'No file uploaded' }, 400);
    }

    // Validate the file extension
    if (!file.name.endsWith('.plugin.js')) {
      debugLog(`Upload failed: Invalid file extension for file ${file.name}.`);
      return c.json({ error: 'File must have a .plugin.js extension' }, 400);
    }

    // Validate the file contents (ensure it's a valid JavaScript file)
    const fileText = await file.text();
    if (!fileText.includes('module.exports')) {
      debugLog(`Upload failed: Invalid plugin file ${file.name}, missing module.exports.`);
      return c.json({ error: 'Invalid plugin file, must contain module.exports' }, 400);
    }

    // Define the R2 bucket object key using userId
    const objectKey = `plugins/${userId}/${file.name}`;

    // Store the file in the R2 bucket
    try {
      await c.env.PLUGIN_BUCKET.put(objectKey, file.stream(), {
        httpMetadata: {
          contentType: 'application/javascript',
        },
      });
    } catch (r2Error) {
      debugLog(`Failed to upload plugin to R2: ${r2Error}`);
      return c.json({ error: 'Failed to upload plugin' }, 500);
    }

    debugLog(`Plugin uploaded successfully by user ${userId}: ${file.name}`);

    return c.json({ message: 'Plugin uploaded successfully!' });
  } catch (error) {
    debugLog(`Unexpected error in /protected/upload-plugin: ${error}`);
    return c.json({ error: 'Internal server error' }, 500);
  }
});

// Step 1: Redirect to Discord for OAuth
app.get('/auth', (c: Context) => {
  const authorizationUrl = `${DISCORD_API_URL}/oauth2/authorize?client_id=${c.env.DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(
    DISCORD_REDIRECT_URI
  )}&response_type=code&scope=identify`;

  debugLog('Redirecting to Discord for OAuth.');

  return c.redirect(authorizationUrl);
});

// Step 2: OAuth callback (Exchange code for token)
app.get('/auth/callback', async (c: Context<{ Bindings: Env }>) => {
  try {
    const code = c.req.query('code');

    if (!code) {
      debugLog('OAuth callback failed: Missing authorization code.');
      return c.json({ error: 'Missing authorization code' }, 400);
    }

    debugLog('Exchanging code for token.');

    // Exchange the authorization code for an access token
    const tokenResponse = await fetch(`${DISCORD_API_URL}/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: c.env.DISCORD_CLIENT_ID,
        client_secret: c.env.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: DISCORD_REDIRECT_URI,
      }),
    });

    const tokenData: { access_token: string } = await tokenResponse.json();

    if (!tokenResponse.ok) {
      debugLog(`Failed to exchange code for token: ${JSON.stringify(tokenData)}`);
      return c.json({ error: 'Failed to exchange code for token', details: tokenData }, 400);
    }

    const accessToken = tokenData.access_token;

    // Step 3: Fetch the user's Discord info using the access token
    const userResponse = await fetch(`${DISCORD_API_URL}/users/@me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    const userData: { id: string; username: string; avatar: string } = await userResponse.json();

    if (!userResponse.ok) {
      debugLog(`Failed to fetch user info: ${JSON.stringify(userData)}`);
      return c.json({ error: 'Failed to fetch user info', details: userData }, 400);
    }

    const userId = userData.id;

    // Store the user's Discord info in the database
    try {
      await c.env.DB.prepare(
        'INSERT INTO users (id, username, avatar) VALUES (?, ?, ?) ON CONFLICT (id) DO UPDATE SET username = ?, avatar = ?'
      )
        .bind(userId, userData.username, userData.avatar, userData.username, userData.avatar)
        .run();
    } catch (dbError) {
      debugLog(`Database error during user insertion: ${dbError}`);
      return c.json({ error: 'Internal server error' }, 500);
    }

    // Debug logging
    debugLog(`OAuth flow completed. User ID: ${userId}, Username: ${userData.username}`);

    // Return an HTML page with a password form
    return c.html(`
      <html>
        <body>
          <h1>Set your Password</h1>
          <form method="POST" action="/auth/set-password">
            <input type="hidden" name="userId" value="${userId}">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
            <button type="submit">Set Password</button>
          </form>
        </body>
      </html>
    `);
  } catch (error) {
    debugLog(`Unexpected error in /auth/callback: ${error}`);
    return c.json({ error: 'Internal server error' }, 500);
  }
});

// Route for setting a user password
app.post('/auth/set-password', async (c: Context<{ Bindings: Env }>) => {
  try {
    const formData = await c.req.parseBody();
    const userId = formData.userId;
    const password = formData.password as string;

    if (!userId || !password) {
      debugLog('Set password failed: Missing userId or password.');
      return c.json({ error: 'Missing userId or password' }, 400);
    }

    // Hash the password with bcrypt
    const hashedPassword = bcrypt.hashSync(password, 10);

    // Store the hashed password in the database
    try {
      await c.env.DB.prepare('UPDATE users SET password = ? WHERE id = ?')
        .bind(hashedPassword, userId)
        .run();
    } catch (dbError) {
      debugLog(`Database error during password update: ${dbError}`);
      return c.json({ error: 'Internal server error' }, 500);
    }

    debugLog(`Password set for user ID: ${userId}`);

    return c.json({ message: 'Password set successfully' });
  } catch (error) {
    debugLog(`Unexpected error in /auth/set-password: ${error}`);
    return c.json({ error: 'Internal server error' }, 500);
  }
});

export default app;
