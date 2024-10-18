// Import necessary modules and define environment types
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
  KV: KVNamespace;
};

type Variables = {
  userId: string;
};

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

const DISCORD_API_URL = 'https://discord.com/api';
const DEBUG_MODE = false;
const DISCORD_REDIRECT_URI = DEBUG_MODE ? 'http://localhost:3000/auth/callback' : 'https://pet.pm/auth/callback';

// Helper function to log in debug mode
const debugLog = (message: string) => {
    console.log(`[DEBUG]: ${message}`);
};

// Enable CORS for all routes
app.use(
  '*',
  cors({
    origin: '*',
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowHeaders: ['Content-Type', 'Authorization'],
  })
);

// Middleware to verify JWT and set userId in context
app.use('/protected/*', async (c, next) => {
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    debugLog('Unauthorized access attempt without token.');
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const token = authHeader.substring(7); // Remove 'Bearer ' prefix

  try {
    const { payload } = await jwtVerify(token, new TextEncoder().encode(c.env.SECRET_KEY));
    if (!payload.userId) {
      throw new Error("Invalid payload: Missing userId.");
    }
    c.set('userId', payload.userId as string);
    debugLog(`Authenticated user: ${payload.userId}`);
    await next();
  } catch (err) {
    debugLog(`Invalid or expired token: ${err}`);
    return c.json({ error: 'Invalid or expired token' }, 401);
  }
});

// Step 1: Redirect to Discord for OAuth
app.get('/auth/sync', (c: Context) => {
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

    const hashedPassword = bcrypt.hashSync(password, 10);

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

// Middleware to ensure users can only access their own plugins
const authUserOnly = async (c: Context, next: Function) => {
  const authenticatedUserId = c.get('userId'); // ID from JWT
  const requestedUserId = c.get('userId');     // ID from route or payload

  if (authenticatedUserId !== requestedUserId) {
    debugLog(`User ID mismatch: ${authenticatedUserId} tried to access ${requestedUserId}'s resources.`);
    return c.json({ error: 'Access denied' }, 403);
  }

  await next();
};

// Add the new download plugin route
app.get('/protected/download-plugin', authUserOnly, async (c) => {
  try {
    const userId = c.get('userId');
    let fileName = c.req.query('fileName');

    if (!fileName) {
      return c.json({ error: 'Missing file name' }, 400);
    }

    if (fileName.startsWith(`plugins/${userId}/`)) {
      fileName = fileName.replace(`plugins/${userId}/`, '');
    }

    const objectKey = `plugins/${userId}/${fileName}`;

    let object;
    try {
      object = await c.env.PLUGIN_BUCKET.get(objectKey);
      debugLog(`Attempted to download plugin: ${objectKey}`);
      if (!object) {
        return c.json({ error: 'File not found' }, 404);
      }
    } catch (r2Error) {
      debugLog(`R2 error: ${r2Error}`);
      return c.json({ error: 'Failed to retrieve plugin from R2' }, 500);
    }

    return c.body(object.body, 200, {
      'Content-Type': 'application/javascript',
      'Content-Disposition': `attachment; filename="${fileName}"`,
    });
  } catch (error) {
    debugLog(`Unexpected error in /protected/download-plugin: ${error}`);
    return c.json({ error: 'Internal server error', details: error }, 500);
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
      return c.json({ error: 'Internal server error', details: dbError }, 500);
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

    const secret = new TextEncoder().encode(c.env.SECRET_KEY);
    const jwt = await new SignJWT({ userId })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .sign(secret);

    debugLog(`User logged in successfully: ${userId}`);

    return c.json({ message: 'Login successful', token: jwt });
  } catch (error) {
    debugLog(`Unexpected error in /login: ${error}`);
    return c.json({ error: 'Internal server error', details: error }, 500);
  }
});

// Protected route to get user info
app.get('/protected/user', authUserOnly, async (c) => {
  try {
    const userId = c.get('userId');

    let user;
    try {
      user = await c.env.DB.prepare('SELECT id, username, avatar FROM users WHERE id = ?')
        .bind(userId)
        .first();
    } catch (dbError) {
      debugLog(`Database error: ${dbError}`);
      return c.json({ error: 'Internal server error', details: dbError }, 500);
    }

    if (!user) {
      debugLog(`User info requested for non-existent user: ${userId}`);
      return c.json({ error: 'User not found' }, 404);
    }

    debugLog(`User info retrieved for user: ${userId}`);

    return c.json(user);
  } catch (error) {
    debugLog(`Unexpected error in /protected/user: ${error}`);
    return c.json({ error: 'Internal server error', details: error }, 500);
  }
});

// Protected route to get user's plugins (restricted to authenticated user)
app.get('/protected/plugins', authUserOnly, async (c) => {
  try {
    const userId = c.get('userId');

    debugLog(`Retrieving plugins for user: ${userId}`);

    let list;
    try {
      list = await c.env.PLUGIN_BUCKET.list({ prefix: `plugins/${userId}/` });
    } catch (r2Error) {
      debugLog(`R2 error: ${r2Error}`);
      return c.json({ error: 'Internal server error', details: r2Error }, 500);
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
    return c.json({ error: 'Internal server error', details: error }, 500);
  }
});

// Protected route to upload plugin (restricted to authenticated user)
app.post('/protected/upload-plugin', authUserOnly, async (c) => {
  try {
    const userId = c.get('userId');

    debugLog(`Upload plugin attempt by user: ${userId}`);

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

    if (!file.name.endsWith('.plugin.js')) {
      debugLog(`Upload failed: Invalid file extension for file ${file.name}.`);
      return c.json({ error: 'File must have a .plugin.js extension' }, 400);
    }

    const fileText = await file.text();
    if (!fileText.includes('module.exports')) {
      debugLog(`Upload failed: Invalid plugin file ${file.name}, missing module.exports.`);
      return c.json({ error: 'Invalid plugin file, must contain module.exports' }, 400);
    }

    const objectKey = `plugins/${userId}/${file.name}`;

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
    return c.json({ error: 'Internal server error', details: error }, 500);
  }
});

// Protected route to delete plugin (restricted to authenticated user)
app.delete('/protected/delete-plugin', authUserOnly, async (c) => {
  try {
    const userId = c.get('userId');
    const { fileName } = await c.req.json();

    if (!fileName) {
      return c.json({ error: 'Missing file name' }, 400);
    }

    debugLog(`Delete plugin attempt by user: ${userId}, file: ${fileName}`);

    const objectKey = `plugins/${userId}/${fileName}`;

    try {
      await c.env.PLUGIN_BUCKET.delete(objectKey);
    } catch (r2Error) {
      debugLog(`Failed to delete plugin from R2: ${r2Error}`);
      return c.json({ error: 'Failed to delete plugin' }, 500);
    }

    debugLog(`Plugin deleted successfully by user ${userId}: ${fileName}`);

    return c.json({ message: 'Plugin deleted successfully!' });
  } catch (error) {
    debugLog(`Unexpected error in /protected/delete-plugin: ${error}`);
    return c.json({ error: 'Internal server error', details: error }, 500);
  }
});

export default app;
