import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { google } from 'googleapis'

const app = new Hono()

// CORS middleware
app.use('*', cors({
  origin: [
    'https://youload.me',
    'http://localhost:5173',
    'http://localhost:3000'
  ],
  credentials: true,
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
}))

// Google OAuth2 client
const oauth2Client = new google.auth.OAuth2(
  process.env.CLIENT_ID || env.CLIENT_ID,
  process.env.CLIENT_SECRET || env.CLIENT_SECRET,
  process.env.REDIRECT_URI || env.REDIRECT_URI
)

const youtube = google.youtube({
  version: 'v3',
  auth: oauth2Client
})

// Helper function to generate token ID
function generateTokenId() {
  return Math.random().toString(36).substring(2) + Date.now().toString(36)
}

// Helper function to validate tokens
async function validateTokens(tokens) {
  try {
    oauth2Client.setCredentials(tokens)
    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client })
    await oauth2.userinfo.get()
    return true
  } catch (error) {
    return false
  }
}

// Auth routes
app.get('/auth/google', (c) => {
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: [
      'https://www.googleapis.com/auth/youtube.upload',
      'https://www.googleapis.com/auth/youtube',
      'https://www.googleapis.com/auth/userinfo.profile',
      'https://www.googleapis.com/auth/userinfo.email'
    ],
    include_granted_scopes: true,
    prompt: 'consent'
  })
  return c.redirect(url)
})

app.get('/auth/callback', async (c) => {
  const { code } = c.req.query()
  
  if (!code) {
    return c.redirect(`${env.FRONTEND_URL}/auth/error?message=No authorization code`)
  }
  
  try {
    const { tokens } = await oauth2Client.getToken(code)
    oauth2Client.setCredentials(tokens)
    
    // Get user info
    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client })
    const userInfo = await oauth2.userinfo.get()
    
    // Store tokens in KV
    const tokenId = generateTokenId()
    const tokenData = {
      ...tokens,
      user: userInfo.data
    }
    
    await env.AUTH_STORE.put(tokenId, JSON.stringify(tokenData), {
      expirationTtl: 60 * 60 * 24 * 30 // 30 days
    })
    
    // Redirect to frontend with token
    const frontendUrl = env.FRONTEND_URL || 'http://localhost:5173'
    return c.redirect(`${frontendUrl}/auth/success?token=${tokenId}`)
    
  } catch (error) {
    console.error('Auth error:', error)
    const frontendUrl = env.FRONTEND_URL || 'http://localhost:5173'
    return c.redirect(`${frontendUrl}/auth/error?message=Authentication failed`)
  }
})

// Auth success endpoint for frontend
app.get('/auth/success', async (c) => {
  const { token } = c.req.query()
  
  if (!token) {
    return c.json({ error: 'No token provided' }, 400)
  }
  
  try {
    const tokenData = await env.AUTH_STORE.get(token)
    if (!tokenData) {
      return c.json({ error: 'Invalid token' }, 401)
    }
    
    const parsedData = JSON.parse(tokenData)
    return c.json({
      success: true,
      token: token,
      user: parsedData.user
    })
    
  } catch (error) {
    console.error('Token validation error:', error)
    return c.json({ error: 'Token validation failed' }, 500)
  }
})

// Get current user info
app.get('/auth/me', async (c) => {
  const token = c.req.header('Authorization')?.replace('Bearer ', '')
  
  if (!token) {
    return c.json({ error: 'Unauthorized' }, 401)
  }

  try {
    const tokenData = await env.AUTH_STORE.get(token)
    if (!tokenData) {
      return c.json({ error: 'Invalid token' }, 401)
    }

    const parsedData = JSON.parse(tokenData)
    
    // Validate tokens are still valid
    const isValid = await validateTokens(parsedData)
    if (!isValid) {
      await env.AUTH_STORE.delete(token)
      return c.json({ error: 'Token expired' }, 401)
    }
    
    return c.json({ user: parsedData.user })
  } catch (error) {
    console.error('Get user error:', error)
    return c.json({ error: 'Failed to get user info' }, 500)
  }
})

// Upload endpoint
app.post('/upload', async (c) => {
  try {
    const body = await c.req.parseBody()
    const token = c.req.header('Authorization')?.replace('Bearer ', '')
    
    if (!token) {
      return c.json({ error: 'Unauthorized' }, 401)
    }

    // Get tokens from KV
    const tokenData = await env.AUTH_STORE.get(token)
    if (!tokenData) {
      return c.json({ error: 'Invalid token' }, 401)
    }

    const parsedData = JSON.parse(tokenData)
    oauth2Client.setCredentials(parsedData)

    const videoFile = body.video
    if (!videoFile || typeof videoFile === 'string') {
      return c.json({ error: 'No video file provided' }, 400)
    }

    // Validate file size (max 128MB for YouTube)
    if (videoFile.size > 128 * 1024 * 1024) {
      return c.json({ error: 'File size too large. Maximum size is 128MB.' }, 400)
    }

    // Prepare video metadata
    const videoMetadata = {
      snippet: {
        title: body.title || 'Untitled Video',
        description: body.description || '',
        tags: body.tags ? body.tags.split(',').map(tag => tag.trim()).slice(0, 10) : [],
        categoryId: '22' // People & Blogs
      },
      status: {
        privacyStatus: body.visibility || 'public',
        selfDeclaredMadeForKids: false
      }
    }

    // For Shorts, add relevant tags and description
    if (body.isShorts === 'true') {
      if (!videoMetadata.snippet.tags.includes('shorts')) {
        videoMetadata.snippet.tags.push('shorts')
      }
      if (!videoMetadata.snippet.description.includes('#shorts')) {
        videoMetadata.snippet.description += '\n\n#shorts'
      }
    }

    // Upload to YouTube
    const response = await youtube.videos.insert({
      part: 'snippet,status',
      requestBody: videoMetadata,
      media: {
        body: videoFile.stream(),
        mimeType: videoFile.type
      }
    })

    return c.json({
      success: true,
      videoId: response.data.id,
      videoUrl: `https://youtube.com/watch?v=${response.data.id}`,
      title: videoMetadata.snippet.title,
      message: 'Video uploaded successfully'
    })

  } catch (error) {
    console.error('Upload error:', error)
    
    // Handle specific YouTube API errors
    if (error.code === 403) {
      return c.json({ 
        error: 'YouTube quota exceeded. Please try again later.' 
      }, 429)
    } else if (error.code === 401) {
      return c.json({ 
        error: 'Authentication expired. Please login again.' 
      }, 401)
    }
    
    return c.json({ 
      error: 'Upload failed',
      details: error.message 
    }, 500)
  }
})

// Batch upload status endpoint
app.post('/upload/batch-status', async (c) => {
  const { videoIds } = await c.req.json()
  const token = c.req.header('Authorization')?.replace('Bearer ', '')
  
  if (!token) {
    return c.json({ error: 'Unauthorized' }, 401)
  }

  try {
    const tokenData = await env.AUTH_STORE.get(token)
    if (!tokenData) {
      return c.json({ error: 'Invalid token' }, 401)
    }

    // This would check the status of multiple video uploads
    // For now, return mock data
    const statusData = videoIds.map(id => ({
      id,
      status: 'completed',
      url: `https://youtube.com/watch?v=${id}`,
      title: `Video ${id}`
    }))

    return c.json({
      videos: statusData
    })
  } catch (error) {
    console.error('Batch status error:', error)
    return c.json({ error: 'Failed to get batch status' }, 500)
  }
})

// Health check endpoint
app.get('/health', (c) => {
  return c.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    service: 'YouLoad Backend'
  })
})

// 404 handler
app.notFound((c) => {
  return c.json({ error: 'Endpoint not found' }, 404)
})

// Error handler
app.onError((err, c) => {
  console.error('Server error:', err)
  return c.json({ error: 'Internal server error' }, 500)
})

export default app
