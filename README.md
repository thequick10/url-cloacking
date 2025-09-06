# 🎯 URL Cloaking

<div align="center">

![Node.js Version](https://img.shields.io/badge/node-%3E%3D%2014.0.0-green.svg)
![Express Version](https://img.shields.io/badge/express-%5E4.18.2-lightgrey)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

A powerful and efficient URL resolution service that tracks campaign parameters, handles complex redirects, and validates marketing URLs.

[Key Features](#-key-features) •
[Installation](#%EF%B8%8F-installation) •
[API Endpoints Usage](#-api-endpoints-usage) •
[Deployment](#-deployment) •
[Dependencies](#dependencies) •
[Frontend Usage](#frontend-usage) •
[Sample JSON Response](#sample-response) •
[Import/Export Capabilities](#-importexport-capabilities) •
[User Management](#-user-management)

</div>

## Campaign link generator
- **Dashboard:** Access the dashboard at `https://your-campaign-url.com/` (replace with your actual campaign URL).
- **Add Campaigns:** Enter campaign URL, tags/notes, and select country, then click "Add Campaign".
- **Refresh URLs:** Refresh individual or all campaign URLs to get updated final resolved URLs.
- **Import/Export:** Import campaigns from CSV or XLSX files; export current campaigns to CSV.
- **Filtering and Sorting:** Search campaigns, filter by date range, and sort by newest, oldest, or import order.
- **Delete Campaigns:** Delete individual or all campaigns.
- **Edit Campaigns:** Edit campaign details, including URL, tags, and notes.
- **User Agent Selection:** Select user agent type (desktop or mobile) for each campaign.

## API Request Analytics
- Access the dashboard at `/analytics/stats.html`
- View campaign statistics, including date, total requests and bandwidth etc.
- Filter by date range & search requests by date.
- Export data to CSV.

## URL Resolution Stats
- Access the dashboard at `/resolution-stats/resolutions.html`
- View URL resolution statistics, including total requests, successful and failed requests, and bandwidth etc.
- Filter by date range & search requests by date.
- Export data to CSV.
- View the stats in a table format.
- View stats by regional performance 

## ⏱️ Timing Statistics Dashboard
- Access the dashboard at `/timing-stat/timing-stat.html`.
- View daily statistics for total time, average time per URL, and request counts.
- Filter by date range, sort results, and export timing data as CSV.
- The dashboard is fully responsive and mobile-friendly.

### Sample Response
```json
{
  "originalUrl": "https://your-campaign-url.com",
  "finalUrl": "https://final-destination.com?clickid=123&utm_source=campaign",
  "method": "browser-api",
  "hasClickId": true,
  "hasUtmSource": true,
  "hasClickRef": false
  //more paramenters
}
```

## 🚀 Key Features

- 🌐 **Browser Emulation**: Uses Puppeteer for JavaScript-heavy redirects
- 🌏 **Region Based URL Resolutions**: Region-based URL resolution with proxy support for multiple geographic zones
- 🖇 **Multiple Endpoint Support**: Single and multiple region URL resolution endpoints
- 📊 **Data Management**: Campaign management frontend with URL tracking, tagging, and status display
- 📥 **File Import/Export Support**: Import and export campaigns via CSV and XLSX file formats
- 📍 **Location Detection**: Auto-detection of user location and manual country selection
- 🔐 **Security**: Rate limiting, security headers, and basic authentication for enhanced security
- 📊 **API Usage Analytics**: Analytics page for usage tracking and monitoring
- 🔗 **URL Resolution Stats** URL Resolutions stat page to track failed and success url in respect of regions
- ✅ **Health Check Support**: System health and region listing API endpoints
- 👥 **User Management**: Admin interface to create, update (including password changes), and delete users with role-based access control

### 📁 Import/Export Capabilities
- 📥 **Import Support**:
  - CSV file import
  - XLSX file import
  - Drag & drop file support
  - Smart column detection
  - Batch processing
- 📤 **Export Options**:
  - Export to CSV
  - Complete campaign history
  - Formatted date and time

### 🌍 Location Detection
- 🔍 **Auto-Detection**: Automatic country detection
- 🔄 **Multiple Services**: Fallback to multiple geolocation services
- 🚥 **Status Indicators**: Visual feedback for detection process
- 🔄 **Manual Refresh**: Option to refresh location detection

### 🔍 Search & Filter
- 🔎 **Real-time Search**: Instant search across all fields
- 📅 **Date Range Filter**: 
  - Built-in date range picker
  - Clear filter option
  - Support for custom date formats
- 📊 **Sorting Options**:
  - Sort by newest/oldest
  - Persistent sorting preferences
  - Sort by File Import Order

### 🔄 URL Refresh Features
- 🔄 **Individual Refresh**: Refresh single URLs
- 📊 **Batch Refresh**: Refresh all URLs with progress tracking
- ⚠️ **Error Handling**: 
  - Automatic retry mechanism
  - Error status indicators
  - Restore previous URL on failure
- 📈 **Progress Tracking**: Visual progress indicators

## 🧑‍💻 User Agent Support
- **Desktop**: Emulates a desktop browser user agent.
- **Mobile**: Emulates a mobile browser user agent.
- **Random (Rotating)**: Randomly selects a desktop or mobile user agent for each request. This is the default option and helps simulate diverse real-world traffic.

You can select the user agent type from the frontend dropdown. The selected type is sent to the backend and used for all URL resolutions and analytics.

### 💫 Additional Features
- 📋 **Clipboard Support**: One-click URL copying
- ✏️ **Inline Editing**: Edit campaign URLs and tags directly
- 🗑️ **Data Management**: Delete individual or all campaigns
- 📱 **Responsive Design**: Works on desktop and mobile
- 🔔 **Notifications**: Beautiful toast notifications for all actions
- 🖥 **User Agent Selection**: Choose between Desktop, Mobile, or Random (rotating) user agents for each request. The Random option will select a new user agent for every request, simulating real-world browsing patterns.
- ⏱️ **Timing Statistics Dashboard**: Dedicated dashboard to track and analyze the time taken to resolve URLs, with filtering, sorting, and CSV export capabilities.

## 🛠️ Installation

1. **Clone the repository**
```bash
git clone https://github.com/thequick10/TraceToEnd.git
cd TraceToEnd
```

2. **Install dependencies**
```bash
npm install
```

3. **DotENV Config**
```.env
Configure your dotenv file in your local server and add all variable values in dotenv

For Instance:

BRIGHTDATA_API_KEY=<YOUR_BRIGHTDATA_API_KEY>
BRIGHTDATA_US_PROXY=brd-customer-<CUSTOMER_ID>-zone-<YOUR_ZONE_ID>-country-<COUNTRY>

Add all variables and their value just like above

Make sure you use 2-letter country code like for united states use only - US
```

5. **Start the server**
```bash
# Development mode
npm run dev

# Production mode
npm start
```

## 💻 API Endpoints Usage

The server provides comprehensive API endpoints for URL resolution, user management, analytics, and system monitoring. All endpoints require authentication except where noted.

### 🔗 URL Resolution Endpoints

#### Single URL Resolution
```http
GET /resolve?url=<URL>&region=<REGION_CODE>&uaType=<USER_AGENT_TYPE>
```

**Parameters:**
- `url` (required): The URL to resolve
- `region` (optional): Two-letter country code (default: "US")
- `uaType` (optional): "desktop", "mobile", or "random" (default: "random")

**Response:**
```json
{
  "originalUrl": "https://example.com",
  "finalUrl": "https://final-destination.com?utm_source=campaign",
  "region": "US",
  "requestedRegion": "US",
  "actualRegion": "US",
  "regionMatch": true,
  "method": "browser-api",
  "hasClickId": false,
  "hasClickRef": false,
  "hasUtmSource": true,
  "hasImRef": false,
  "hasMtkSource": false,
  "hasTduId": false,
  "hasPublisherId": false,
  "ipData": {
    "ip": "192.168.1.1",
    "country": "United States",
    "country_code": "US"
  },
  "uaType": "random"
}
```

#### Multiple Region URL Resolution
```http
GET /resolve-multiple?url=<URL>&regions=<REGION_LIST>&uaType=<USER_AGENT_TYPE>
```

**Parameters:**
- `url` (required): The URL to resolve
- `regions` (required): Comma-separated list of region codes (e.g., "us,ca,gb")
- `uaType` (optional): "desktop", "mobile", or "random" (default: "random")

**Response:**
```json
{
  "originalUrl": "https://example.com",
  "results": [
    {
      "region": "US",
      "finalUrl": "https://us-destination.com",
      "ipData": { "country_code": "US" }
    },
    {
      "region": "CA",
      "finalUrl": "https://ca-destination.com",
      "ipData": { "country_code": "CA" }
    }
  ]
}
```

### 📊 Analytics & Statistics Endpoints

#### BrightData API Usage Statistics
```http
GET /zone-usage?from=<YYYY-MM-DD>&to=<YYYY-MM-DD>
```

**Parameters:**
- `from` (required): Start date in YYYY-MM-DD format
- `to` (required): End date in YYYY-MM-DD format

**Response:**
```json
{
  "data": {
    "2024-01-01": {
      "requests": 150,
      "bandwidth": 2048000
    }
  },
  "summary": {
    "totalBandwidth": 2048000,
    "totalRequests": 150,
    "dateRange": {
      "from": "2024-01-01",
      "to": "2024-01-31"
    }
  }
}
```

#### Timing Statistics
```http
GET /time-stats?start=<YYYY-MM-DD>&end=<YYYY-MM-DD>
```

**Parameters:**
- `start` (optional): Start date filter
- `end` (optional): End date filter

**Response:**
```json
[
  {
    "date": "2024-01-01",
    "url": "https://example.com",
    "time": 2500
  }
]
```

#### Resolution Statistics
```http
GET /resolution-stats
```

**Response:**
```json
{
  "totalSuccess": 1250,
  "totalFailure": 45,
  "perRegion": {
    "US": { "success": 300, "failure": 10 },
    "CA": { "success": 250, "failure": 8 }
  },
  "failedUrls": [
    {
      "url": "https://example.com",
      "region": "US",
      "reason": "Timeout"
    }
  ]
}
```

### 🔐 Authentication Endpoints

#### User Login
```http
POST /login
```

**Body:**
```json
{
  "username": "user@example.com",
  "password": "password123"
}
```

#### User Registration
```http
POST /api/auth/register
```

**Body:**
```json
{
  "name": "John Doe",
  "username": "johndoe",
  "email": "john@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "id": 123,
  "approved": false,
  "message": "Registration submitted. Pending admin approval."
}
```

#### Get Current User
```http
GET /api/auth/me
```

**Response:**
```json
{
  "user": {
    "id": 123,
    "username": "johndoe",
    "role": "Subscriber",
    "name": "John Doe",
    "email": "john@example.com"
  }
}
```

#### Update User Profile
```http
PUT /api/auth/me
```

**Body:**
```json
{
  "name": "John Smith",
  "email": "johnsmith@example.com",
  "password": "newpassword123"
}
```

### 👥 User Management Endpoints (Admin Only)

#### List Users
```http
GET /api/users?q=<SEARCH>&page=<PAGE>&pageSize=<SIZE>
```

**Parameters:**
- `q` (optional): Search query for name, username, or email
- `page` (optional): Page number (default: 1)
- `pageSize` (optional): Items per page (default: 50)

**Response:**
```json
{
  "users": [
    {
      "id": 123,
      "name": "John Doe",
      "username": "johndoe",
      "email": "john@example.com",
      "role": "Subscriber",
      "approved": true,
      "created_at": "2024-01-01T00:00:00.000Z",
      "updated_at": "2024-01-15T00:00:00.000Z"
    }
  ],
  "total": 150
}
```

#### Create User
```http
POST /api/users
```

**Body:**
```json
{
  "name": "Jane Doe",
  "username": "janedoe",
  "email": "jane@example.com",
  "password": "password123",
  "role": "Subscriber",
  "approved": true
}
```

#### Update User
```http
PUT /api/users/:id
```

**Body:**
```json
{
  "name": "Jane Smith",
  "email": "janesmith@example.com",
  "role": "Admin",
  "password": "newpassword123",
  "approved": true
}
```

#### Delete User
```http
DELETE /api/users/:id
```

#### Approve User Registration
```http
POST /api/users/:id/approve
```

#### Reject User Registration
```http
POST /api/users/:id/reject
```

### 📋 Activity Logging Endpoints

#### List Activities
```http
GET /api/activities?page=<PAGE>&pageSize=<SIZE>&action=<ACTION>&username=<USERNAME>&from=<DATE>&to=<DATE>
```

**Parameters:**
- `page` (optional): Page number (default: 1)
- `pageSize` (optional): Items per page (default: 100)
- `action` (optional): Filter by action type
- `username` (optional): Filter by username
- `from` (optional): Start date filter
- `to` (optional): End date filter

#### Log Activity
```http
POST /api/activities
```

**Body:**
```json
{
  "action": "CUSTOM_ACTION",
  "details": "Additional details about the activity"
}
```

### 🖥️ System & Utility Endpoints

#### List Supported Regions
```http
GET /regions
```

**Response:**
```json
["US", "CA", "GB", "IN", "AU", "DE", "FR", "JP", "SG", "BR", "TW", "CZ", "UA", "AE", "PL", "ES", "ID", "ZA", "MX", "MY", "IT", "TH", "NL", "AR", "BY", "RU", "IE", "HK", "KZ", "NZ", "TR", "DK", "GR", "NO", "AT", "IS", "SE", "PT", "CH", "BE", "PH", "IL", "MD", "RO", "CL", "SA"]
```

#### System Health Check
```http
GET /system-info
```

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "uptime": "3600 seconds",
  "memory": {
    "rss": "150.25 MB",
    "heapTotal": "100.50 MB",
    "heapUsed": "80.75 MB",
    "external": "5.20 MB"
  },
  "loadAverage": {
    "1m": "1.25",
    "5m": "1.15",
    "15m": "1.05"
  },
  "memoryStats": {
    "total": "8192.00 MB",
    "free": "2048.00 MB"
  },
  "cpu": {
    "cores": 4,
    "model": "Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz"
  },
  "healthy": true
}
```

#### Get Client IP Address
```http
GET /ip
```

**Response:**
```json
{
  "ip": "192.168.1.100"
}
```

#### Puppeteer Connection Status
```http
GET /puppeteer-status
```

**Response:**
```json
{
  "status": "ok",
  "message": "Puppeteer connection is working."
}
```

### 🔒 Authentication & Security

- **Session-based Authentication**: All endpoints require valid user sessions
- **Role-based Access Control**: Admin endpoints require `Admin` role
- **Rate Limiting**: Configurable rate limiting (default: 100 requests per 5 minutes)
- **Security Headers**: Helmet.js provides comprehensive security headers
- **CORS Protection**: Configurable CORS with allowed origins
- **Password Security**: bcrypt hashing with salt rounds of 10
- **Activity Logging**: All user actions are logged for audit purposes

### 📊 Error Responses

All endpoints return standardized error responses:

```json
{
  "error": "Error message description",
  "details": "Additional error details (optional)"
}
```

**Common HTTP Status Codes:**
- `200`: Success
- `201`: Created
- `400`: Bad Request
- `401`: Unauthorized
- `403`: Forbidden
- `404`: Not Found
- `500`: Internal Server Error

## 🚀 Deployment

### Prerequisites
- Node.js >= 14.0.0
- NPM or Yarn
- 512MB RAM minimum

### Environment Variables
```env
PORT=8080  # Server port (optional)
```

### Deployment Platforms
- 🌐 Any Node.js compatible hosting

## Dependencies
Key npm packages used:

- express
- cors
- dotenv
- helmet
- express-basic-auth
- express-rate-limit
- puppeteer-core
- https
- os
- path
- url

## License and Author

Author: Rupesh Shah  
License: MIT (or specify your license)
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Puppeteer](https://pptr.dev/) for headless browser automation
- [Express.js](https://expressjs.com/) for the web framework
- [node-fetch](https://github.com/node-fetch/node-fetch) for HTTP requests

---