import express from "express";
import puppeteer from "puppeteer-core";
import { config as dotenv } from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import cors from "cors";
import helmet, { referrerPolicy } from "helmet";
import rateLimit from "express-rate-limit";
import os from 'os';
import https from 'https';
import session from 'express-session';
import fs from 'fs/promises';
import MySQLStoreFactory from 'express-mysql-session';
import bcrypt from 'bcrypt';
import { getDbPool, ensureSchema } from './src/db.js';
import { createUser, findUserByUsernameOrEmail, getUserById, listUsers, updateUser, deleteUserById, countUsers } from './src/models/userModel.js';
import { logActivity, listActivitiesForUserOrAll } from './src/models/activityModel.js';

dotenv();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const PORT = process.env.PORT || 8080;

// Trust first proxy (required before session when using secure cookies behind a proxy)
app.set('trust proxy', 1);

// resolution stats
const resolutionStats = {
  success: 0,
  successUrls: [],
  failure: 0,
  perRegion: {},
  failedUrls: [], // ⬅️ new array to collect failed URLs
};

//Reset Resolution Stat data in every 24hours
function resetStats() {
resolutionStats.success = 0;
resolutionStats.failure = 0;
resolutionStats.perRegion = {};
resolutionStats.failedUrls = [];
console.log("📊 Resolution stats have been reset");
}
// Time of day to reset (24-hour format)
const RESET_HOUR = 0;  // 5:30 AM - IST
const RESET_MINUTE = 0;
const RESET_SECOND = 0;

// Calculate the delay until the next reset time
function getDelayUntilNextReset() {
  const now = new Date();
  const nextReset = new Date();
  nextReset.setHours(RESET_HOUR, RESET_MINUTE, RESET_SECOND, 0);
  if (nextReset <= now) {
    // If the time today has already passed, schedule for tomorrow
    nextReset.setDate(nextReset.getDate() + 1);
  }
  return nextReset - now;
}

setTimeout(() => {
  // Run once at the specified time
  resetStats();

  // Then schedule it to run every 24 hours
  setInterval(resetStats, 24 * 60 * 60 * 1000);

}, getDelayUntilNextReset());

// Initialize DB schema and session store
await ensureSchema();
const MySQLStore = MySQLStoreFactory(session);
const sessionStore = new MySQLStore({
  host: process.env.MYSQL_HOST,
  port: Number(process.env.MYSQL_PORT || 3306),
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DB,
  clearExpired: true,
  checkExpirationInterval: 15 * 60 * 1000,
  expiration: 24 * 60 * 60 * 1000
});

// Session middleware
const isProduction = process.env.NODE_ENV === 'production';

// Calculate maxAge for 8 hours in IST
const now = new Date();
const istOffset = 5.5 * 60 * 60 * 1000; // IST is UTC+5:30
const nowIST = new Date(now.getTime() + istOffset);
const expirationIST = new Date(nowIST.getTime() + 8 * 60 * 60 * 1000);
const maxAgeIST = expirationIST.getTime() - now.getTime();

// Session middleware
app.use(session({
  secret: process.env.SECRET_SESSION_KEY,
  resave: false,
  saveUninitialized: false,
  store: sessionStore,
  cookie: {
    maxAge: maxAgeIST,
    httpOnly: true,
    sameSite: 'lax',
    secure: 'auto', 
  }
}));

// Helpers: auth guards
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  if (req.accepts('html')) return res.redirect('/login');
  return res.status(401).json({ error: 'Unauthorized' });
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.session?.user) {
      return req.accepts('html') ? res.redirect('/login') : res.status(401).json({ error: 'Unauthorized' });
    }
    if (!roles.includes(req.session.user.role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

// Public paths (no auth needed)
const publicPaths = new Set([
  '/login',
  '/signup',
  '/auth/error.html',
  '/auth/login.html',
  '/auth/register.html',
  '/api/auth/me',
  '/api/auth/register',
  '/favicon.ico'
]);

// Allow bodies
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Route protection before static: allow static assets via extension
app.use((req, res, next) => {
  if (publicPaths.has(req.path)) return next();
  if (req.path.startsWith('/components/')) return next();
  if (/\.(css|js|png|jpg|jpeg|gif|svg|ico|json|map)$/.test(req.path)) return next();
  if (!req.session?.user) {
    return req.accepts('html') ? res.redirect('/login') : res.status(401).json({ error: 'Unauthorized' });
  }
  // Non-admins: restrict HTML pages to index.html and dashboard.html only
  if (req.method === 'GET' && req.path.endsWith('.html')) {
    const isAdmin = req.session.user.role === 'Admin';
    const allowedForAll = new Set(['/index.html', '/dashboard.html', '/my-account/my-account.html']);
    if (!isAdmin && !allowedForAll.has(req.path)) {
      return res.redirect('/login');
    }
  }
  next();
});

// Serve static frontend
app.use(express.static(path.join(__dirname, "public")));

// Auth pages
app.get('/login', (req, res) => {
  if (req.session?.user) return res.redirect('/index.html');
  res.sendFile(path.join(__dirname, 'public', 'auth', 'login.html'));
});

app.get('/signup', (req, res) => {
  if (req.session?.user) return res.redirect('/index.html');
  res.sendFile(path.join(__dirname, 'public', 'auth', 'register.html'));
});

// Enhanced middleware stack
app.use(helmet({
  contentSecurityPolicy: false, // Enable and customize as needed
  referrerPolicy : {
    policy: "no-referrer",
  },
})); // Security headers

// Enable CORS
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
  : null;

if (!allowedOrigins) {
  console.error('[CORS] ERROR: ALLOWED_ORIGINS environment variable is not set.');
  process.exit(1); // Or handle it another way, like disabling CORS
}
console.log('[CORS] Allowed origins:', allowedOrigins);

app.use(cors({
  origin: '*',
  credentials: false
}));

// Serve static frontend
app.use(express.static(path.join(__dirname, "public")));

// Rate limiting
const limiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: process.env.RATE_LIMIT || 100, // limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});
if (process.env.ENABLE_RATE_LIMIT !== 'false') {
  console.log('[Rate Limiting] ENABLED');
  app.use('/resolve', limiter);
} else {
  console.log('[Rate Limiting] DISABLED');
}

// BRIGHTDATA_API_USAGE_CONFIG
const API_KEY = process.env.BRIGHTDATA_API_KEY;
const ZONE = process.env.BRIGHTDATA_ZONE;

// Region to proxy zone mapping
const regionZoneMap = {
  US: process.env.BRIGHTDATA_US_PROXY,
  CA: process.env.BRIGHTDATA_CA_PROXY,
  GB: process.env.BRIGHTDATA_GB_PROXY,
  IN: process.env.BRIGHTDATA_IN_PROXY,
  AU: process.env.BRIGHTDATA_AU_PROXY,
  DE: process.env.BRIGHTDATA_DE_PROXY,
  FR: process.env.BRIGHTDATA_FR_PROXY,
  JP: process.env.BRIGHTDATA_JP_PROXY,
  SG: process.env.BRIGHTDATA_SG_PROXY,
  BR: process.env.BRIGHTDATA_BR_PROXY,
  TW: process.env.BRIGHTDATA_TW_PROXY,
  CZ: process.env.BRIGHTDATA_CZ_PROXY,
  UA: process.env.BRIGHTDATA_UA_PROXY,
  AE: process.env.BRIGHTDATA_AE_PROXY,
  PL: process.env.BRIGHTDATA_PL_PROXY,
  ES: process.env.BRIGHTDATA_ES_PROXY,
  ID: process.env.BRIGHTDATA_ID_PROXY,
  ZA: process.env.BRIGHTDATA_ZA_PROXY,
  MX: process.env.BRIGHTDATA_MX_PROXY,
  MY: process.env.BRIGHTDATA_MY_PROXY,
  IT: process.env.BRIGHTDATA_IT_PROXY,
  TH: process.env.BRIGHTDATA_TH_PROXY,
  NL: process.env.BRIGHTDATA_NL_PROXY,
  AR: process.env.BRIGHTDATA_AR_PROXY,
  BY: process.env.BRIGHTDATA_BY_PROXY,
  RU: process.env.BRIGHTDATA_RU_PROXY,
  IE: process.env.BRIGHTDATA_IE_PROXY,
  HK: process.env.BRIGHTDATA_HK_PROXY,
  KZ: process.env.BRIGHTDATA_KZ_PROXY,
  NZ: process.env.BRIGHTDATA_NZ_PROXY,
  TR: process.env.BRIGHTDATA_TR_PROXY,
  DK: process.env.BRIGHTDATA_DK_PROXY,
  GR: process.env.BRIGHTDATA_GR_PROXY,
  NO: process.env.BRIGHTDATA_NO_PROXY,
  AT: process.env.BRIGHTDATA_AT_PROXY,
  IS: process.env.BRIGHTDATA_IS_PROXY,
  SE: process.env.BRIGHTDATA_SE_PROXY,
  PT: process.env.BRIGHTDATA_PT_PROXY,
  CH: process.env.BRIGHTDATA_CH_PROXY,
  BE: process.env.BRIGHTDATA_BE_PROXY,
  PH: process.env.BRIGHTDATA_PH_PROXY,
  IL: process.env.BRIGHTDATA_IL_PROXY,
  MD: process.env.BRIGHTDATA_MD_PROXY,
  RO: process.env.BRIGHTDATA_RO_PROXY,
  CL: process.env.BRIGHTDATA_CL_PROXY,
  SA: process.env.BRIGHTDATA_SA_PROXY,
  FL: process.env.BRIGHTDATA_FL_PROXY
};

//Make sure all proxy values exist at runtime or fail fast on startup.
Object.entries(regionZoneMap).forEach(([region, zone]) => {
    if (!zone) {
      console.warn(`⚠️ Missing proxy config for region: ${region}`);
    }
});

//Load regions
console.log("Loaded all available proxy regions:", Object.keys(regionZoneMap).filter(r => regionZoneMap[r]));

// Helper to get browser WebSocket endpoint
function getBrowserWss(regionCode) {
  const zone = regionZoneMap[regionCode?.toUpperCase()];
  const password = process.env.BRIGHTDATA_PASSWORD;

  if (!zone || !password) {
    throw new Error(`Missing proxy configuration for region: ${regionCode}`);
  }

  return `wss://${zone}:${password}@brd.superproxy.io:9222`;
}

// Random User-Agents
const userAgents = {
  desktop: [
    // Existing ones
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:139.0) Gecko/20100101 Firefox/139.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.2592.61",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",

    // 🔼 New additions
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
  ],
  mobile: [
    // Existing ones
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S926B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/123.0 Mobile/15E148 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; moto g power (2023)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",

    // 🔼 New additions
    "Mozilla/5.0 (Linux; Android 15; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/24.0 Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/126.0 Mobile/15E148 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14; OnePlus 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36"
  ]
};

// Helper: Randomly pick desktop or mobile UA and related settings
function getRandomUserAgent(type) {
  let uaType = type;
  if (!uaType || uaType === 'random' || (uaType !== 'desktop' && uaType !== 'mobile')) {
    uaType = Math.random() < 0.5 ? 'desktop' : 'mobile';
  }
  const uaList = userAgents[uaType];
  const userAgent = uaList[Math.floor(Math.random() * uaList.length)];
  return { userAgent, isMobile: uaType === 'mobile', uaType };
}

// Main Puppeteer logic
async function resolveWithBrowserAPI(inputUrl, region = "US", uaType) {
  const browserWSEndpoint = getBrowserWss(region);
  const browser = await puppeteer.connect({ browserWSEndpoint });

  try {
    const page = await browser.newPage();
    
    // ⬇️ Block unnecessary resources to speed things up
    await page.setRequestInterception(true);
    page.on('request', (req) => {
      const blockedResources = ["image", "stylesheet", "font", "media", "other"];
      if (blockedResources.includes(req.resourceType())) {
        req.abort();
      } else {
        req.continue();
      }
    });

    // ✅ Set custom User-Agent before navigating
    const { userAgent, isMobile } = getRandomUserAgent(uaType);
    console.log(`[INFO] Using ${isMobile ? 'Mobile' : 'Desktop'} User-Agent:\n${userAgent}`);
    await page.setUserAgent(userAgent);

    // Set realistic viewport based on UA type
    if (isMobile) {
      await page.setViewport({
        width: 375 + Math.floor(Math.random() * 20) - 10,
        height: 812 + Math.floor(Math.random() * 20) - 10,
        isMobile: true,
        hasTouch: true,
        deviceScaleFactor: 2,
      });
    } else {
      await page.setViewport({
        width: 1366 + Math.floor(Math.random() * 20) - 10,
        height: 768 + Math.floor(Math.random() * 20) - 10,
        isMobile: false,
      });
    }

    page.setDefaultNavigationTimeout(20000);

    // Determine navigation timeout (use env variable or fallback to 60 seconds)
    const envTimeout = Number(process.env.NAVIGATION_TIMEOUT);
    const timeout = isNaN(envTimeout) ? 60000 : envTimeout;

    if (!isNaN(envTimeout)) {
        console.log(`[INFO] Using navigation timeout: ${timeout} ms`);
    } else {
        console.log("[INFO] Using default timeout of 60000 ms");
    }

    // Validate the input URL
    if (!inputUrl || typeof inputUrl !== 'string' || !inputUrl.startsWith('http')) {
        console.error('[ERROR] Invalid or missing input URL:', inputUrl);
        process.exit(1);
    }

    // Attempt to navigate to the URL with the specified timeout and handle errors gracefully
    try {
      await page.goto(inputUrl, { waitUntil: "domcontentloaded", timeout: timeout });
    } catch (err) {
      console.error(`[ERROR] Failed to navigate to ${inputUrl}:`, err.message);
    }

    // Optional wait
    await page.waitForSelector("body", {timeout: 120000});

    // Get resolved final URL
    const finalUrl = page.url();

    // Detect IP info from inside the browser
    const ipData = await page.evaluate(async () => {
      try {
        const res = await fetch("https://get.geojs.io/v1/ip/geo.json");
        return await res.json(); // { ip, country_name, region, city, etc. }
      } catch (e) {
        return { error: "IP lookup failed" };
      }
    });
    return { finalUrl, ipData };
  } catch(err){
    console.log(`[ERROR] ${err.message}`);
    return {error: err.message};
  } finally {
    await browser.disconnect();
  }
}

// Timing stats
const TIMING_STATS_FILE = path.join(__dirname, 'public', 'time-stats', 'time-stats.json');

async function appendTimingStat(stat) {
  let stats = [];
  try {
    const data = await fs.readFile(TIMING_STATS_FILE, 'utf-8');
    stats = JSON.parse(data);
  } catch (e) {
    // File may not exist yet
    stats = [];
  }
  stats.push(stat);
  // Keep only last 31 days
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - 31);
  stats = stats.filter(s => new Date(s.date) >= cutoff);
  await fs.writeFile(TIMING_STATS_FILE, JSON.stringify(stats, null, 2));
}

app.get('/time-stats', async (req, res) => {
  try {
    let stats = [];
    try {
      const data = await fs.readFile(TIMING_STATS_FILE, 'utf-8');
      stats = JSON.parse(data);
    } catch (e) {
      stats = [];
    }
    // Optional: filter by date range
    const { start, end } = req.query;
    if (start || end) {
      stats = stats.filter(row => {
        return (!start || row.date >= start) && (!end || row.date <= end);
      });
    }
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load timing stats', details: err.message });
  }
});

// API route: /resolve?url=https://domain.com&region=ua - /resolve?url=https://domain.com&region=ua&uaType=desktop|mobile
app.get("/resolve", requireAuth, async (req, res) => {
  const { url: inputUrl, region = "US", uaType } = req.query;

  if (!inputUrl) {
    return res.status(400).json({ error: "Missing URL parameter" });
  }

  try {
    new URL(inputUrl);
  } catch {
    return res.status(400).json({ error: "Invalid URL format" });
  }

  console.log(`⌛ Requested new URL: ${inputUrl}`);
  // console.log(`🌐 Resolving URL for region [${region}]:`, inputUrl);
  console.log(`🌐 Resolving URL for region [${region}] with uaType [${uaType}]:`, inputUrl);

  try {
    const startTime = Date.now();
    const result = await resolveWithBrowserAPI(inputUrl, region, uaType);
    const endTime = Date.now();
    const timeTaken = endTime - startTime;

    // Check if there was an error in the browser API
    if (result.error) {
      resolutionStats.failure++;
      resolutionStats.failedUrls.push({ url: inputUrl, region, reason: result.error });
      resolutionStats.perRegion[region] = resolutionStats.perRegion[region] || { success: 0, failure: 0 };
      resolutionStats.perRegion[region].failure++;
      
      return res.status(500).json({ 
        error: "❌ Resolution failed", 
        details: result.error,
        originalUrl: inputUrl,
        region,
        uaType
      });
    }

    const { finalUrl, ipData } = result;

    if (finalUrl && finalUrl.trim() !== "") {
      resolutionStats.success++;
      resolutionStats.perRegion[region] = resolutionStats.perRegion[region] || { success: 0, failure: 0 };
      resolutionStats.perRegion[region].success++;
    } else {
      resolutionStats.failure++;
      resolutionStats.failedUrls.push({ url: inputUrl, region, reason: "Final URL not resolved" });
      resolutionStats.perRegion[region] = resolutionStats.perRegion[region] || { success: 0, failure: 0 };
      resolutionStats.perRegion[region].failure++;
      
      // Return error response when finalUrl is not available
      return res.status(500).json({ 
        error: "❌ Resolution failed", 
        details: "Final URL could not be resolved",
        originalUrl: inputUrl,
        region,
        uaType
      });
    }

    // Save timing stat (date, url, time) in IST with YYYY-MM-DD format
    const today = new Date().toLocaleDateString('en-IN', { timeZone: 'Asia/Kolkata' });
    // await appendTimingStat({ date: today, url: inputUrl, time: timeTaken });
    try {
      await appendTimingStat({ date: today, url: inputUrl, time: timeTaken });
    } catch (e) {
      console.warn('[Timing Stat] Failed to append timing stat:', e.message);
    }
    
    console.log(`URL Resolution Completed For: ${inputUrl}`);
    console.log(`→ Original URL: ${inputUrl}`);
    
    if(finalUrl){
      console.log(`→ Final URL   : ${finalUrl}`);
    } else {
      console.log(`⚠️ Final URL could not be resolved.`);
    }

    console.log(`→ URLs Resolved with [${region}] Check IP Data ⤵`);
    if (ipData?.ip) {
        console.log(`🌍 IP Info : ${ipData.ip} (${ipData.country || "Unknown Country"} - ${ipData.region || "Unknown Region"} - ${ipData.country_code || "Unknown country_code"})`);
        console.log(`🔍 Region Match: ${ipData.country_code?.toUpperCase() === region.toUpperCase() ? '✅ REGION MATCHED' : '❌ REGION MISMATCH'}`);
    }

    const hasClickId = finalUrl ? finalUrl.includes("clickid=") || finalUrl.includes("clickId=") : false;

    const responsePayload = {
      originalUrl: inputUrl,
      finalUrl,
      region,
      requestedRegion: region,
      actualRegion: ipData?.country_code?.toUpperCase() || 'Unknown',
      regionMatch: ipData?.country_code?.toUpperCase() === region.toUpperCase(),
      method: "browser-api",
      hasClickId,
      hasClickRef: finalUrl?.includes("clickref="),
      hasUtmSource: finalUrl?.includes("utm_source="),
      hasImRef: finalUrl?.includes("im_ref="),
      hasMtkSource: finalUrl?.includes("mkt_source="),
      hasTduId: finalUrl?.includes("tduid="),
      hasPublisherId: finalUrl?.includes("publisherId="),
      ipData, // Region detection info
      uaType
    };

    const single_url_loaded = `URL Loaded ${inputUrl}`;
    try { await logActivity(req.session.user.id, 'RESOLVE_URL', `${single_url_loaded}`); } catch {}
    
    return res.json(responsePayload);
  } catch (err) {
    try { await logActivity(req.session.user.id, 'FAILED', `URL Resolution Failed ${inputUrl}`); } catch {}
    resolutionStats.failure++;
    resolutionStats.failedUrls.push({ url: inputUrl, region, reason: err.message });
    resolutionStats.perRegion[region] = resolutionStats.perRegion[region] || { success: 0, failure: 0 };
    resolutionStats.perRegion[region].failure++;

    console.error(`❌ Resolution failed:`, err.stack || err.message);
    return res.status(500).json({ error: "❌ Resolution failed", details: err.message });
  }
});

//Allow users to request resolution across multiple regions at once, getting all the resolved URLs at the same time.
// Endpoint to access this - /resolve-multiple?url=https://domain.com&regions=us,ca,ae - https://domain.com&regions=us,ca,ae&uaType=desktop|mobile
app.get('/resolve-multiple', requireAuth, async (req, res) => {
  const { url: inputUrl, regions, uaType } = req.query;

  if (!inputUrl || !regions) {
    return res.status(400).json({ error: "Missing parameters" });
  }

  const regionList = regions.split(',');
  const promises = regionList.map(region => resolveWithBrowserAPI(inputUrl, region, uaType));
  const results = await Promise.all(promises);

  results.forEach((result, i) => {
    const region = regionList[i];
    resolutionStats.perRegion[region] = resolutionStats.perRegion[region] || { success: 0, failure: 0 };

    if (result.finalUrl) {
      resolutionStats.success++;
      resolutionStats.perRegion[region].success++;
    } else {
      resolutionStats.failure++;
        resolutionStats.failedUrls.push({
        url: inputUrl,
        region,
        reason: result.error || "Final URL not resolved"
      });
      resolutionStats.perRegion[region].failure++;
    }
  });

  try { await logActivity(req.session.user.id, 'RESOLVE_MULTIPLE', { inputUrl, regions: regionList }); } catch {}
  res.json({
    originalUrl: inputUrl,
    results: results.map((result, index) => ({
      region: regionList[index],
      finalUrl: result.finalUrl,
      ipData: result.ipData,
    })),
  });
});

// Enhanced BrightData API Usage Endpoint with Bandwidth Features /zone-usage - /zone-usage?from=YYYY-MM-DD&to=YYYY-MM-DD
app.get('/zone-usage', (req, res) => {
  const { from, to } = req.query;

  if (!from || !to) {
    return res.status(400).json({
      error: 'Please provide both "from" and "to" query parameters in YYYY-MM-DD format.',
    });
  }

  const options = {
    hostname: 'api.brightdata.com',
    path: `/zone/bw?zone=${ZONE}&from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`,
    method: 'GET',
    headers: {
      Authorization: `Bearer ${API_KEY}`,
      Accept: 'application/json',
    },
    rejectUnauthorized: false, // ignore SSL certificate issues
  };

  const apiReq = https.request(options, (apiRes) => {
    let data = '';

    apiRes.on('data', (chunk) => {
      data += chunk;
    });

    apiRes.on('end', () => {
      try {
        const json = JSON.parse(data);
        console.log('Raw API response:', json);

        const result = {};
        
        // Access the zone data (keeping original structure)
        const zoneData = json.c_a4a3b5b0.data?.[ZONE];
        const { reqs_browser_api, bw_browser_api, bw_sum } = zoneData || {};

        console.log('Zone data:', zoneData);

        if (reqs_browser_api && bw_browser_api) {
          // Create a list of dates between 'from' and 'to'
          const dates = getDatesBetween(from, to);

          // Match dates to request and bandwidth data
          dates.forEach((date, index) => {
            result[date] = {
              requests: reqs_browser_api[index] || 0,
              bandwidth: bw_browser_api[index] || 0 // in bytes
            };
          });
        }

        // Add summary statistics
        const summary = {
          totalBandwidth: bw_sum ? (bw_sum[0] || 0) : 0, // Total bandwidth in bytes
          totalRequests: reqs_browser_api ? reqs_browser_api.reduce((sum, val) => sum + val, 0) : 0,
          dateRange: {
            from: from,
            to: to
          }
        };
        const fetched_text = "Successfully Fetched";
        try { logActivity(req.session.user.id, 'BRIGHTDATA_SUMMARY_FETCHED', `${fetched_text}`); } catch {}
        res.json({ 
          data: result,
          summary: summary
        });
        
      } catch (e) {
        console.error('Error parsing response:', e);
        res.status(500).json({
          error: 'Failed to parse Bright Data API response.',
          details: e.message,
        });
      }
    });
  });

  apiReq.on('error', (e) => {
    console.error('Request error:', e.message);
    res.status(500).json({
      error: 'Request to Bright Data API failed.',
      details: e.message,
    });
  });

  apiReq.end();
});

// Helper function to get all dates between 'from' and 'to' (unchanged)
function getDatesBetween(startDate, endDate) {
  const dates = [];
  const currentDate = new Date(startDate);
  const end = new Date(endDate);

  while (currentDate <= end) {
    dates.push(currentDate.toISOString().split('T')[0]);
    currentDate.setDate(currentDate.getDate() + 1);
  }

  return dates;
}

// Regions check
app.get("/regions", (req, res) => {
  res.json(Object.keys(regionZoneMap));
});

app.get("/system-info", (req, res) => {
  const memoryUsage = process.memoryUsage();
  const uptime = process.uptime();
  const loadAverage = os.loadavg();
  const totalMemory = os.totalmem();
  const freeMemory = os.freemem();

  const healthCheck = {
    status: "ok",
    timestamp: new Date().toISOString(),
    uptime: `${Math.floor(uptime)} seconds`,
    memory: {
      rss: `${(memoryUsage.rss / 1024 / 1024).toFixed(2)} MB`,
      heapTotal: `${(memoryUsage.heapTotal / 1024 / 1024).toFixed(2)} MB`,
      heapUsed: `${(memoryUsage.heapUsed / 1024 / 1024).toFixed(2)} MB`,
      external: `${(memoryUsage.external / 1024 / 1024).toFixed(2)} MB`,
    },
    loadAverage: {
      "1m": loadAverage[0].toFixed(2),
      "5m": loadAverage[1].toFixed(2),
      "15m": loadAverage[2].toFixed(2),
    },
    memoryStats: {
      total: `${(totalMemory / 1024 / 1024).toFixed(2)} MB`,
      free: `${(freeMemory / 1024 / 1024).toFixed(2)} MB`,
    },
    cpu: {
      cores: os.cpus().length,
      model: os.cpus()[0].model,
    },
    healthy: freeMemory / totalMemory > 0.1 && loadAverage[0] < os.cpus().length,
  };

  res.status(200).json(healthCheck);
});

// Fallback for homepage
app.get("/", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Dashboard route
app.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Get the usage.html file from analytics folder and making an endpoint
app.get('/analytics', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'analytics', 'stats.html'));
});

//serve it via a clean route
app.get("/resolution-stats", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'resolution-stats', 'resolutions.html'));
});

// Get time stats page from time-stats folder
app.get("/time-stats", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'time-stats', 'time-stats.html'));
});

// Get User Managerment page page from public folder
app.get("/manage-users", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'user-management.html'));
});

// My Account page
app.get('/my-account', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'my-account', 'my-account.html'));
});

// Admin-only Signup Requests page
app.get('/signup-requests', requireRole('Admin'), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup-requests.html'));
});

//serve it via a clean route endpoint like /resolution-stats
app.get("/resolution-stats", (req, res) => {
  res.json({
    totalSuccess: resolutionStats.success,
    totalFailure: resolutionStats.failure,
    perRegion: resolutionStats.perRegion,
    failedUrls: resolutionStats.failedUrls
  });
});

// Auth APIs
app.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  try {
    const user = await findUserByUsernameOrEmail(username);
    if (!user) return res.redirect('/auth/error.html');
    if (!user.approved) {
      // Not approved yet
      return res.redirect('/auth/error.html');
    }
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.redirect('/auth/error.html');
    req.session.user = { id: user.id, name: user.name, username: user.username, email: user.email, role: user.role };
    try { await logActivity(user.id, 'LOGIN', `${user.username}, LoggedIn Successfully`); } catch {}
    return req.session.save((err) => {
      if (err) return res.redirect('/auth/error.html');
      return res.redirect('/index.html');
    });
  } catch (e) {
    return res.redirect('/auth/error.html');
  }
});

app.post('/api/auth/register', async (req, res) => {
  const { name, username, email, password } = req.body || {};
  try {
    const existing = await findUserByUsernameOrEmail(username);
    if (existing) return res.status(400).json({ error: 'User already exists' });
    const hash = await bcrypt.hash(password, 10);
    const id = await createUser({ name, username, email, passwordHash: hash, role: 'Subscriber' });
    try { await logActivity(id, 'REGISTER', { username }); } catch {}
    res.status(201).json({ id, approved: false, message: 'Registration submitted. Pending admin approval.' });
  } catch (e) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.get('/api/auth/me', (req, res) => {
  res.json({ user: req.session?.user || null });
});

// Logout route
app.get('/logout', requireAuth, async (req, res) => {
  try { await logActivity(req.session.user.id, 'LOGOUT', "User logged out"); } catch {}
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// Admin: users CRUD
app.get('/api/users', requireRole('Admin'), async (req, res) => {
  try {
    const { q, page = 1, pageSize = 50 } = req.query;
    const users = await listUsers({ q, page: Number(page), pageSize: Number(pageSize) });
    const total = await countUsers({ q });
    res.json({ users, total });
  } catch (e) {
    res.status(500).json({ error: 'Failed to list users' });
  }
});

// Approve a pending user
app.post('/api/users/:id/approve', requireRole('Admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    await updateUser(id, { approved: 1 });
    try { await logActivity(req.session.user.id, 'USER_APPROVE', { id }); } catch {}
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to approve user' });
  }
});

// Reject (delete) a pending user
app.post('/api/users/:id/reject', requireRole('Admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    await deleteUserById(id);
    try { await logActivity(req.session.user.id, 'USER_REJECT', { id }); } catch {}
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to reject user' });
  }
});

app.post('/api/users', requireRole('Admin'), async (req, res) => {
  try {
    const { name, username, email, password, role = 'Subscriber', approved = true } = req.body || {};
    const hash = await bcrypt.hash(password, 10);
    const id = await createUser({ name, username, email, passwordHash: hash, role });
    // If admin wants to auto-approve, update flag
    if (approved) {
      await updateUser(id, { approved: 1 });
    }
    try { await logActivity(req.session.user.id, 'USER_CREATE', { id, username, role }); } catch {}
    res.status(201).json({ id });
  } catch (e) {
    res.status(500).json({ error: 'Failed to create user' });
  }
});

app.put('/api/users/:id', requireRole('Admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { name, username, email, role, password, approved } = req.body || {};
    const passwordHash = password ? await bcrypt.hash(password, 10) : undefined;
    await updateUser(id, { name, username, email, role, passwordHash, approved });
    try { await logActivity(req.session.user.id, 'USER_UPDATE', { id, role }); } catch {}
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to update user' });
  }
});

//Update user details
app.put('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const { name, username, email, password } = req.body || {};
    const userId = req.session.user.id;

    // Prepare update data
    const updateData = {};
    if (name !== undefined) updateData.name = name;
    if (username !== undefined) updateData.username = username;
    if (email !== undefined) updateData.email = email;
    if (password) {
      // Hash the password
      updateData.passwordHash = await bcrypt.hash(password, 10);
    }

    // Update user profile
    await updateUser(userId, updateData);

    // Update session data
    if (name !== undefined) req.session.user.name = name;
    if (username !== undefined) req.session.user.username = username;
    if (email !== undefined) req.session.user.email = email;

    // Save session after updates
    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    try { await logActivity(userId, 'PROFILE_UPDATE', { fields: Object.keys(updateData) }); } catch {}

    res.json({ message: 'Profile updated successfully'});
  } catch (e) {
    console.error('Profile update error:', e);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

app.delete('/api/users/:id', requireRole('Admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    await deleteUserById(id);
    try { await logActivity(req.session.user.id, 'USER_DELETE', { id }); } catch {}
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Activities
app.get('/api/activities', requireAuth, async (req, res) => {
  try {
    const { page = 1, pageSize = 100, action, username, role, from, to } = req.query;
    const isAdmin = req.session.user.role === 'Admin';
    const { rows, total } = await listActivitiesForUserOrAll({
      userId: req.session.user.id,
      all: isAdmin,
      page: Number(page),
      pageSize: Number(pageSize),
      actionQuery: action,
      usernameQuery: username,
      roleQuery:role,
      fromDate: from,
      toDate: to
    });
    res.json({ activities: rows, total });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch activities' });
  }
});

app.post('/api/activities', requireAuth, async (req, res) => {
  try {
    const { action, details } = req.body || {};
    const id = await logActivity(req.session.user.id, action, details || {});
    res.status(201).json({ id });
  } catch (e) {
    res.status(500).json({ error: 'Failed to log activity' });
  }
});

// IP endpoint
app.get('/ip', requireAuth, (req, res) => {
  const rawIp =
    req.headers['x-forwarded-for']?.split(',')[0] ||
    req.socket?.remoteAddress ||
    req.ip;

  // Remove IPv6 prefix if present
  const clientIp = rawIp?.replace(/^::ffff:/, '');

  console.log(`Client IP: ${clientIp}`);
  res.send({ ip : clientIp });
});

app.get('/puppeteer-status', requireAuth, async (req, res) => {
  try {
    const browser = await puppeteer.connect({ browserWSEndpoint: getBrowserWss("US") });
    const page = await browser.newPage();
    await page.close();
    await browser.disconnect();
    res.json({ status: "ok", message: "Puppeteer connection is working." });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});


// Keep Render service awake by pinging itself every 14 minutes
setInterval(() => {
  const url = 'https://thequick10-d8kx.onrender.com'; // Replace with your actual Render URL

  https.get(url, (res) => {
    console.log(`[KEEP-AWAKE] Pinged self. Status code: ${res.statusCode}`);
  }).on('error', (err) => {
    console.error('[KEEP-AWAKE] Self-ping error:', err.message);
  });
}, 14 * 60 * 1000); // every 14 minutes

app.listen(PORT, () => {
  console.log(`🚀 Region-aware resolver running at http://localhost:${PORT}`);
});