import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "crypto";
import { JsonProjectStorage } from "./server/storage/jsonProjectStorage";
import { calculateProjectMetrics } from "./server/services/projectMetrics";
import { analyzeProjectWithOpenAI } from "./server/services/openaiAnalysisService";
import { fetchProjectsFromSheet } from "./server/services/googleSheetsService";

dotenv.config();

const storage = new JsonProjectStorage();

// Session container for active tokens
const activeSessions = new Set<string>();

const getSessionFromCookie = (req: express.Request): string | null => {
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) return null;
  const cookies = cookieHeader.split(";").reduce((acc: Record<string, string>, c: string) => {
    const [name, ...val] = c.trim().split("=");
    if (name) {
      acc[name] = val.join("=");
    }
    return acc;
  }, {});
  return cookies.session || null;
};

// SHA-256 hash calculator for secure verification
const getPasswordHash = (pwd: string): string => {
  return crypto.createHash("sha256").update(pwd).digest("hex");
};

function verifyPassword(pwd: string): boolean {
  const cleanPwd = pwd ? String(pwd).trim() : "";
  
  // Unconditionally allow "123" or its hash for testing access as requested
  if (cleanPwd === "123" || getPasswordHash(cleanPwd) === "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3") {
    return true;
  }

  const envHash = process.env.APP_ACCESS_PASSWORD_HASH;
  if (envHash && envHash.trim() !== "") {
    return getPasswordHash(cleanPwd) === envHash.trim();
  }
  
  const envPwd = process.env.APP_ACCESS_PASSWORD;
  if (envPwd && envPwd.trim() !== "") {
    return cleanPwd === envPwd.trim();
  }
  
  return false;
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(cors());
  app.use(express.json({ limit: '50mb' }));

  // Protection middleware for API endpoints
  app.use((req, res, next) => {
    const isPublicRoute =
      req.path === "/api/auth/login" ||
      req.path === "/api/auth/check" ||
      req.path === "/api/auth/logout" ||
      req.path === "/api/health" ||
      req.path === "/api/bitrix/health" ||
      req.path === "/api/bitrix/projects/import";

    if (isPublicRoute) {
      return next();
    }

    if (req.path.startsWith("/api")) {
      const token = getSessionFromCookie(req);
      if (token && activeSessions.has(token)) {
        return next();
      }
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    next();
  });

  // Auth Endpoints
  // 1. POST /api/auth/login
  app.post("/api/auth/login", (req, res) => {
    const { password } = req.body;
    if (!password) {
      return res.status(400).json({ success: false, error: "Пароль обязателен к заполнению" });
    }

    if (verifyPassword(password)) {
      const sessionToken = crypto.randomBytes(32).toString("hex");
      activeSessions.add(sessionToken);

      // Max-Age is 43200 seconds (12 hours)
      // SameSite=None; Secure must be used for cross-origin browser iframe environments
      res.setHeader(
        "Set-Cookie",
        `session=${sessionToken}; HttpOnly; SameSite=None; Secure; Path=/; Max-Age=43200`
      );
      return res.json({ success: true, authenticated: true });
    } else {
      return res.status(401).json({ success: false, error: "Неверный пароль" });
    }
  });

  // 2. GET /api/auth/check
  app.get("/api/auth/check", (req, res) => {
    const token = getSessionFromCookie(req);
    if (token && activeSessions.has(token)) {
      return res.json({ authenticated: true });
    }
    return res.json({ authenticated: false });
  });

  // 3. POST /api/auth/logout
  app.post("/api/auth/logout", (req, res) => {
    const token = getSessionFromCookie(req);
    if (token) {
      activeSessions.delete(token);
    }
    res.setHeader("Set-Cookie", "session=; HttpOnly; SameSite=None; Secure; Path=/; Max-Age=0");
    return res.json({ success: true });
  });

  // 7.1. health
  app.get("/api/health", (req, res) => {
    res.json({
      success: true,
      status: "ok",
      timestamp: new Date().toISOString(),
      envStatus: {
        hash_present: !!(process.env.APP_ACCESS_PASSWORD_HASH && process.env.APP_ACCESS_PASSWORD_HASH.trim() !== ""),
        plain_present: !!(process.env.APP_ACCESS_PASSWORD && process.env.APP_ACCESS_PASSWORD.trim() !== ""),
        node_env: process.env.NODE_ENV || "development"
      }
    });
  });

  // 7.2. bitrix/health
  app.get("/api/bitrix/health", (req, res) => {
    res.json({
      success: true,
      service: "bitrix-ingest",
      status: "ready"
    });
  });

  // 7.3. bitrix/projects/import
  app.post("/api/bitrix/projects/import", async (req, res) => {
    const authHeader = req.headers.authorization;
    const token = process.env.APP_INGEST_TOKEN;

    if (!authHeader) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    const providedToken = authHeader.replace("Bearer ", "");
    if (providedToken !== token) {
      return res.status(403).json({ success: false, error: "Forbidden" });
    }

    const { projects, syncId, mode } = req.body;

    if (!Array.isArray(projects)) {
      return res.status(400).json({ success: false, error: "projects must be an array" });
    }

    try {
      const result = await storage.upsertProjects(projects, syncId || `sync-${Date.now()}`, mode || "full");
      res.json(result);
    } catch (error: any) {
      res.status(500).json({ success: false, error: error.message });
    }
  });

  // 7.4. GET /api/projects
  app.get("/api/projects", async (req, res) => {
    try {
      // 1. Fetch latest straight from Google Sheets
      const sheetsProjects = await fetchProjectsFromSheet();
      
      // 2. Sync to local storage to preserve lastAnalysis and other metadata
      await storage.upsertProjects(sheetsProjects, `sheets-sync-${Date.now()}`, "full");

      // 3. Return everything from local storage
      const rawProjects = await storage.getAllProjects();
      
      const assessmentDate = new Date();
      const projects = rawProjects.map(p => ({
        ...p,
        _metrics: calculateProjectMetrics(p, assessmentDate)
      }));
      
      const stats = {
        total: projects.length,
        active: projects.filter(p => p.status === "active").length,
        completed: projects.filter(p => p.status === "completed").length,
        atRisk: projects.filter(p => p.status === "at_risk" || p._metrics.planFactByQuarter.some(q => q.status === "risk")).length,
        overdue: projects.filter(p => p.status === "overdue" || p._metrics.pcStatus === "Просрочен").length,
        missingData: projects.filter(p => p._metrics.pcStatus === "Недостаточно данных").length,
        avgCompleteness: projects.reduce((acc, p) => acc + (p._metrics.significantCompletenessPercent || 0), 0) / (projects.length || 1),
        avgProgress: projects.reduce((acc, p) => acc + (p._metrics.weightedTaskProgressPercent || 0), 0) / (projects.length || 1),
        noIndicators: projects.filter(p => p.indicators.length === 0).length,
        lagging: projects.filter(p => p._metrics.planFactByQuarter.some(q => q.deviation < 0)).length
      };

      res.json({
        success: true,
        projects,
        stats
      });
    } catch (error: any) {
      res.status(500).json({ success: false, error: error.message });
    }
  });

  // 7.5. GET /api/projects/:projectId
  app.get("/api/projects/:projectId", async (req, res) => {
    try {
      const project = await storage.getProjectById(req.params.projectId);
      if (!project) {
        return res.status(404).json({ success: false, error: "Project not found" });
      }
      res.json({ success: true, project });
    } catch (error: any) {
      res.status(500).json({ success: false, error: error.message });
    }
  });

  // 7.6. POST /api/projects/:projectId/analyze
  app.post("/api/projects/:projectId/analyze", async (req, res) => {
    try {
      const project = await storage.getProjectById(req.params.projectId);
      if (!project) {
        return res.status(404).json({ success: false, error: "Project not found" });
      }

      const assessmentDate = new Date();
      const metrics = calculateProjectMetrics(project, assessmentDate);
      
      const analysis = await analyzeProjectWithOpenAI({
        project,
        metrics,
        assessmentDate: assessmentDate.toISOString()
      });

      await storage.saveAnalysis(project.projectId, analysis);

      res.json({ success: true, analysis });
    } catch (error: any) {
      console.error("Analysis Error:", error);
      res.status(500).json({ success: false, error: error.message });
    }
  });

  // 18. GET /api/sync-logs
  app.get("/api/sync-logs", async (req, res) => {
    try {
      const logs = await storage.getSyncLogs();
      res.json({ success: true, logs });
    } catch (error: any) {
      res.status(500).json({ success: false, error: error.message });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
