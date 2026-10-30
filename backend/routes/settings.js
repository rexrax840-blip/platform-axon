const express = require("express");
const crypto = require("crypto");
const AdminSettings = require("../models/AdminSettings");

const router = express.Router();

async function getOrCreateSettings() {
  let settings = await AdminSettings.findOne({ key: "global" });
  if (!settings) {
    settings = new AdminSettings({ key: "global" });
    await settings.save();
  }
  return settings;
}

function hashPassword(password) {
  return crypto.createHash("sha256").update(String(password)).digest("hex");
}

// Public settings: brand, channels, VIP levels, working hours, deposit
// addresses and Cloudinary cloud name / key only. Secrets are never sent.
router.get("/", async (req, res) => {
  try {
    const settings = await getOrCreateSettings();
    res.json({ settings: settings.toPublicJSON() });
  } catch (error) {
    console.error("Get settings error:", error);
    res.status(500).json({ error: "Failed to fetch settings" });
  }
});

// Admin update: brand, channels, VIP levels, working hours, deposit
// addresses, Cloudinary (cloudName/apiKey, plus apiSecret only when a new
// value is supplied). Admin credentials are NOT updated here.
router.put("/", async (req, res) => {
  try {
    const settings = await getOrCreateSettings();
    const body = req.body || {};
    if (typeof body.brandName === "string") settings.brandName = body.brandName;
    if (Array.isArray(body.contactChannels)) settings.contactChannels = body.contactChannels;
    if (Array.isArray(body.vipLevels)) settings.vipLevels = body.vipLevels;
    if (body.workingHours && typeof body.workingHours === "object") {
      settings.workingHours = { ...settings.workingHours.toObject(), ...body.workingHours };
    }
    if (Array.isArray(body.depositAddresses)) settings.depositAddresses = body.depositAddresses;
    if (body.cloudinary && typeof body.cloudinary === "object") {
      if (typeof body.cloudinary.cloudName === "string") settings.cloudinary.cloudName = body.cloudinary.cloudName;
      if (typeof body.cloudinary.apiKey === "string") settings.cloudinary.apiKey = body.cloudinary.apiKey;
      if (typeof body.cloudinary.apiSecret === "string" && body.cloudinary.apiSecret) {
        settings.cloudinary.apiSecret = body.cloudinary.apiSecret;
      }
    }
    await settings.save();
    res.json({ message: "Settings updated", settings: settings.toPublicJSON() });
  } catch (error) {
    console.error("Update settings error:", error);
    res.status(500).json({ error: "Failed to update settings" });
  }
});

// Set admin panel username + password (used by the /admin-password page).
// The password is stored only as a SHA-256 hash, never in plain text.
router.post("/admin-credentials", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password are required." });
    }
    const settings = await getOrCreateSettings();
    settings.admin.username = String(username).trim();
    settings.admin.passwordHash = hashPassword(password);
    await settings.save();
    res.json({ message: "Admin credentials updated" });
  } catch (error) {
    console.error("Set admin credentials error:", error);
    res.status(500).json({ error: "Failed to update admin credentials" });
  }
});

// Verify admin panel username + password. Returns no secret on success.
router.post("/admin-login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const settings = await getOrCreateSettings();
    if (!settings.admin?.passwordHash) {
      return res.json({ ok: false, adminPasswordSet: false });
    }
    const ok =
      String(username).trim() === settings.admin.username &&
      hashPassword(password) === settings.admin.passwordHash;
    res.json({ ok, adminPasswordSet: true });
  } catch (error) {
    console.error("Admin login error:", error);
    res.status(500).json({ error: "Failed to verify admin credentials" });
  }
});

module.exports = router;
