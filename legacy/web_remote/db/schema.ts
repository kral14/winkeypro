import { sqliteTable, text, integer, index } from "drizzle-orm/sqlite-core";

export const devices = sqliteTable("devices", {
  id: text("id").primaryKey(),
  owner: text("owner"),
  name: text("name").notNull(),
  publicKeyHex: text("public_key_hex").notNull(),
  secretHash: text("secret_hash").notNull(),
  pairHash: text("pair_hash"),
  pairExpires: integer("pair_expires"),
  lastSeen: integer("last_seen").notNull(),
  locked: integer("locked"),
  pinReady: integer("pin_ready").notNull().default(0),
  status: text("status").notNull().default("ACTIVE"),
  created: integer("created").notNull(),
}, t => [
  index("device_owner").on(t.owner),
  index("device_status").on(t.status)
]);

export const challenges = sqliteTable("challenges", {
  nonce: text("nonce").primaryKey(),
  deviceId: text("device_id").notNull(),
  purpose: text("purpose").notNull(),
  expiresAt: integer("expires_at").notNull(),
  consumed: integer("consumed").notNull().default(0),
  createdAt: integer("created_at").notNull(),
}, t => [
  index("challenge_device_purpose").on(t.deviceId, t.purpose)
]);

export const mobileSessions = sqliteTable("mobile_sessions", {
  token: text("token").primaryKey(),
  deviceId: text("device_id").notNull(),
  createdAt: integer("created_at").notNull(),
  expiresAt: integer("expires_at").notNull(),
  scope: text("scope").notNull().default("mobile_remote"),
}, t => [
  index("session_device").on(t.deviceId)
]);

export const commands = sqliteTable("commands", {
  id: text("id").primaryKey(),
  deviceId: text("device_id").notNull(),
  owner: text("owner"),
  action: text("action").notNull(),
  state: text("state").notNull(),
  created: integer("created").notNull(),
  expires: integer("expires").notNull(),
  finished: integer("finished"),
  result: text("result"),
}, t => [
  index("command_queue").on(t.deviceId, t.state, t.created)
]);

export const auditLogs = sqliteTable("audit_logs", {
  id: text("id").primaryKey(),
  actor: text("actor").notNull(),
  action: text("action").notNull(),
  targetDeviceId: text("target_device_id"),
  details: text("details"),
  timestamp: integer("timestamp").notNull(),
});
