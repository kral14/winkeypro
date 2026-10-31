CREATE TABLE IF NOT EXISTS `challenges` (
	`nonce` text PRIMARY KEY NOT NULL,
	`device_id` text NOT NULL,
	`purpose` text NOT NULL,
	`expires_at` integer NOT NULL,
	`consumed` integer DEFAULT 0 NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `challenge_device_purpose` ON `challenges` (`device_id`,`purpose`);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `mobile_sessions` (
	`token` text PRIMARY KEY NOT NULL,
	`device_id` text NOT NULL,
	`created_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	`scope` text DEFAULT 'mobile_remote' NOT NULL
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `session_device` ON `mobile_sessions` (`device_id`);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `audit_logs` (
	`id` text PRIMARY KEY NOT NULL,
	`actor` text NOT NULL,
	`action` text NOT NULL,
	`target_device_id` text,
	`details` text,
	`timestamp` integer NOT NULL
);
--> statement-breakpoint
ALTER TABLE `devices` ADD `public_key_hex` text;
--> statement-breakpoint
ALTER TABLE `devices` ADD `status` text DEFAULT 'ACTIVE' NOT NULL;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `device_status` ON `devices` (`status`);

