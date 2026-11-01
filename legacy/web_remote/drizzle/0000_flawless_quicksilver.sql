CREATE TABLE `commands` (
	`id` text PRIMARY KEY NOT NULL,
	`device_id` text NOT NULL,
	`owner` text NOT NULL,
	`action` text NOT NULL,
	`state` text NOT NULL,
	`created` integer NOT NULL,
	`expires` integer NOT NULL,
	`finished` integer,
	`result` text
);
--> statement-breakpoint
CREATE INDEX `command_queue` ON `commands` (`device_id`,`state`,`created`);--> statement-breakpoint
CREATE TABLE `devices` (
	`id` text PRIMARY KEY NOT NULL,
	`owner` text,
	`name` text NOT NULL,
	`secret_hash` text NOT NULL,
	`pair_hash` text,
	`pair_expires` integer,
	`last_seen` integer NOT NULL,
	`locked` integer,
	`pin_ready` integer DEFAULT 0 NOT NULL,
	`created` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `device_owner` ON `devices` (`owner`);