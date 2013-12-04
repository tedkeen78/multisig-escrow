PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS `users` (
  `id` INTEGER PRIMARY KEY UNIQUE NOT NULL,
  `email` TEXT UNIQUE NOT NULL,
  `otpenabled` BOOLEAN DEFAULT 0 NOT NULL,
  `otpkey` TEXT,
  `emailoptout` BOOLEAN DEFAULT 0 NOT NULL
);

CREATE TABLE IF NOT EXISTS `transactions` (
  `id` INTEGER PRIMARY KEY UNIQUE NOT NULL,
  `uuid` TEXT UNIQUE NOT NULL,
  `buyer` INTEGER REFERENCES `users`(`id`) ON DELETE SET NULL,
  `seller` INTEGER REFERENCES `users`(`id`) ON DELETE SET NULL,
  `arbitrator` INTEGER REFERENCES `users`(`id`) ON DELETE SET NULL,
  `buyer_agreed` BOOLEAN DEFAULT 0 NOT NULL,
  `seller_agreed` BOOLEAN DEFAULT 0 NOT NULL,
  `arbitrator_agreed` BOOLEAN DEFAULT 0 NOT NULL,
  `inv_secret` TEXT NOT NULL,
  `buyer_address` TEXT,
  `seller_address` TEXT,
  `arbitrator_address` TEXT UNIQUE,
  `arbitrator_privkey` TEXT UNIQUE,
  `title` TEXT NOT NULL,
  `text` TEXT NOT NULL,
  `time_made` INTEGER NOT NULL,
  `time_canceled` INTEGER,
  `time_started` INTEGER,
  `time_fundsactive` INTEGER,
  `time_complete` INTEGER,
  `timelength` INTEGER,
  `payment` INTEGER NOT NULL,
  `arb_fee` REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS `transactions_buyer_idx` ON `transactions`(`buyer`);
CREATE INDEX IF NOT EXISTS `transactions_seller_idx` ON `transactions`(`seller`);
CREATE INDEX IF NOT EXISTS `transactions_arbitrator_idx` ON `transactions`(`arbitrator`);
CREATE INDEX IF NOT EXISTS `transactions_time_made_idx` ON `transactions`(`time_made`);
CREATE INDEX IF NOT EXISTS `transactions_time_canceled_idx` ON `transactions`(`time_canceled`);
CREATE INDEX IF NOT EXISTS `transactions_time_started_idx` ON `transactions`(`time_started`);
CREATE INDEX IF NOT EXISTS `transactions_time_fundsactive_idx` ON `transactions`(`time_fundsactive`);
CREATE INDEX IF NOT EXISTS `transactions_time_complete_idx` ON `transactions`(`time_complete`);
-- SQLite creates implicit indexes on unique and primary key fields, so
-- we don't need to worry about creating indexes for those fields.

CREATE TABLE IF NOT EXISTS `transactioncomments` (
  `id` INTEGER PRIMARY KEY UNIQUE NOT NULL,
  `transaction` INTEGER NOT NULL REFERENCES `transactions`(`id`) ON DELETE CASCADE,
  `commentnum` INTEGER NOT NULL,
  `user` INTEGER REFERENCES `users`(`id`) ON DELETE SET NULL,
  `time` INTEGER NOT NULL,
  `text` TEXT NOT NULL,
  UNIQUE (`transaction`, `commentnum`)
);

CREATE INDEX IF NOT EXISTS `transactioncomments_transaction_idx` ON `transactioncomments`(`transaction`);
