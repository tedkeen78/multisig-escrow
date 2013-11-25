PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS `users` (
  `id` INTEGER NOT NULL,
  `email` TEXT UNIQUE NOT NULL,
  `otpenabled` BOOLEAN DEFAULT 0 NOT NULL,
  `otpkey` TEXT,
  PRIMARY KEY (`id` ASC)
);

CREATE TABLE IF NOT EXISTS `transactions` (
  `id` INTEGER NOT NULL,
  `uuid` TEXT UNIQUE NOT NULL,
  `buyer` INTEGER,
  `seller` INTEGER,
  `arbitrator` INTEGER,
  `buyer_agreed` BOOLEAN DEFAULT 0 NOT NULL,
  `seller_agreed` BOOLEAN DEFAULT 0 NOT NULL,
  `arbitrator_agreed` BOOLEAN DEFAULT 0 NOT NULL,
  `inv_secret` TEXT NOT NULL,
  `buyer_address` TEXT,
  `seller_address` TEXT,
  `arbitrator_address` TEXT,
  `arbitrator_privkey` TEXT,
  `title` TEXT NOT NULL,
  `text` TEXT NOT NULL,
  `time_made` INTEGER NOT NULL,
  `time_canceled` INTEGER,
  `time_started` INTEGER,
  `time_fundsactive` INTEGER,
  `time_complete` INTEGER,
  `timelength` INTEGER,
  `payment` INTEGER NOT NULL,
  `arb_fee` REAL NOT NULL,
  PRIMARY KEY (`id` ASC),
  FOREIGN KEY (`buyer`) REFERENCES `users`(`id`) ON DELETE SET NULL,
  FOREIGN KEY (`seller`) REFERENCES `users`(`id`) ON DELETE SET NULL,
  FOREIGN KEY (`arbitrator`) REFERENCES `users`(`id`) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS `transactioncomments` (
  `id` INTEGER NOT NULL,
  `transaction` INTEGER NOT NULL,
  `commentnum` INTEGER NOT NULL,
  `user` INTEGER,
  `time` INTEGER NOT NULL,
  `text` TEXT NOT NULL,
  PRIMARY KEY (`id` ASC),
  UNIQUE (`transaction`, `commentnum`),
  FOREIGN KEY (`user`) REFERENCES `users`(`id`) ON DELETE SET NULL,
  FOREIGN KEY (`transaction`) REFERENCES `transactions`(`id`) ON DELETE CASCADE
);
