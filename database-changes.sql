ALTER TABLE `user`
  ADD `account_activation_hash` VARCHAR(64) NULL DEFAULT NULL AFTER `reset_token_expires_at`,
  ADD UNIQUE (`account_activation_hash`); 
