CREATE TABLE `firewall_policy` (
  `id` text PRIMARY KEY NOT NULL,
  `revision` integer DEFAULT 0 NOT NULL,
  `policy` text NOT NULL,
  FOREIGN KEY (`id`) REFERENCES `interfaces_table`(`name`) ON UPDATE cascade ON DELETE cascade
);
