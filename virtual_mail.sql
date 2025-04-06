-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: localhost
-- Erstellungszeit: 06. Apr 2025 um 11:13
-- Server-Version: 8.0.27
-- PHP-Version: 8.0.0

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Datenbank: `virtual_mail2`
--

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `admin_mailbox_access_log`
--

CREATE TABLE `admin_mailbox_access_log` (
  `id` int NOT NULL,
  `admin_user_id` int NOT NULL,
  `target_user_id` int NOT NULL,
  `access_timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `justification_reason` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `acknowledged_legitimate_interest` tinyint(1) NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `attachments`
--

CREATE TABLE `attachments` (
  `id` int NOT NULL,
  `original_filename` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `stored_filename` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `mime_type` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `filesize_bytes` bigint NOT NULL,
  `uploaded_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `uploader_user_id` int DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `domains`
--

CREATE TABLE `domains` (
  `id` int NOT NULL,
  `domain_name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `is_public_registrable` tinyint(1) NOT NULL DEFAULT '1',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Daten für Tabelle `domains`
--

INSERT INTO `domains` (`id`, `domain_name`, `is_public_registrable`, `created_at`) VALUES
(1, 'internal.local', 1, '2024-02-27 09:00:00'),
(5, 'opento.public', 1, '2025-04-06 08:58:57'),
(6, 'mycooldomain.com', 0, '2025-04-06 08:59:12');

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `emails`
--

CREATE TABLE `emails` (
  `id` bigint NOT NULL,
  `sender_user_id` int NOT NULL,
  `subject` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `body` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
  `sent_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Daten für Tabelle `emails`
--

INSERT INTO `emails` (`id`, `sender_user_id`, `subject`, `body`, `sent_at`) VALUES
(4, 6, 'Welcome!', 'Hey,\r\n\r\nthank you for using this nice virtual mail system.\r\nCool what LLMs are able to do these days, isn\'t it?\r\n\r\nBe sure to check out my website: https://mizel.de', '2025-04-06 09:05:01');

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `email_attachments`
--

CREATE TABLE `email_attachments` (
  `id` int NOT NULL,
  `email_id` bigint NOT NULL,
  `attachment_id` int NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `email_recipients`
--

CREATE TABLE `email_recipients` (
  `id` bigint NOT NULL,
  `email_id` bigint NOT NULL,
  `recipient_user_id` int NOT NULL,
  `folder` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'INBOX',
  `is_read` tinyint(1) NOT NULL DEFAULT '0',
  `received_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Daten für Tabelle `email_recipients`
--

INSERT INTO `email_recipients` (`id`, `email_id`, `recipient_user_id`, `folder`, `is_read`, `received_at`) VALUES
(7, 4, 2, 'INBOX', 1, '2025-04-06 09:05:01'),
(8, 4, 6, 'SENT', 1, '2025-04-06 09:05:01');

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `users`
--

CREATE TABLE `users` (
  `id` int NOT NULL,
  `username` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `domain_id` int NOT NULL,
  `password_hash` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `full_name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_admin` tinyint(1) NOT NULL DEFAULT '0',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `last_login` timestamp NULL DEFAULT NULL,
  `storage_used_bytes` bigint NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Daten für Tabelle `users`
--

INSERT INTO `users` (`id`, `username`, `domain_id`, `password_hash`, `full_name`, `is_admin`, `created_at`, `last_login`, `storage_used_bytes`) VALUES
(2, 'admin', 1, '$2y$10$Bw5Chm5rTI1Ex3vfj/25WeFHYqDa0wLbIPnexvMDvA9lo7LZvqZ6q', 'Administrator', 1, '2025-04-05 10:27:14', '2025-04-06 08:58:26', 464),
(6, 'mzl-alx', 6, '$2y$10$.3yAuPXPWkT/eS7jQoDNI.FDV5ZcCySTwUY1jAUUZQfxQK1omnhyO', 'Alex | mizel.de', 0, '2025-04-06 09:01:44', '2025-04-06 09:02:07', 172);

--
-- Indizes der exportierten Tabellen
--

--
-- Indizes für die Tabelle `admin_mailbox_access_log`
--
ALTER TABLE `admin_mailbox_access_log`
  ADD PRIMARY KEY (`id`),
  ADD KEY `admin_user_id` (`admin_user_id`),
  ADD KEY `target_user_id` (`target_user_id`);

--
-- Indizes für die Tabelle `attachments`
--
ALTER TABLE `attachments`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `stored_filename` (`stored_filename`),
  ADD KEY `uploader_user_id` (`uploader_user_id`);

--
-- Indizes für die Tabelle `domains`
--
ALTER TABLE `domains`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `domain_name` (`domain_name`);

--
-- Indizes für die Tabelle `emails`
--
ALTER TABLE `emails`
  ADD PRIMARY KEY (`id`),
  ADD KEY `sender_user_id` (`sender_user_id`);

--
-- Indizes für die Tabelle `email_attachments`
--
ALTER TABLE `email_attachments`
  ADD PRIMARY KEY (`id`),
  ADD KEY `email_id` (`email_id`),
  ADD KEY `attachment_id` (`attachment_id`);

--
-- Indizes für die Tabelle `email_recipients`
--
ALTER TABLE `email_recipients`
  ADD PRIMARY KEY (`id`),
  ADD KEY `email_id` (`email_id`),
  ADD KEY `recipient_folder` (`recipient_user_id`,`folder`);

--
-- Indizes für die Tabelle `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_email` (`username`,`domain_id`),
  ADD KEY `domain_id` (`domain_id`);

--
-- AUTO_INCREMENT für exportierte Tabellen
--

--
-- AUTO_INCREMENT für Tabelle `admin_mailbox_access_log`
--
ALTER TABLE `admin_mailbox_access_log`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT für Tabelle `attachments`
--
ALTER TABLE `attachments`
  MODIFY `id` int NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT für Tabelle `domains`
--
ALTER TABLE `domains`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT für Tabelle `emails`
--
ALTER TABLE `emails`
  MODIFY `id` bigint NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT für Tabelle `email_attachments`
--
ALTER TABLE `email_attachments`
  MODIFY `id` int NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT für Tabelle `email_recipients`
--
ALTER TABLE `email_recipients`
  MODIFY `id` bigint NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;

--
-- AUTO_INCREMENT für Tabelle `users`
--
ALTER TABLE `users`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- Constraints der exportierten Tabellen
--

--
-- Constraints der Tabelle `admin_mailbox_access_log`
--
ALTER TABLE `admin_mailbox_access_log`
  ADD CONSTRAINT `admin_mailbox_access_log_ibfk_1` FOREIGN KEY (`admin_user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `admin_mailbox_access_log_ibfk_2` FOREIGN KEY (`target_user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints der Tabelle `attachments`
--
ALTER TABLE `attachments`
  ADD CONSTRAINT `attachments_ibfk_1` FOREIGN KEY (`uploader_user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL;

--
-- Constraints der Tabelle `emails`
--
ALTER TABLE `emails`
  ADD CONSTRAINT `emails_ibfk_1` FOREIGN KEY (`sender_user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints der Tabelle `email_attachments`
--
ALTER TABLE `email_attachments`
  ADD CONSTRAINT `email_attachments_ibfk_1` FOREIGN KEY (`email_id`) REFERENCES `emails` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `email_attachments_ibfk_2` FOREIGN KEY (`attachment_id`) REFERENCES `attachments` (`id`) ON DELETE CASCADE;

--
-- Constraints der Tabelle `email_recipients`
--
ALTER TABLE `email_recipients`
  ADD CONSTRAINT `email_recipients_ibfk_1` FOREIGN KEY (`email_id`) REFERENCES `emails` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `email_recipients_ibfk_2` FOREIGN KEY (`recipient_user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints der Tabelle `users`
--
ALTER TABLE `users`
  ADD CONSTRAINT `users_ibfk_1` FOREIGN KEY (`domain_id`) REFERENCES `domains` (`id`) ON DELETE RESTRICT;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
