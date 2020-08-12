CREATE USER 'mail_mailmask'@'localhost' IDENTIFIED BY 'xyz';

GRANT SELECT, INSERT, UPDATE, DELETE ON privacy_domains TO ‘mail_mailmask’@‘localhost’;
GRANT SELECT, INSERT, UPDATE, DELETE ON privacy_forwardings TO ‘mail_mailmask’@‘localhost’;

CREATE TABLE `privacy_domains` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `domain` varchar(45) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `domain` (`domain`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `privacy_forwardings` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `source` varchar(80) NOT NULL,
  `destination` text NOT NULL,
  `expiration` mediumtext DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `source` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
