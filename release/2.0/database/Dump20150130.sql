CREATE DATABASE  IF NOT EXISTS `bypass` /*!40100 DEFAULT CHARACTER SET latin1 */;
USE `bypass`;
-- MySQL dump 10.13  Distrib 5.5.41, for debian-linux-gnu (x86_64)
--
-- Host: 127.0.0.1    Database: bypass
-- ------------------------------------------------------
-- Server version	5.5.41-0ubuntu0.14.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `base_info`
--

DROP TABLE IF EXISTS `base_info`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `base_info` (
  `base_info_id` int(11) NOT NULL AUTO_INCREMENT,
  `serialnum` varchar(45) DEFAULT NULL,
  `hostname` varchar(45) DEFAULT NULL,
  `hardware` varchar(45) DEFAULT NULL,
  `version` varchar(45) DEFAULT NULL,
  `http_method` varchar(45) DEFAULT NULL,
  `analysts_cache` int(11) DEFAULT '1',
  `dns1` varchar(45) DEFAULT NULL,
  `dns2` varchar(45) DEFAULT NULL,
  `init_liscence` text,
  `legal_liscence` text,
  `created` int(11) unsigned zerofill DEFAULT NULL,
  `updated` int(11) DEFAULT NULL,
  PRIMARY KEY (`base_info_id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `base_info`
--

LOCK TABLES `base_info` WRITE;
/*!40000 ALTER TABLE `base_info` DISABLE KEYS */;
INSERT INTO `base_info` VALUES (1,'123456','bodao','server','1.0',NULL,1,NULL,NULL,'0000',NULL,NULL,NULL);
/*!40000 ALTER TABLE `base_info` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `cpu_mem`
--

DROP TABLE IF EXISTS `cpu_mem`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `cpu_mem` (
  `cpu_mem_id` int(11) NOT NULL,
  `cpu_mem_data` text,
  `cpu_mem_created` int(11) DEFAULT NULL,
  PRIMARY KEY (`cpu_mem_id`),
  UNIQUE KEY `cpu_mem_id_UNIQUE` (`cpu_mem_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `cpu_mem`
--

LOCK TABLES `cpu_mem` WRITE;
/*!40000 ALTER TABLE `cpu_mem` DISABLE KEYS */;
/*!40000 ALTER TABLE `cpu_mem` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `http_data`
--

DROP TABLE IF EXISTS `http_data`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `http_data` (
  `data_num` int(11) NOT NULL,
  `head` text,
  `body` text,
  `created` int(11) DEFAULT NULL,
  `updated` int(11) DEFAULT NULL,
  PRIMARY KEY (`data_num`),
  UNIQUE KEY `head_UNIQUE` (`data_num`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `http_data`
--

LOCK TABLES `http_data` WRITE;
/*!40000 ALTER TABLE `http_data` DISABLE KEYS */;
/*!40000 ALTER TABLE `http_data` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `http_domain`
--

DROP TABLE IF EXISTS `http_domain`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `http_domain` (
  `do_id` int(11) NOT NULL AUTO_INCREMENT,
  `type` int(11) DEFAULT NULL,
  `domain` varchar(255) DEFAULT NULL,
  `tag` int(11) DEFAULT NULL,
  `created` int(11) DEFAULT NULL,
  `updated` int(11) DEFAULT NULL,
  `state` tinyint(4) DEFAULT NULL,
  PRIMARY KEY (`do_id`),
  UNIQUE KEY `do_id_UNIQUE` (`do_id`),
  UNIQUE KEY `domain_UNIQUE` (`domain`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `http_domain`
--

LOCK TABLES `http_domain` WRITE;
/*!40000 ALTER TABLE `http_domain` DISABLE KEYS */;
/*!40000 ALTER TABLE `http_domain` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `http_rule`
--

DROP TABLE IF EXISTS `http_rule`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `http_rule` (
  `rule_id` int(11) NOT NULL AUTO_INCREMENT,
  `do_id` int(11) DEFAULT NULL,
  `orders` int(11) DEFAULT NULL,
  `url` varchar(255) DEFAULT '',
  `cookies` varchar(255) DEFAULT '',
  `referer` varchar(255) DEFAULT '',
  `data_num` int(11) DEFAULT NULL,
  `created` int(11) DEFAULT NULL,
  `updated` int(11) DEFAULT NULL,
  `state` tinyint(4) DEFAULT '0',
  PRIMARY KEY (`rule_id`),
  UNIQUE KEY `rule_id_UNIQUE` (`rule_id`),
  KEY `fk_http_rule_1_idx` (`do_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `http_rule`
--

LOCK TABLES `http_rule` WRITE;
/*!40000 ALTER TABLE `http_rule` DISABLE KEYS */;
/*!40000 ALTER TABLE `http_rule` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `inpackage`
--

DROP TABLE IF EXISTS `inpackage`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `inpackage` (
  `in_id` int(11) NOT NULL AUTO_INCREMENT,
  `inter_id` int(11) DEFAULT NULL,
  `inter_id2` int(11) DEFAULT NULL,
  `type1` varchar(15) DEFAULT NULL,
  `type2` int(11) DEFAULT NULL,
  `type3` varchar(45) DEFAULT NULL,
  `created` int(11) DEFAULT NULL,
  `updated` int(11) DEFAULT NULL,
  PRIMARY KEY (`in_id`),
  UNIQUE KEY `inter_id_UNIQUE` (`inter_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `inpackage`
--

LOCK TABLES `inpackage` WRITE;
/*!40000 ALTER TABLE `inpackage` DISABLE KEYS */;
/*!40000 ALTER TABLE `inpackage` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `interface`
--

DROP TABLE IF EXISTS `interface`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `interface` (
  `inter_id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(20) DEFAULT NULL,
  `type` int(11) DEFAULT '0',
  `created` int(11) DEFAULT NULL,
  `updated` int(11) DEFAULT NULL,
  `state` tinyint(4) DEFAULT '0',
  PRIMARY KEY (`inter_id`),
  UNIQUE KEY `name_UNIQUE` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `interface`
--

LOCK TABLES `interface` WRITE;
/*!40000 ALTER TABLE `interface` DISABLE KEYS */;
/*!40000 ALTER TABLE `interface` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `manage`
--

DROP TABLE IF EXISTS `manage`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `manage` (
  `ma_id` int(11) NOT NULL AUTO_INCREMENT,
  `inter_id` int(11) DEFAULT NULL,
  `ip` varchar(20) DEFAULT NULL,
  `mask` varchar(20) DEFAULT NULL,
  `gateway` varchar(20) DEFAULT NULL,
  `dns1` varchar(20) DEFAULT NULL,
  `dns2` varchar(20) DEFAULT NULL,
  `created` int(11) DEFAULT NULL,
  `updated` int(11) DEFAULT NULL,
  PRIMARY KEY (`ma_id`),
  UNIQUE KEY `inter_id_UNIQUE` (`inter_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `manage`
--

LOCK TABLES `manage` WRITE;
/*!40000 ALTER TABLE `manage` DISABLE KEYS */;
/*!40000 ALTER TABLE `manage` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `netport`
--

DROP TABLE IF EXISTS `netport`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `netport` (
  `netport_id` int(11) NOT NULL,
  `net_data` text,
  `netport_created` int(11) DEFAULT NULL,
  PRIMARY KEY (`netport_id`),
  UNIQUE KEY `idnetport_UNIQUE` (`netport_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `netport`
--

LOCK TABLES `netport` WRITE;
/*!40000 ALTER TABLE `netport` DISABLE KEYS */;
/*!40000 ALTER TABLE `netport` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `out_left`
--

DROP TABLE IF EXISTS `out_left`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `out_left` (
  `out_left_id` int(11) NOT NULL AUTO_INCREMENT,
  `out_left_num` int(11) DEFAULT '8',
  PRIMARY KEY (`out_left_id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `out_left`
--

LOCK TABLES `out_left` WRITE;
/*!40000 ALTER TABLE `out_left` DISABLE KEYS */;
INSERT INTO `out_left` VALUES (1,8);
/*!40000 ALTER TABLE `out_left` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `outpackage`
--

DROP TABLE IF EXISTS `outpackage`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `outpackage` (
  `out_id` int(11) NOT NULL AUTO_INCREMENT,
  `inter_id` int(11) DEFAULT NULL,
  `out_num` int(11) DEFAULT '0',
  `created` int(11) DEFAULT NULL,
  `updated` int(11) DEFAULT NULL,
  PRIMARY KEY (`out_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `outpackage`
--

LOCK TABLES `outpackage` WRITE;
/*!40000 ALTER TABLE `outpackage` DISABLE KEYS */;
/*!40000 ALTER TABLE `outpackage` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sys_user`
--

DROP TABLE IF EXISTS `sys_user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `sys_user` (
  `uid` int(11) NOT NULL AUTO_INCREMENT,
  `user_name` varchar(45) DEFAULT NULL,
  `user_pw` varchar(45) DEFAULT NULL,
  `user_email` varchar(45) DEFAULT NULL,
  `user_permission` int(11) DEFAULT '0',
  PRIMARY KEY (`uid`),
  UNIQUE KEY `user_name_UNIQUE` (`user_name`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sys_user`
--

LOCK TABLES `sys_user` WRITE;
/*!40000 ALTER TABLE `sys_user` DISABLE KEYS */;
/*!40000 ALTER TABLE `sys_user` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2015-01-30 10:15:48
