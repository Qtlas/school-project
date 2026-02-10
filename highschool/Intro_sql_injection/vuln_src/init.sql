-- MariaDB dump 10.19  Distrib 10.11.6-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: vulndb
-- ------------------------------------------------------
-- Server version	10.11.6-MariaDB-2

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `post`
--

DROP TABLE IF EXISTS `post`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `post` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `author_name` varchar(64) DEFAULT NULL,
  `title` varchar(20) DEFAULT NULL,
  `content` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `post`
--

LOCK TABLES `post` WRITE;
/*!40000 ALTER TABLE `post` DISABLE KEYS */;
INSERT INTO `post` VALUES
(1,'admin','Hello world !','This is the first post !'),
(2,'jane_smith','New Day','Good morning! It\'s a beautiful new day, full of possibilities.'),
(3,'john_doe','First Post','Hello everyone! This is my first post on this platform.'),
(4,'mike_jackson','Tech Tip','Here\'s a useful tech tip I discovered recently.'),
(5,'sarah_adams','Beach Day','Spent an amazing day at the beach today. Feeling refreshed!'),
(6,'david_wilson','Latest News','Sharing some of the latest news updates I came across.'),
(7,'emily_taylor','New Recipe','Excited to share a delicious new recipe I tried out.'),
(8,'chris_anderson','Travel Experience','Just got back from an incredible trip. Can\'t wait to share my experiences!');
/*!40000 ALTER TABLE `post` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user`
--

DROP TABLE IF EXISTS `user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL,
  `email` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=22 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user`
--

LOCK TABLES `user` WRITE;
/*!40000 ALTER TABLE `user` DISABLE KEYS */;
INSERT INTO `user` VALUES
(1,'admin','password','admin@gmail.com'),
(2,'john_doe','password1','john.doe@example.com'),
(3,'jane_smith','password2','jane.smith@example.com'),
(4,'mike_jackson','password3','mike.jackson@example.com'),
(5,'sarah_adams','password4','sarah.adams@example.com'),
(6,'david_wilson','password5','david.wilson@example.com'),
(7,'emily_taylor','password6','emily.taylor@example.com'),
(8,'chris_anderson','password7','chris.anderson@example.com'),
(9,'laura_miller','password8','laura.miller@example.com'),
(10,'james_thompson','password9','james.thompson@example.com'),
(11,'emma_brown','password10','emma.brown@example.com'),
(12,'sam_robinson','password11','sam.robinson@example.com'),
(13,'olivia_carter','password12','olivia.carter@example.com'),
(14,'luke_harris','password13','luke.harris@example.com'),
(15,'sophia_wilson','password14','sophia.wilson@example.com'),
(16,'jacob_jones','password15','jacob.jones@example.com'),
(17,'ava_martin','password16','ava.martin@example.com'),
(18,'noah_thomas','password17','noah.thomas@example.com'),
(19,'mia_taylor','password18','mia.taylor@example.com'),
(20,'william_white','password19','william.white@example.com'),
(21,'oliver_clark','password20','oliver.clark@example.com');
/*!40000 ALTER TABLE `user` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2024-04-18 22:58:34
