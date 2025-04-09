CREATE DATABASE IF NOT EXISTS wordpress;
CREATE USER IF NOT EXISTS 'wordpress'@'localhost' IDENTIFIED BY 'wordpress';
GRANT ALL PRIVILEGES ON wordpress.* TO 'wordpress'@'localhost';
FLUSH PRIVILEGES;
