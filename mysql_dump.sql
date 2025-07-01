DROP TABLE IF EXISTS programme_demande;
DROP TABLE IF EXISTS user;

CREATE TABLE user (
  id INT NOT NULL AUTO_INCREMENT,
  prenom VARCHAR(100) NOT NULL,
  nom VARCHAR(100) NOT NULL,
  email VARCHAR(120) NOT NULL,
  password VARCHAR(256) NOT NULL,
  is_admin BOOLEAN DEFAULT 0,
  confirmed BOOLEAN DEFAULT 0,
  PRIMARY KEY (id),
  UNIQUE (email)
);

INSERT INTO user (id, prenom, nom, email, password, is_admin, confirmed) VALUES
(1, 'Amine', 'chabane', 'amine.chabane006@gmail.com', '$2b$12$esnwQodLEJfbqkgXozfkZu6sypEt3aZneCYdGBJsEC8TsZqh7zaeG', 1, 0),
(2, 'amine', 'chabane', 'francestrasbourg06@gmail.com', '$2b$12$r1ppLOn6y3ClviLKItME5us9J0HeQ/T9VQD2wsbYlnuP21ZtmaTSi', 0, 1);

CREATE TABLE programme_demande (
  id INT NOT NULL AUTO_INCREMENT,
  user_id INT NOT NULL,
  poids INT NOT NULL,
  taille INT NOT NULL,
  age INT NOT NULL,
  objectif VARCHAR(500) NOT NULL,
  type VARCHAR(100) NOT NULL,
  date DATETIME,
  fichier VARCHAR(200),
  PRIMARY KEY (id),
  FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

INSERT INTO programme_demande (id, user_id, poids, taille, age, objectif, type, date, fichier) VALUES
(1, 2, 80, 180, 23, 'Bonjour, mon objectif est de perdre du poids surtout au niveau du ventre, je fait du sport régulièrement environ 4 fois par semaine j''ai un niveau intermédiaire et je veux des excercie intense. Merci beaucoup', 'entrainement', '2025-06-27 07:02:23', 'chabane_1.pdf'),
(2, 2, 80, 180, 22, 'Mon objectif est de progresser et de gagner en masse musculaire, j''ai aussi un retard dans mes jambes que je voudrai récupérer je suis faiblee génétiquement la bas', 'entrainement', '2025-07-01 07:52:17', NULL);
