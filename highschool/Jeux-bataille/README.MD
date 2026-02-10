<h1> Rapport de projet </h1>

<h2> Introduction :</h2>

<p>Dans le cadre de notre projet en NSI, nous avons modélisé le jeu de Bataille en utilisant le langage de programmation Python et en utilisant la Programmation Orientée Objet. </p>

<h2> Analyse du Problème Posé :</h2>

<p> La Bataille possède des règles précises, on a dû le modéliser : </p>

<ul>
  <li><strong>Joueurs :</strong> Deux joueurs, ayant chacun un paquet de cartes.</li>
  <li><strong>52 Cartes :</strong> Un jeu de 52 cartes, divisé entre les joueurs.</li>
  <li><strong>Paquet de Joueur :</strong> Chaque joueur possède un paquet de cartes, où l'on peut tirer et ajouter des cartes.</li>
  <li><strong>Carte :</strong> Les cartes du jeu, codées une valeur et une figure.</li>
  <li><strong>Partie :</strong> La gestion du déroulement du jeu, des batailles et de la fin de la partie.</li>
</ul>

<p>Grâce à cette analyse on a pu travailler et diviser le projet en plusieurs classes dont chaque personne du groupe a été attribuée :</p>

<li> Partie/Graphique </li>
<li> JeuCartes </li>
<li> Joueur et Cartes </li>
<li> Paquet </li>


<h2> Solutions Proposées :</h2>

<h3> Carte :</h3>

<p>La classe <code>Carte</code> a été créée pour représenter les cartes du jeu. Chaque carte est définie par une valeur et une figure. Et il y a notamment une méthode afficher qui avec la valeur et la famille renvoie une image de la carte associée.</p>
<h3> Paquet :</h3>

<p>La classe <code>Paquet</code> gère les opérations que l’on fait sur le paquet. Elle utilise une file pour stocker les cartes et possède des méthodes pour ajouter une carte au paquet, obtenir la taille du paquet et afficher le paquet.</p>

<h3> JeuCartes :</h3>

<p>La classe <code>JeuCartes</code> représente l'ensemble du jeu de cartes. Elle initialise les 52 cartes, avec une liste par compréhension, et offre une méthode pour mélanger le jeu.</p>


<h3> Player :</h3>

<p>La classe <code>Player</code> représente un joueur avec un nom et un paquet de cartes. Elle offre une méthode pour tirer une carte du paquet.</p>


<h3> Game :</h3>

<p>La classe <code>Game</code> Organise le déroulement du jeu. Elle initialise le jeu en créant un jeu de cartes, distribue les cartes aux joueurs, gère les batailles, détermine le gagnant de la partie et gère toute la partie graphique.</p>

<h3> Graphique : </h3>
<p>A l'aide de la librairie <a href=https://www.pygame.org/news>pygame</a> nous avons pu modéliser le jeu en graphique à l'aide d'images de carte. </p>

<h3> Travaille en equipe et deroulement du projet : </h3>
<ul>
  <li> <p><strong>1er Jeudi </strong>: Le premier jeudi nous a permit de poser le problemme et le diviser en plusieurs petits problemmes que nous avons pue modeliser ensemble avec la programmation oriente objet, et se diviser donc les taches comme enoncer precedemment.</p> </li>
  <li> <p> <strong>2eme Jeudi</strong> : Lors du deuxiemme Jeudi nous avons commencer a parler de code en python et avons reflechie a differentes maniere d'implementer la modelisation en python, et avons finie de structurer le jeu.</p></li>
  <li> <p> <strong>3eme Jeudi </strong> : Pour le 3 eme regroupement nous avons mit en communs nos differents code et avons ajuster certaines lines de codes pour la liaisons entres les differentes Class et avons debuter une partie graphique.</p> </li>
  <li> <p> <strong>4 eme Jeudi </strong> : Lors de l'avant dernier Jeudi nous avions finaliser le code et commencer a parler du rapport et de la presentation orale du projet.
  <li> <p> <strong> Dernier Jeudi </strong> : Presentation a l'orale et remit du rapport ecris.
</ul>

<h2> Conclusion :</h2>

<p> Ce projet nous a permis d’utiliser la PPO dans un contexte réel. La modélisation des différents éléments de la Bataille nous a permis d’apprendre à structurer un projet efficacement et à travailler en groupe en se répartissant les tâches. </p>


<h2> Lien vers le Code :</h2>

<p> Le code complet du projet est disponible sur notre <a href=https://github.com/QtlasPy/Jeux-bataille> dépôt GitHub </a>.</br>
<strong> Pygame requis : <a href=https://pypi.org/project/pygame/>Installer pygame </a> </p>
