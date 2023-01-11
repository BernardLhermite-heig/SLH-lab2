# SLH - Labo 2

### Auteur : Stéphane Marengo

# Mise en place

Les variables `SMTP_USERNAME`, `SMTP_PASS`, `OAUTH_ID` et `OAUTH_SECRET` doivent être définies dans le fichier `.env` à la racine du projet.

Les autres variables peuvent être modifiées si besoin mais cela n'est à priori pas nécessaire.

# Remarques

L'expiration du token permettant la vérification d'un compte n'a pas été gérée. En production il faudrait mettre en place un système permettant de renvoyer un email de confirmation de compte si le token a expiré.

Le secret fourni dans le fichier `.env` utilisé pour la génération du token JWT n'est clairement pas assez complexe.

Lorsqu'un utilisateur tente de s'authentifier en utilisant OAuth et qu'un compte est déjà associé à son email, une erreur 401 est renvoyée. En production, il faudrait le rediriger sur la page de connexion avec un message lui indiquant qu'il existe déjà un compte associé à son email ou mettre en place un système permettant de fusionner les deux.