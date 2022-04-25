
```
  $$$$$$\ $$$$$$$$\ $$$$$$$\
 $$  __$$\\__$$  __|$$  __$$\
 $$ /  \__|  $$ |   $$ |  $$ |
 $$ |$$$$\   $$ |   $$ |  $$ |
 $$ |\_$$ |  $$ |   $$ |  $$ |
 $$ |  $$ |  $$ |   $$ |  $$ |
 \$$$$$$  |  $$ |   $$$$$$$  |
  \______/   \__|   \_______/
```

##### Index
* [Vue générale](#ov)
    * [Cas d'utilisation standard](#ov-usecase)
* [Getting started](#gs)
    * [Préparation de Git Tug Deployer](#gs-gtd)
    * [Préparation du dépôt](#gs-repository)
        * [BitBucket](#gs-repository-bitbucket)
    * [Préparation du serveur](#gs-server)
        * [Systemd](#gs-server-systemd)
        * [Crontask](#gs-server-crontask)

<a name="ov" />

# Vue générale

**Git Tug Deployer (GTD) permet d'automatiser le déploiement
du code poussé sur un un dépôt Git.**

<a name="ov-usecase" />

## Cas d'utilisation standard

1. Un développeur réalise des modifications ;
2. Il `commit` puis `push` ses modifications sur une branche donnée d'un dépôt BitBucket ;
3. Lorsque le serveur de BitBucket reçoit le `commit`, ce dernier appelle un URL pré-configuré : l'URL de GTD ;
4. GTD vérifie si les métadonnées du `commit` correspondent bien à celles requises dans la configuration ;
5. Si c'est le cas, deux options :
    * Le `daemon` est configuré.

      Dans ce cas GTD marque la requête de déploiement.
      Un worker de type crontâche ou tâche de fond vérifie régulièrement ce marquage,
      et lorsqu'il est positif, réalise le déploiement en effectuant un `git pull` dans le répertoire
      de travail du serveur ;

    * Le `daemon` n'est pas configuré.

      Dans ce cas, GTD tente directement un `git pull`.

**Avantage et désavantages du `daemon` :**

* Exécute le `git pull` avec les droits utilisateur déterminés, au lieu du seul `www-data` de PHP ;
* Gère les commits lourds et longs ;
* En revanche, nécessite de configurer une crontâche et/ou de paramétrer
    `systemd` pour activer la tâche de fond ;

<a name="gs" />

# Getting started

<a name="gs-gtd" />

## Préparation de Git Tug Deployer

1. **Télécharger** [l'archive du dépôt GTD](https://github.com/d4w33d/GitTugDeployer/archive/refs/heads/main.zip)
2. **Décompresser** l'archive au sein du dossier de travail du projet
    (aka quelque part dans l'arborescence du dépôt, par exemple à la racine)
3. Copier `config-sample.ini` vers **`config.ini`**
4. Dans `config.ini`, éditer (au minimum) ces paramètres :
    * **`repository.root_directory`** : indiquer le chemin valide vers la racine ;
    * **`security.hook_keys[]`** : renseigner une chaîne aléatoire (alpha-numérique et symboles) de 64 caractères sur chaque ligne ;
    * **`daemon.enabled`** : `on` ou `off` en fonction du choix effectué plus haut ;
    * **`git.use_ssh_key`** : indiquer le chemin valide vers la clef privée SSH
        qui est autorisée en lecture seule sur BitBucket ou Github
        (dont la clef publique aura été paramètres dans la configuration du dépôt) ;
    * **`git.branch`** : vérifier le nom de la branche qui doit être écoutée.
        Généralement "master" ou "main" en production, et "staging" ou "preprod" en pré-production.
    * **`web.login[]`** : indiquer un nom d'utilisateur et un mot de passe qui permettront d'accéder au panneau de contrôle.
5. Finalement, **déployer ces modifications** sur le dépôt (`git commit` et `git push`) ;
6. Pour vérifier que tout fonctionne correctement, vous pouvez accéder à la console en pointant
    sur le répertoire dans lequel vous avez décompressé GTD : http{s}://{racine}/{du}/{projet}/gtd,
    et en utilisant les identifiants de connexion indiqués dans `web.login[]`.

<a name="gs-repository" />

## Préparation du dépôt

<a name="gs-repository-bitbucket" />

### BitBucket

* Assurez vous qu'une clef SSH a bien été configurée sur BitBucket, dans
    ***Repository settings*** >> ***Access keys*** ;
* Dans la console GTD, récupérez l'un des liens de type `Silent` (clic-droit, Copier l'adresse du lien) ;
* Sur BitBucket, dans ***Repository settings*** >> ***Webhooks***, créez un nouveau Hook,
    en laissant les options par défaut et en renseignant un titre et l'URL copié dans l'étape précédente ;

<a name="gs-server" />

## Préparation du serveur

Si le `daemon` n'est pas activé, il n'y a aucune action spécifique à réaliser
sur le serveur.

Si le `daemon` est activé :

<a name="gs-server-systemd" />

### Systemd

Systemd est le système de gestion de tâches de fond (services) installé par défaut
sur les distributions Linux basées sur Debian et Fedora.

Pour activer la tâche de fond de GTD, exécuter la commande suivante :

```
$ {absolute_path_to_web_root}/gtd/gtd daemon enable
```

Pour désactiver la tâche, utiliser la commande inverse :

```
$ {absolute_path_to_web_root}/gtd/gtd daemon disable
```

S'il n'est pas possible d'utiliser systemd, il est également possible de lancer
la commande suivante dans un `screen` :

```
$ {absolute_path_to_web_root}/gtd/gtd daemon watch
```

Si la branche indiquée dans le fichier de configuration est une variable d'environnement,
il faut dans ce cas préciser spécifiquement la branche que l'on souhaite écouter, dans la commande :

```
$ GTD_DAEMON_GIT_BRANCH={listened_branch_name} {absolute_path_to_web_root}/gtd/gtd daemon watch
```

<a name="gs-server-crontask" />

### Crontask

Identifié comme utilisateur qui est en droit de réaliser le `git pull`,
exécuter la ligne de commande `$ crontab -e` :

L'écriture standard de la ligne crontask est :

```
* * * * * {absolute_path_to_web_root}/gtd/gtd cmd exec
```

Si la branche indiquée dans le fichier de configuration est une variable d'environnement,
il faut dans ce cas préciser spécifiquement la branche dans la commande :

```
* * * * * GTD_DAEMON_GIT_BRANCH={listened_branch_name} {absolute_path_to_web_root}/gtd/gtd cmd exec
```

Les lignes ci-dessus executent le démon chaque minute. C'est parfois trop peu,
notamment lors de sessions de débogage. Dans ce cas, il est possible de modifier légèrement
la crontask, en exécutant plusieurs fois le script, mais en le décalant d'un quart de minute.

Ainsi, la tâche est exécutée toutes les 15 secondes.

```
* * * * * sleep 15: {absolute_path_to_web_root}/gtd/gtd cmd exec
* * * * * sleep 30; {absolute_path_to_web_root}/gtd/gtd cmd exec
* * * * * sleep 45; {absolute_path_to_web_root}/gtd/gtd cmd exec
* * * * * sleep 60; {absolute_path_to_web_root}/gtd/gtd cmd exec
```
