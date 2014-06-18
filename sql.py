import sqlite3

fichierBDD = "SosMed_bdd.sq3"
connexion = sqlite3.connect(fichierBDD)

##Dialogue avec la base cree via un curseur
##Cursor() permet la creation d'un objet curseur interface, sorte de tampon memoire
#intermediaire qui contient les donnees en cours de traitement

def alter(column):
    # ajout d'une colonne
    curseur = connexion.cursor()
    curseur.execute("ALTER TABLE accounts ADD " + column + " VARCHAR(1)")
    connexion.commit() 
    curseur.close()

def insert(login, hash, salt, privilege):
    # ajout d'un accounts
    curseur = connexion.cursor()
    curseur.execute("INSERT INTO accounts(login, hash, salt,privilege) VALUES('" + login + "', '" + hash + "', '" + salt  + "', '" + privilege + "')")
    connexion.commit() # commit sert a transmettre les donnees du tampon curseur a la base de donnees
    curseur.close()

def select(login):
    # affichage de la base
    curseur = connexion.cursor()
    if login == "*":
        curseur.execute("SELECT * FROM accounts")
    else:
        curseur.execute("SELECT * FROM accounts WHERE login='" + login + "'")
    resultat = list(curseur)
    nb = len(resultat)
    if (nb):
        return(resultat)
    else:
        return("Aucun enregistrement !")
        curseur.close() 

def delete(login):
    # suppression d'un accounts
    curseur = connexion.cursor()
    curseur.execute("DELETE FROM accounts WHERE login='"+ login + "'")
    print (login)
    connexion.commit()
    curseur.close()
    

def update(login, n_hash, salt):
    # modification d'un accounts
    curseur = connexion.cursor()
    curseur.execute("UPDATE accounts SET hash='" + n_hash + "' , salt='" + salt + "' WHERE login='" + login + "'")
    connexion.commit()
    curseur.close()
    
def salt(login):
    # recuperation du salt
    curseur = connexion.cursor()
    curseur.execute("SELECT salt FROM accounts WHERE login='" + login + "'")
    resultat = list(curseur)
    return(resultat)
    curseur.close()

def count():
    # recuperation du nombre de ligne
    curseur = connexion.cursor()
    curseur.execute("SELECT COUNT(*) FROM accounts")
    resultat = list(curseur)
    return(resultat)
    curseur.close()
    
