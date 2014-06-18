import socket, time
import getpass
import os, sys
import random
from random import getrandbits
import hashlib
import Crypto
from Crypto.Cipher import Blowfish
from base64 import b64encode, b64decode

def envoi(msg):
    time.sleep(0.2)
    msg = msg.encode()
    connexion_avec_serveur.send(msg)

def recept():
    msg = connexion_avec_serveur.recv(1024)
    msg = msg.decode()
    return msg

def sha1(pwd):
    pwd = pwd.encode('utf-8')
    m = hashlib.sha1()
    m.update(pwd)
    return(m.hexdigest())

def pwd(p):
    string = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    pw_length = p
    key = ""

    for i in range(pw_length):
        next_index = random.randrange(len(string))
        key = key + string[next_index]
    
    return(key)

def get_mac():
    ipconfig = os.popen('ipconfig /all').readlines()
    for line in ipconfig:
        if 'physique' in line.lower():
           var = line.split(':')[1].strip().encode('utf-8')
           m = hashlib.md5()
           m.update(var)
           return m.hexdigest()
           break

def DH (client, server):
    g = 2
    prime = 7919
    bits = 32

    ####a = getrandbits(bits)  Import from Server
    A = pow(g, client, prime)

    #b = getrandbits(bits)      Export to Server
    B = pow(g, server, prime)

    s1 = pow(A, server, prime)
    s2 = pow(B, client, prime)

    if(s1 == s2):
        s1 = str(s1).encode('utf-8')
        m = hashlib.md5()
        m.update(s1)
        return m.hexdigest()

def blowfish(plaintext,key):
        
    if len(plaintext)%8 != 0:
        multiple = len(plaintext)%8
        for i in range(8 - multiple):
            plaintext += " "
            


    c1 = Blowfish.new(key, Blowfish.MODE_ECB)
    msg_e = c1.encrypt(plaintext)
    return msg_e

    
#connexion_avec_serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#connexion_avec_serveur.connect(('10.0.0.1', 12800))

print ("""**************************************************
   _______               _______           __ 
  |     __|.-----.-----.|   |   |.-----.--|  |
  |__     ||  _  |__ --||       ||  -__|  _  |
  |_______||_____|_____||__|_|__||_____|_____|

**************************************************

****SOSMED CLI****""")

client_connecte = True

while client_connecte:

    loop = 1
    state = "B"
    auth = True
    privilege = False
    PA = True
    cpt = 0

    connexion_avec_serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connexion_avec_serveur.connect(('127.0.0.1', 12800))

    #### Blacklist####################################################
    envoi(state)
    envoi(get_mac())
    blacklist = recept()
    if blacklist == "unauthorized":
        print("Vous êtes Black-list par le serveur")
        break
    else :
        state = "A"
    
    ###Authentification###############################################
    while auth:
        envoi(state)
        cpt = recept()
        if cpt == "stop":
            print("SosMed> Tentative de connexion excessive")
            connexion_avec_serveur.close()
            break  
        login = input("SosMed>login : ")
        password = getpass.getpass("SosMed>Password : ")
        while login == "" or password == "":
            print("SosMed> Les arguments ne peuvent etre nuls")
            login = input("SosMed>login : ")
            password = getpass.getpass("SosMed>Password : ")
        envoi(login)
        ####Chiffrement password
        DH_num_client = str(getrandbits(32))
        envoi(DH_num_client)
        DH_num_server = recept()
        DH_key = DH(int(DH_num_client),int(DH_num_server))
        password_e = blowfish(password,DH_key)
        time.sleep(0.1)
        connexion_avec_serveur.send(password_e)
        auth_match = recept()
        if auth_match == "match":
            auth = False
            state = "L"
            privilege = recept()

    if cpt == "stop":
        break
        
    ###Post-Authenfication###################################"
    while PA :
        cmd = input(login + "@SosMed>")
        while cmd == "":
            cmd = input(login + "@SosMed>")
        cmd = cmd.split()

        ##### Fonction EXIT
        if cmd[0].upper() == "EXIT":
            envoi(state)
            envoi("EXIT")
            envoi(login)
            right = recept()
            client_connecte = False
            break

        ##### Fonction LOGOUT
        if cmd[0].upper() == "LOGOUT":
            envoi(state)
            envoi("LOGOUT")
            envoi(login)
            right = recept()
            client_connecte = True
            break

        ###### Fonction GenPass
        elif cmd[0].upper() == "GENPASS" and privilege.upper() == "A":
            passwd, salt = pwd(12), pwd(1)
            print(login + "@SosMed>", passwd)
            print(login + "@SosMed>", sha1(passwd + salt), "salt:", salt)


        ###### Fonction Ajouter
        elif cmd[0].upper() == "ADD" and privilege.upper() == "A":
            envoi(state)
            envoi(cmd[0])
            envoi(login)
            loop = 1
            right = recept()
            if right != "A":
                print(login + "@SosMed> Vous n'avez pas l'authorisation")
                continue
            msgClient1=input(login + "@SosMed>login : ")
            envoi(msgClient1)
            while loop == 1:
                c = input(login + "@SosMed>Voulez vous générer un password ? (O)ui, (N)on : ")
                if c.upper() == "O" :
                    passwd, salt = pwd(12), pwd(1)
                    time.sleep(1)
                    envoi(salt)
                    time.sleep(1)
                    envoi(sha1(passwd + salt))
                    time.sleep(1)
                    ok = 0 
                    while ok == 0:
                        c = input(login + "@SosMed>Quel privilege? (A)dministrateur, (U)ser : ")
                        if c.upper() == "A" or c.upper() == "U":
                            ok = 1
                        else :
                            print(login + "@SosMed>Erreur de selection de privilege")
                    envoi(c)
                    print(login + "@SosMed>", passwd)
                    while loop == 1:
                        validation = input(login + "@SosMed>Confirmer l'opération ? ((O)ui/(N)on :")
                        if validation.upper() == "O":
                            envoi(validation)
                            print(login + "@SosMed>-=Utilisateur crée=-")
                            loop = 0
                        elif validation.upper() == "N":
                            print (login + "@SosMed>Opération annulée")
                            loop = 0
                        else:
                            print(login + "@SosMed>Répondre (O)ui or (N)on ")
                elif c.upper() == "N" :
                    msgClient2=input(login + "@SosMed>password : ")
                    passwd, salt = msgClient2, pwd(1)
                    time.sleep(1)
                    envoi(salt)
                    time.sleep(1)
                    envoi(sha1(passwd + salt))
                    time.sleep(1)
                    c = input(login + "@SosMed>Quel privilege? (A)dministrateur, (U)ser : ")
                    envoi(c)
                    while loop == 1:
                        validation = input(login + "@SosMed>Confirmer l'opération ? ((O)ui/(N)on :")
                        if validation.upper() == "O":
                            envoi(validation)
                            loop = 0
                        elif validation.upper() == "N":
                            print (login + "@SosMed>Opération annulée")
                            loop = 0
                        else:
                            print(login + "@SosMed>Répondre (O)ui or (N)on ")

                    print(login + "@SosMed>-=Utilisateur crée=-")  
                else :
                    print(login + "@SosMed>-=choix invalide=-")

            ###### fonction Consulter
        elif cmd[0].upper() == "SELECT" and privilege.upper() == "A":
            envoi(state)
            envoi(cmd[0])
            envoi(login)
            right = recept()
            try :
                 cmd[1]
                 envoi(cmd[1])
            except :
                envoi("*")
            BDD = recept()
            msgServer0 = ""
            loop = 1
            if right != "A":
                print(login + "@SosMed> Vous n'avez pas l'authorisation")
                continue
            if BDD == "NOK":
                print(login + "@SosMed> Aucun enregistrement !")
                continue
            else :
                
                print ("""+----------------+-------------------------------------------------+
|    Login       |                   Password                      |
+----------------+-------------------------------------------------+    """)
                while loop == 1:
                     msgServer0=recept()
                     if msgServer0 == "FIN":
                         loop = 0
                     else:
                         print (msgServer0)

        ###### fonction Supprimer
        elif cmd[0].upper() == "DELETE" and privilege.upper() == "A":
            envoi(state)
            envoi(cmd[0])
            envoi(login)
            right = recept()
            loop = 1
            if right != "A":
                print(login + "@SosMed>Vous n'avez pas l'authorisation")
                continue
            time.sleep(0.05)
            try :
                cmd[1]
            except :
                print(login + "@SosMed>Argument (login) manquant")
                continue
            else :
                envoi(cmd[1])
                ok = recept()
                if ok == "OK":
                    while loop == 1:
                            validation = input(login + "@SosMed>Confirmer l'opération ? ((O)ui/(N)on :")
                            if validation.upper() == "O":
                                envoi(validation)
                                print(login + "@SosMed>-=Utilisateur supprimé=-")
                                loop = 0
                            elif validation.upper() == "N":
                                envoi(validation)
                                print (login + "@SosMed>Opération annulée")
                                loop = 0
                            else:
                                print(login + "@SosMed>Répondre (O)ui or (N)on ")
                else:
                    print(login + "@SosMed>Login inexistant")

        ###### fonction Modifier (admin)
        elif cmd[0].upper() == "UPDATE" and privilege.upper() == "A":
            loop = 1
            envoi(state)
            envoi(cmd[0])
            envoi(login)
            right = recept()
            if right != "A":
                print(login + "@SosMed>Vous n'avez pas l'authorisation")
                continue
            time.sleep(0.05)
            try :
                cmd[1] #login
                cmd[2] # pass
            except :
                print(login + "@SosMed>Argument manquant (ex : update login new_hash")
                continue
            else :
                envoi(cmd[1])
                time.sleep(0.05)#####
                ok = recept()
                if ok == "OK":
                    password = cmd[2]
                    salt = pwd(1)
                    envoi(sha1(password + salt))
                    time.sleep(0.05)
                    envoi(salt)
                    while loop == 1:
                            validation = input(login + "@SosMed>Confirmer l'opération ? ((O)ui/(N)on :")
                            if validation.upper() == "O":
                                envoi(validation)
                                print(login + "@SosMed>-=Utilisateur modifié=-")
                                loop = 0
                            elif validation.upper() == "N":
                                print (login + "@SosMed>Opération annulée")
                                loop = 0
                            else:
                                print(login + "@SosMed>Répondre (O)ui or (N)on ")
                else:
                    print(login + "@SosMed>Login inexistant")


        ###### fonction Modifier (client)
        elif cmd[0].upper() == "UPDATE" and privilege.upper() == "U":
            loop = 1
            try :
                cmd[1] 
                cmd[2]
            except :
                print(login + "@SosMed>Argument manquant (ex : update login new_pass)")
                continue
            else :
                if cmd[1] == login:  
                    envoi(state)
                    envoi(cmd[0])
                    envoi(login)
                    right = recept()
                    password = cmd[2]
                    salt = pwd(1)
                    envoi(sha1(password + salt))
                    time.sleep(0.05)
                    envoi(salt)
                    while loop == 1:
                            validation = input(login + "@SosMed>Confirmer l'opération ? ((O)ui/(N)on :")
                            if validation.upper() == "O":
                                envoi(validation)
                                print(login + "@SosMed>-=Utilisateur modifié=-")
                                loop = 0
                            elif validation.upper() == "N":
                                print (login + "@SosMed>Opération annulée")
                                loop = 0
                            else:
                                print(login + "@SosMed>Répondre (O)ui or (N)on ")

                else:
                    print(login + "@SosMed>Le login ne correspond pas à votre login")

        elif cmd[0].upper() == "--HELP" and privilege.upper() == "A":
             print ("""--help : ensembles des commandes
  select : afficher BDD (deux args. Ex : select (cmd). (select *) par défaut)
  update : modifier des valeurs (deux args. Ex : update login newpass)
  add    : ajouter une entrée dans la base utilisateurs
  delete : supprimer users dans la base (deux args. Exemple : delete (login))
  GenPass: Génère un password hashé
  exit :   sortir""")

        elif cmd[0].upper() == "--HELP" and privilege.upper() == "U":
            print ("""--help : ensembles des commandes
  modpwd : Modifier le mot de passe (un arg. Ex : modpwd new_password)""")
        
        ###### Choix invalide
        else :
            print(login + "@SosMed>Commande invalide, Tapez '--help' pour plus d'informations")



            
print ("SosMed> fermeture de la connexion")
os.system("pause")
