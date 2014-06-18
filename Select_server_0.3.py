import socket, sys, time, datetime,os
import select
import sql
from random import getrandbits
import random
import hashlib
import Crypto
from Crypto.Cipher import Blowfish
from base64 import b64encode, b64decode

def recept():
    msg = client.recv(1024)
    msg = msg.decode()
    return msg

def envoi(msg):
    time.sleep(0.2)
    msg = msg.encode()
    client.send(msg)

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

def DH (client, server):
    g = 2
    prime = 7919
    bits = 32

    #######a = getrandbits(bits)   To export to Client
    A = pow(g, client, prime)

    #######b = getrandbits(bits)   To import from Client
    B = pow(g, server, prime)

    s1 = pow(A, server, prime)
    s2 = pow(B, client, prime)

    if(s1 == s2):
        s1 = str(s1).encode('utf-8')
        m = hashlib.md5()
        m.update(s1)
        return m.hexdigest()


def blowfish(plaintext,key):
    c1 = Blowfish.new(key, Blowfish.MODE_ECB)
    msg_d = c1.decrypt(plaintext)
    msg_d = msg_d.decode('utf-8')
    msg_d = msg_d.replace(" ","")
    return msg_d

hote = ''
port = 12800

connexion_principale = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connexion_principale.bind((hote, port))
connexion_principale.listen(5)
print("----Serveur demarre sur le port {}----".format(port))


counter = 0
auth = True
serveur_lance = True
clients_connectes = []

while serveur_lance:
    # On va vérifier que de nouveaux clients ne demandent pas à se connecter
    # Pour cela, on écoute la connexion_principale en lecture
    # On attend maximum 50ms
    connexions_demandees, wlist, xlist = select.select([connexion_principale],
        [], [], 0.05)
    
    for connexion in connexions_demandees:
        connexion_avec_client, infos_connexion = connexion.accept()
        # On ajoute le socket connecté à la liste des clients
        clients_connectes.append(connexion_avec_client)
    
    # Maintenant, on écoute la liste des clients connectés
    # Les clients renvoyés par select sont ceux devant être lus (recv)
    # On attend là encore 50ms maximum
    # On enferme l'appel à select.select dans un bloc try
    # En effet, si la liste de clients connectés est vide, une exception
    # Peut être levée
    clients_a_lire = []
    try:
        clients_a_lire, wlist, xlist = select.select(clients_connectes,
                [], [], 0.05)
    except select.error:
        pass
    else:
        # On parcourt la liste des clients à lire
        for client in clients_a_lire:

            now = datetime.datetime.now()
            state = recept()
            
            #### Blacklist#########################################################
            if state == "B":
                blacklist_MAC = recept()
                blacklist_IP = str(infos_connexion).split(",")
                file = open('black_list.txt','r')
                for line in file:
                    if blacklist_IP[0].replace("(","") in line or blacklist_MAC in line:
                        resultat = "unauthorized"
                        break
                    else:
                        resultat = "authorized"     
                envoi(resultat) 
                file.close()
                file = open('log_SosMed.txt','a')
                log = (str(datetime.date.today()), " |",str(now.hour),":", str(now.minute), ":", str(now.second) ,"| ", str(infos_connexion)," | Action = Black_list_test. ",blacklist_IP[0].replace("(","")," | Resultat = ",resultat, "\n")
                file.writelines(log)
                file.close()

                
            ####A (Authentification) condition####################################
            if state == "A":
                file = open('log_SosMed.txt','r')
                counter = 0
                for line in file:
                    rule = line.split("|") ; rule_hours = rule[1].split(":") ; rule_minute = int(rule_hours[1])
                    if now.hour == int(rule_hours[0]) and ((now.minute - rule_minute) <= 1 and "Action = login" in line and rule[0] == str(datetime.date.today())):
                        counter = counter + 1
                    if counter == 10:
                        file = open('black_list.txt','a')
                        log = (blacklist_IP[0].replace("(",""), " : " ,blacklist_MAC,"\n")
                        file.writelines(log)
                        file.close()
                        counter_str = "stop"
                        envoi(counter_str)
                        
                        break
                    else:
                        counter_str = "run"
                if counter_str == "stop":
                    break
                envoi(counter_str)
                login = recept()
                #####Déchiffrement password
                DH_num_server = str(getrandbits(32))
                envoi(DH_num_server)
                DH_num_client = recept()
                DH_key = DH(int(DH_num_client),int(DH_num_server))
                password_e = client.recv(1024)
                password_d = blowfish(password_e,DH_key)
                BDD_auth = sql.select(login)
                try :
                    BDD_auth[0][3]
                except :
                    resultat = "error login"
                    envoi("nomatch")
                else :
                    if (sha1(password_d + BDD_auth[0][2])) == (BDD_auth[0][1]):
                        resultat = "match"
                        envoi(resultat)
                        envoi(BDD_auth[0][3])
                        log = (str(datetime.date.today()), " |",str(now.hour),":", str(now.minute), ":", str(now.second) ,"| ", str(infos_connexion)," | Action = login. (", login , ",", BDD_auth[0][3] , ") | Resultat = ",resultat, "\n")
                    else:
                        resultat = "nomatch"
                        envoi(resultat)
                        log = (str(datetime.date.today()), " |",str(now.hour),":", str(now.minute), ":", str(now.second) ,"| ", str(infos_connexion)," | Action = login. (", login , ") | Resultat = ",resultat, "\n")
                file = open('log_SosMed.txt','a')
                file.writelines(log)
                file.close()

            ####L (Logon) condition#####################################################        
            if state == "L":
                file = open('log_SosMed.txt','a')
                cmd = recept()
                login = recept()
                BDD_right = sql.select(login)
                envoi(BDD_right[0][3])
                
                ####Exit de l'utilisateur et inscription dans le fichier log####
                if cmd.upper() == "EXIT":
                    log = (str(datetime.date.today()), " |",str(now.hour),":", str(now.minute), ":", str(now.second) ,"| ", str(infos_connexion)," | Action = Connexion OFF. (", login, ")\n")
                    file.writelines(log)
                    file.close()
                    break

                ####Logout de l'utilisateur et inscription dans le fichier log####
                if cmd.upper() == "LOGOUT":
                    log = (str(datetime.date.today()), " |",str(now.hour),":", str(now.minute), ":", str(now.second) ,"| ", str(infos_connexion)," | Action = Logout. (", login, ")\n")
                    file.writelines(log)
                    file.close()
                    break

                #### fonction Ajouter
                elif cmd.upper() == "ADD" and BDD_right[0][3] =="A":
                    msgClient0=recept()  # login
                    msgClient1=recept()   #salt
                    msgClient2=recept()   # sha1
                    msgClient3=recept()   # privilege
                    validation=recept()  # Validation
                    if validation.upper() == "O":
                        sql.insert(msgClient0, msgClient2, msgClient1, msgClient3)


                #### fonction Consulter
                elif cmd.upper() == "SELECT" and BDD_right[0][3] == "A":
                        msgClient0=recept()
                        msgServer0 = ""
                        BDD = sql.select(msgClient0)
                        if BDD == "Aucun enregistrement !" :
                            envoi("NOK")
                            continue
                        else :
                            envoi("OK")
                            for i in BDD:
                               msgServer0 = ("|    "+ i[0] + "              " +  i[1]  + "\n+----------------+-------------------------------------------------+")
                               envoi(msgServer0)
                               time.sleep(0.05)
                            msgServer1="FIN"
                            envoi(msgServer1)

                #### fonction Supprimer
                elif cmd.upper() == "DELETE" and BDD_right[0][3] == "A":
        
                        msgClient0=recept()
                        exist = sql.select(msgClient0)
                        try :
                            exist[0][3]
                        except :
                            envoi("NOK")
                            continue
                        else:
                            envoi("OK")
                            validation=recept()
                        
                            if validation.upper() == "O":
                                sql.delete(msgClient0)


                #### fonction Modifier (admin)
                elif cmd.upper() == "UPDATE" and BDD_right[0][3] == "A":
                        msgClient0=recept()
                        exist = sql.select(msgClient0)
                        try :
                            exist[0][3]
                        except :
                            envoi("NOK")
                            continue
                        else:
                            envoi("OK")
                            msgClient1=recept()
                            msgClient2=recept()
                            validation=recept()
                            if validation.upper() == "O":
                                sql.update(msgClient0,msgClient1,msgClient2)
                            
                #### fonction Modifier (client)
                elif cmd.upper() == "UPDATE" and BDD_right[0][3] == "U":
                        msgClient1=recept()
                        msgClient2=recept()
                        validation=recept()
                        if validation.upper() == "O":
                            sql.update(login,msgClient1,msgClient2)
            
                                                               

print("Fermeture des connexions")
for client in clients_connectes:
    client.close()

connexion_principale.close()
