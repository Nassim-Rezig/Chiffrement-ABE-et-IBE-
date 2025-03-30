import hashlib
import json
from pypbc import Parameters, Pairing, Element

# -------------------------------------------------------------------------
# Initialisation globale (à réaliser une seule fois, par exemple lors du
# démarrage de l'application ou lors de la configuration)
# -------------------------------------------------------------------------

# Exemple de paramètres pour une courbe de type A (pour illustration).
# Dans une vraie application, utilisez des paramètres sûrs et validés.
PARAMS = """type a
q 107
h 2
r 53
exp2 6
exp1 3
sign1 1
sign0 -1
"""


parameters = Parameters(param_string=PARAMS)
pairing = Pairing(parameters)
Q = Element.random(pairing, type=Element.G1)
    



# Génération de la clé maître (master secret) dans Zr
# Note : en pratique, cette clé doit être générée une fois et stockée en sécurité.
master_secret = Element.random(pairing, type=Element.Zr)
# Calcul de la clé publique maître : P_pub = Q * master_secret
master_public = Q * master_secret

# -------------------------------------------------------------------------
# Fonctions utilitaires pour IBE
# -------------------------------------------------------------------------

def hash_to_G1(identity):
    """
    Mappe une chaîne (ici l'email) vers un élément de G1 à l'aide d'un hash.
    """
    h = hashlib.sha256(identity.encode()).digest()
    # Convertir le hash en entier et le réduire modulo l'ordre (order) de l'appariement
    x = int.from_bytes(h, byteorder="big") % pairing.order
    # On retourne Q multiplié par x
    return Q * x

def ibe_encrypt(plaintext, identity):
    """
    Chiffre un message (ici le numéro d'assurance) en IBE en utilisant l'email
    comme identité.
    Le schéma réalisé ici est une version simplifiée du Boneh-Franklin.
    """
    # Convertir le message en bytes (s'il ne l'est pas déjà)
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # 1. Dériver l'élément associé à l'identité
    Q_id = hash_to_G1(identity)
    
    # 2. Choisir un aléa r dans Zr
    r = Element.random(pairing, type=Element.Zr)
    
    # 3. Calculer U = r * Q (partie "publique" du chiffrement)
    U = Q * r
    
    # 4. Calculer l'appariement e(P_pub, Q_id) et l'élever à la puissance r
    pairing_result = pairing.apply(master_public, Q_id) ** r
    
    # 5. Dériver une clé symétrique à partir du résultat de l'appariement
    # Ici, nous utilisons SHA-256 (pour une vraie application, pensez à un KDF robuste)
    k = hashlib.sha256(str(pairing_result).encode('utf-8')).digest()
    
    # 6. Chiffrer le message par un XOR simple (limité à la taille de k)
    # Pour un message plus long, il faudrait utiliser un chiffrement symétrique adapté.
    ciphertext_bytes = bytes(a ^ b for a, b in zip(plaintext, k))
    
    # 7. Sérialiser U (par exemple en utilisant sa représentation en chaîne)
    U_serialized = U.__str__()
    
    # Le ciphertext est composé de U et du message chiffré
    return {"U": U_serialized, "ciphertext": ciphertext_bytes.hex()}

def serialize_ciphertext(ciphertext):
    """
    Sérialise le dictionnaire du ciphertext pour le stocker, par exemple en JSON.
    """
    return ciphertext