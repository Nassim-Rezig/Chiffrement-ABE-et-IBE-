# crypto_utils.py

import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from charm.toolbox.pairinggroup import PairingGroup, GT

from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07

# --- Initialisation du schéma ABE ---
# On initialise le groupe de paires et le schéma CP-ABE.
group = PairingGroup('SS512')
cpabe = CPabe_BSW07(group)
public_key, master_key = cpabe.setup()

# Définition de la politique d'accès
policy = 'role:admin and service:assurance'

def derive_sym_key(m):
    """
    Dérive une clé symétrique de 16 octets à partir de l'élément m (de type GT)
    en appliquant SHA-256 sur sa sérialisation.
    """
    m_bytes = group.serialize(m)
    return hashlib.sha256(m_bytes).digest()[:16]

def encrypt_attribute(attribute_value):
    """
    Chiffre la valeur d'un attribut en utilisant une approche hybride :
      - Encapsulation de clé avec ABE : on chiffre un élément m aléatoire de GT.
      - Dérivation d'une clé symétrique via m.
      - Chiffrement symétrique (AES en mode CTR) de l'attribut.
    
    Renvoie un tuple composé de :
      - ciphertext : le texte chiffré obtenu par AES
      - abe_ciphertext : le ciphertext ABE de m
      - nonce : le nonce utilisé par AES (pour le déchiffrement)
    """
    # Génération d'un élément aléatoire m dans GT
    m = group.random(GT)
    # Dérivation de la clé symétrique à partir de m
    sym_key = derive_sym_key(m)
    
    # Chiffrement symétrique avec AES en mode CTR
    cipher_aes = AES.new(sym_key, AES.MODE_CTR)
    ciphertext = cipher_aes.encrypt(attribute_value.encode())
    nonce = cipher_aes.nonce

    # Chiffrement de m avec ABE (on encapsule m)
    abe_ciphertext = cpabe.encrypt(public_key, m, policy)

    return ciphertext, abe_ciphertext, nonce

def decrypt_attribute(ciphertext, abe_ciphertext, nonce, user_attributes):
    """
    Déchiffre la valeur d'un attribut pour un utilisateur possédant les attributs requis.
    
    Nécessite :
      - ciphertext : le texte chiffré obtenu par AES
      - abe_ciphertext : le ciphertext ABE contenant m encapsulé
      - nonce : le nonce utilisé lors du chiffrement AES
      - user_attributes : la liste des attributs de l'utilisateur pour le déchiffrement ABE
    
    Renvoie la valeur de l'attribut déchiffré sous forme de chaîne de caractères.
    """
    # Déchiffrement ABE pour récupérer m
    m = cpabe.decrypt(public_key, master_key, abe_ciphertext, user_attributes)
    # Dérivation de la même clé symétrique
    sym_key = derive_sym_key(m)
    
    # Déchiffrement symétrique avec AES en mode CTR
    cipher_aes = AES.new(sym_key, AES.MODE_CTR, nonce=nonce)
    plaintext = cipher_aes.decrypt(ciphertext).decode()
    return plaintext
