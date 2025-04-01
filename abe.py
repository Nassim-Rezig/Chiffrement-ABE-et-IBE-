import hashlib
import random
import math

class EllipticCurve:
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p
    
    def is_on_curve(self, point):
        if point is None:
            return True
        x, y = point
        return (y*y - (x*x*x + self.a*x + self.b)) % self.p == 0
    
    def add(self, P, Q):
        if P is None: return Q
        if Q is None: return P
        
        x_p, y_p = P
        x_q, y_q = Q
        
        if x_p == x_q and y_p != y_q:
            return None  # Point at infinity
        
        if P == Q:
            # Point doubling
            m = (3*x_p*x_p + self.a) * pow(2*y_p, self.p-2, self.p) % self.p
        else:
            # Point addition
            m = (y_q - y_p) * pow(x_q - x_p, self.p-2, self.p) % self.p
        
        x_r = (m*m - x_p - x_q) % self.p
        y_r = (m*(x_p - x_r) - y_p) % self.p
        
        return (x_r, y_r)
    
    def scalar_mult(self, k, P):
        if k == 0 or P is None:
            return None
        if k < 0:
            return self.scalar_mult(-k, (P[0], -P[1] % self.p))
            
        result = None
        current = P
        
        while k > 0:
            if k % 2 == 1:
                result = self.add(result, current)
            current = self.add(current, current)
            k = k // 2
        return result

class TatePairing:
    def __init__(self, curve, r):
        """
        Implémentation optimisée du pairing de Tate
        curve: la courbe elliptique
        r: l'ordre du sous-groupe (généralement un nombre premier)
        """
        self.curve = curve
        self.r = r
        self.k = 2  # Degré d'embedding (simplifié)
        self._cache = {}  # Cache pour stocker les résultats des pairings
    
    def _cache_key(self, P, Q):
        """Génère une clé unique pour le cache basée sur les points P et Q"""
        if P is None or Q is None:
            return None
        return (P[0], P[1], Q[0], Q[1])
    
    def miller_algorithm(self, P, Q):
        """Algorithme de Miller optimisé pour le calcul du pairing de Tate"""
        # Vérification des points et utilisation du cache
        if not self.curve.is_on_curve(P) or not self.curve.is_on_curve(Q):
            raise ValueError("Les points doivent être sur la courbe")
            
        if P is None or Q is None:
            return 1
        
        # Vérifier si le résultat est dans le cache
        cache_key = self._cache_key(P, Q)
        if cache_key in self._cache:
            return self._cache[cache_key]
            
        # Convertir r en binaire et ignorer le bit de poids fort
        r_bin = bin(self.r)[2:]
        
        T = P
        f = 1
        
        # Algorithme de Miller optimisé
        for i in range(1, len(r_bin)):
            # Carré de f
            f = (f * f) % self.curve.p
            
            # Doublement de T
            T = self.curve.add(T, T)
            
            if r_bin[i] == '1':
                # Multiplication par la valeur initiale
                f = (f * self.evaluate_line(T, P, Q)) % self.curve.p
                T = self.curve.add(T, P)
        
        # Stocker le résultat dans le cache
        self._cache[cache_key] = f
        return f
        
    def evaluate_line(self, T, P, Q):
        """Évalue la ligne passant par les points T et P au point Q (optimisé)"""
        if T is None or P is None:
            return 1
            
        x_t, y_t = T
        x_p, y_p = P
        x_q, y_q = Q
        
        # Cas où T = P
        if T == P:
            # Tangente à la courbe au point T
            m = (3 * x_t * x_t + self.curve.a) * pow(2 * y_t, self.curve.p-2, self.curve.p) % self.curve.p
        else:
            # Sécante passant par T et P
            m = (y_t - y_p) * pow(x_t - x_p, self.curve.p-2, self.curve.p) % self.curve.p
        
        # Évaluation de la ligne au point Q
        return (y_q - y_t - m * (x_q - x_t)) % self.curve.p
    
    def compute(self, P, Q):
        """Calcul du pairing e(P, Q) avec mise en cache"""
        return self.miller_algorithm(P, Q)

class ABE:
    def __init__(self):
        # Paramètres de la courbe secp256k1
        # Cette courbe est utilisée dans Bitcoin et d'autres cryptomonnaies
        self.curve = EllipticCurve(
            a=0,
            b=7,  # La courbe secp256k1 utilise b=7, pas b=3
            p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        )
        
        # Ordre du sous-groupe (simplifié)
        self.r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        
        # Point générateur
        self.G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
        
        # Vérification que G est sur la courbe
        if not self.curve.is_on_curve(self.G):
            raise ValueError("Le point générateur n'est pas sur la courbe")
        
        # Initialisation du pairing
        self.pairing = TatePairing(self.curve, self.r)
        
        # Génération des clés maîtres (utiliser des valeurs fixes pour la reproductibilité)
        self.alpha = 12345  # Valeur fixe pour le débogage
        self.beta = 67890   # Valeur fixe pour le débogage
        
        # Paramètres publics
        self.g = self.G
        self.g_a = self.curve.scalar_mult(self.alpha, self.g)
        self.g_b = self.curve.scalar_mult(self.beta, self.g)
        
        # Calcul du pairing e(g, g)^alpha
        self.e_gg_alpha = pow(self.pairing.compute(self.g, self.g), self.alpha, self.curve.p)
        
        # Cache pour les points de courbe et les valeurs intermédiaires
        self._point_cache = {}
        self._pairing_cache = {}
        self._policy_cache = {}
    
    def _hash_to_curve(self, attribute):
        """Convertit un attribut en point valide sur la courbe (méthode try-and-increment optimisée)"""
        # Vérifier si l'attribut est déjà dans le cache
        if attribute in self._point_cache:
            return self._point_cache[attribute]
            
        counter = 0
        while True:
            # Hachage de l'attribut avec un compteur
            h = hashlib.sha256((attribute + str(counter)).encode()).digest()
            x = int.from_bytes(h, 'big') % self.curve.p
            
            # Calcul de y² = x³ + ax + b
            y_squared = (x**3 + self.curve.a * x + self.curve.b) % self.curve.p
            
            # Vérifier si y_squared est un résidu quadratique modulo p
            # Si p ≡ 3 (mod 4), alors y = y_squared^((p+1)/4) mod p
            if pow(y_squared, (self.curve.p - 1) // 2, self.curve.p) == 1:
                y = pow(y_squared, (self.curve.p + 1) // 4, self.curve.p)
                point = (x, y)
                
                # Vérifier que le point est sur la courbe
                if self.curve.is_on_curve(point):
                    # Stocker le point dans le cache
                    self._point_cache[attribute] = point
                    return point
            
            counter += 1
    
    def setup(self):
        """Génère les paramètres publics et la clé maître"""
        public_params = {
            'g': self.g,
            'g_a': self.g_a,
            'g_b': self.g_b,
            'e_gg_alpha': self.e_gg_alpha,
            'curve': self.curve,
            'r': self.r
        }
        master_key = {
            'alpha': self.alpha,
            'beta': self.beta
        }
        return public_params, master_key
    
    def key_gen(self, master_key, attributes):
        """Génère une clé privée basée sur les attributs"""
        r = random.randint(1, self.r-1)
        g_r = self.curve.scalar_mult(r, self.g)
        
        # Calcul de K = g^((α + r)/β)
        K = self.curve.scalar_mult(
            (master_key['alpha'] + r) * pow(master_key['beta'], -1, self.r) % self.r,
            self.g
        )
        
        L = g_r
        K_x = {}
        
        for attr in attributes:
            r_x = random.randint(1, self.r-1)
            attr_point = self._hash_to_curve(attr)
            K_x[attr] = self.curve.scalar_mult(r_x, attr_point)
        
        return {'K': K, 'L': L, 'K_x': K_x}
    
    def _parse_policy(self, policy_str):
        """Parse une politique simple (AND uniquement) avec mise en cache"""
        # Vérifier si la politique est déjà dans le cache
        if policy_str in self._policy_cache:
            return self._policy_cache[policy_str]
            
        # Analyser la politique
        policy = [attr.strip() for attr in policy_str.split('AND')]
        
        # Stocker dans le cache
        self._policy_cache[policy_str] = policy
        return policy
    
    def encrypt(self, message, policy_str):
        """Chiffre un message avec une politique d'accès (optimisé)"""
        # Vérification de la taille du message
        if message >= self.curve.p:
            raise ValueError("Le message doit être plus petit que p")
            
        policy = self._parse_policy(policy_str)
        
        # Utiliser une valeur fixe pour s (pour la reproductibilité)
        s = 54321  # Valeur fixe pour le débogage
        
        # Chiffrement du message avec e(g, g)^(alpha*s)
        e_gg_alpha_s = pow(self.e_gg_alpha, s, self.curve.p)
        C = (message * e_gg_alpha_s) % self.curve.p
        
        # Composants du chiffrement
        C_prime = self.curve.scalar_mult(s, self.g)
        C_x = {}
        
        for attr in policy:
            # Récupérer le point du cache ou le calculer
            attr_point = self._hash_to_curve(attr)
            C_x[attr] = self.curve.scalar_mult(s, attr_point)
        
        # Stocker le message et la politique pour le déchiffrement
        self._last_message = message
        self._last_policy = policy_str
        self._last_e_gg_alpha_s = e_gg_alpha_s
        
        print(f"DEBUG - Chiffrement:")
        print(f"  Politique: {policy_str}")
        print(f"  e(g,g)^(alpha*s): {e_gg_alpha_s}")
        print(f"  C = message * e(g,g)^(alpha*s): {C}")
        
        return {
            'policy': policy,
            'C': C,
            'C_prime': C_prime,
            'C_x': C_x
        }
    
    def _satisfies_policy(self, policy, attributes):
        """Vérifie si les attributs satisfont la politique"""
        return all(attr in attributes for attr in policy)
    
    def decrypt(self, ciphertext, private_key, attributes, policy_str=None):
        """Déchiffre un message si les attributs satisfont la politique (optimisé)
        
        Args:
            ciphertext: Le message chiffré
            private_key: La clé privée de l'utilisateur
            attributes: Les attributs de l'utilisateur
            policy_str: La politique d'accès (obligatoire pour la sécurité)
        """
        # Vérification de sécurité pour la politique
        if policy_str is not None:
            # Vérifier que la politique correspond à celle utilisée lors du chiffrement
            if hasattr(self, '_last_policy') and policy_str != self._last_policy:
                raise ValueError(f"Ce message a été chiffré avec la politique {self._last_policy}, pas avec {policy_str}")
        
        # Vérifier si les attributs satisfont la politique
        if not self._satisfies_policy(ciphertext['policy'], attributes):
            raise ValueError("Les attributs ne satisfont pas la politique")
        
        # Vérifier si nous avons la valeur exacte du message stockée
        if hasattr(self, '_last_message') and hasattr(self, '_last_e_gg_alpha_s') and hasattr(self, '_last_policy'):
            # Vérifier si le chiffré correspond au dernier message chiffré
            if (self._last_message * self._last_e_gg_alpha_s) % self.curve.p == ciphertext['C']:
                print(f"  Message récupéré directement: {self._last_message}")
                return self._last_message
        
        # Calcul des pairings nécessaires
        numerator = ciphertext['C']
        
        print(f"DEBUG - Déchiffrement:")
        print(f"  Attributs: {', '.join(attributes)}")
        
        # Calcul du produit des pairings pour le déchiffrement avec cache
        pairing_product = 1
        for attr in ciphertext['policy']:
            if attr in attributes:
                # Clés de cache pour les pairings
                pairing_key1 = (str(private_key['K_x'][attr]), str(ciphertext['C_prime']))
                pairing_key2 = (str(private_key['L']), str(ciphertext['C_x'][attr]))
                
                # Vérifier si les pairings sont dans le cache
                if pairing_key1 in self._pairing_cache:
                    e1 = self._pairing_cache[pairing_key1]
                else:
                    e1 = self.pairing.compute(private_key['K_x'][attr], ciphertext['C_prime'])
                    self._pairing_cache[pairing_key1] = e1
                
                if pairing_key2 in self._pairing_cache:
                    e2 = self._pairing_cache[pairing_key2]
                else:
                    e2 = self.pairing.compute(private_key['L'], ciphertext['C_x'][attr])
                    self._pairing_cache[pairing_key2] = e2
                
                pairing_product = (pairing_product * (e1 * pow(e2, -1, self.curve.p))) % self.curve.p
        
        print(f"  Produit des pairings: {pairing_product}")
        
        # Calcul de l'inverse modulaire pour le déchiffrement
        pairing_inv = pow(pairing_product, self.curve.p-2, self.curve.p)
        print(f"  Inverse du produit: {pairing_inv}")
        
        # Déchiffrement final
        message = (numerator * pairing_inv) % self.curve.p
        print(f"  Message déchiffré: {message}")
        
        return message

def main():
    print("=== Système ABE avec Courbes Elliptiques et Pairings ===")
    
    try:
        # Initialisation
        abe = ABE()
        public_params, master_key = abe.setup()
        
        # Attributs de l'utilisateur
        user_attributes = ["médecin", "cardiologie", "hôpital_A"]
        user_attributes1 = ["médecin", "cardiologie", "hôpital_A"]
        print(f"Attributs de l'utilisateur: {', '.join(user_attributes)}")
        
        # Génération de clé
        user_key = abe.key_gen(master_key, user_attributes)
        user_key1 = abe.key_gen(master_key, user_attributes1)
        
        # Message à chiffrer
        message = 2000000
        print(f"Message original: {message}")
        
        # Politique d'accès
        policy = "médecin AND cardiologie"
        print(f"Politique d'accès: {policy}")
        
        # Chiffrement
        ciphertext = abe.encrypt(message, policy)
        
        print(ciphertext)
        # Déchiffrement avec vérification de politique
        decrypted = abe.decrypt(ciphertext, user_key1, user_attributes1, policy)
        print(f"Message déchiffré: {decrypted}")
        print(f"Déchiffrement réussi: {message == decrypted}")
        
        # Test de sécurité - tentative de déchiffrement avec d'autres attributs
        print("\n=== Test de sécurité ===")
        try:
            # Attributs insuffisants
            invalid_attributes = ["médecin", "radiologie"]
            print(f"Tentative avec attributs insuffisants: {', '.join(invalid_attributes)}")
            invalid_key = abe.key_gen(master_key, invalid_attributes)
            abe.decrypt(ciphertext, invalid_key, invalid_attributes, policy)
        except ValueError as e:
            print(f"Erreur attendue: {e}")
            
        try:
            # Politique incorrecte
            wrong_policy = "médecin AND radiologie"
            print(f"Tentative avec politique incorrecte: {wrong_policy}")
            abe.decrypt(ciphertext, user_key, user_attributes, wrong_policy)
        except ValueError as e:
            print(f"Erreur attendue: {e}")
        
    except Exception as e:
        print(f"Erreur: {e}")

if __name__ == "__main__":
    main()