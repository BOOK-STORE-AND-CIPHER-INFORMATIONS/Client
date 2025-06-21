#!/usr/bin/env python3
import requests
import json
import urllib3
import base64  
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Désactiver les avertissements InsecureRequestWarning de urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class APIClient:
    def __init__(self, base_url="http://localhost:8080"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.verify = False
        self.token = None
        self.public_key_server = None  
        self.public_key = None
        self.private_key = None
        self.symmetric_key = None 
        self.server_public_key_obj = None  
    
    def login(self, username, password):
        """Effectue la connexion et stocke le token"""
        try:
            response = self.session.post(
                f"{self.base_url}/api/login", 
                json={"username": username, "password": password},
                headers={'Content-Type': 'application/json'}
            )
            
            response.raise_for_status()
            
            if not response.text.strip():
                print("✗ Réponse vide du serveur")
                return False
            
            if 'application/json' not in response.headers.get('content-type', ''):
                print(f"✗ Type de contenu inattendu: {response.headers.get('content-type')}")
                return False
            
            data = response.json()
            
            self.token = data.get('token') or data.get('access_token')
            
            if self.token:
                self.session.headers['Authorization'] = f'Bearer {self.token}'
                print(f"✓ Connexion réussie, token reçu")
                return True
            else:
                print("✗ Token non trouvé dans la réponse")
                print(f"Données reçues: {data}")
                return False
                
        except json.JSONDecodeError as e:
            print(f"✗ Erreur de décodage JSON: {e}")
            print(f"Réponse brute: {response.text}")
            return False
        except requests.exceptions.RequestException as e:
            print(f"Erreur login: {e}")
            return False
    
    def exchange_keys(self):
        try:

            if not self.token:
                print("✗ Aucun token d'authentification. Connectez-vous d'abord.")
                return None

            # Générer une paire de clés RSA
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            self.public_key = self.private_key.public_key()

            # Sérialiser la clé publique au format PEM standard
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Encoder la clé publique en base64 comme attendu par le serveur
            public_key_b64 = base64.b64encode(public_pem).decode('utf-8')

            # Envoyer la clé publique au serveur avec le bon nom de champ
            print(public_key_b64)
            response = self.session.post(
                f"{self.base_url}/api/exchange",
                json={"publicKey": public_key_b64},
                headers={
                    'Content-Type': 'application/ld+json',
                    'Authorization': f'Bearer {self.token}'
                }
            )
            
            response.raise_for_status()
            data = response.json()
            
            server_public_key_b64 = data.get('publicKey')
            symmetric_key_b64 = data.get('symmetricKey')

            if not server_public_key_b64 or not symmetric_key_b64:
                print("✗ Clé publique du serveur ou clé symétrique manquante dans la réponse")
                print(f"Données reçues: {data}")
                return None

            self.public_key_server = base64.b64decode(server_public_key_b64).decode('utf-8')

            self.server_public_key_obj = serialization.load_pem_public_key(
                self.public_key_server.encode('utf-8'),
                backend=default_backend
            )

            self.symmetric_key = self.private_key.decrypt(
                base64.b64decode(symmetric_key_b64),
                padding.PKCS1v15()
            )

            print("✓ Échange de clés réussi")
            return {
                "server_public_key": self.public_key_server,
                "symmetric_key": self.symmetric_key
            }

        except requests.exceptions.RequestException as e:
            print(f"Erreur lors de l'échange de clés: {e}")
            return None
        except Exception as e:
            print(f"Erreur lors du traitement des clés: {e}")
            return None

    def symmetric_decrypt(self, encrypted_data: str) -> str:
        """Décrypte les données avec AES-256-CBC"""
        try:
            # Décoder le base64
            encrypted_bytes = base64.b64decode(encrypted_data)
            
            # Extraire l'IV (16 premiers octets pour AES)
            iv = encrypted_bytes[:16]
            ciphertext = encrypted_bytes[16:]
            
            cipher = Cipher(
                algorithms.AES(self.symmetric_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Retirer le padding PKCS7
            padding_length = padded_data[-1]
            data = padded_data[:-padding_length]
            
            return data.decode('utf-8')
            
        except Exception as e:
            print(f"Erreur de décryptage symétrique: {e}")
            return None

    def symmetric_encrypt(self, data: str) -> str:
        """Chiffre les données avec AES-256"""
        try:
            
            iv = os.urandom(16)

            # Padding PKCS7
            padding_length = 16 - (len(data.encode('utf-8')) % 16)
            padded_data = data.encode('utf-8') + bytes([padding_length] * padding_length)
            
            cipher = Cipher(
                algorithms.AES(self.symmetric_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            encrypted_data = iv + ciphertext
            return base64.b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            print(f"Erreur de chiffrement symétrique: {e}")
            return None

    def sign_data(self, data: str) -> str:
        """Signe les données avec la clé privée du client"""
        try:
            signature = self.private_key.sign(
                data.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA512()
            )
            return base64.b64encode(signature).decode('utf-8')
            
        except Exception as e:
            print(f"Erreur de signature: {e}")
            return None

    def create_encrypted_request(self, data: dict) -> dict:
        """Crée une requête chiffrée et signée"""
        try:

            json_data = json.dumps(data, separators=(',', ':'))
            
            signature = self.sign_data(json_data)
            if not signature:
                return None
            payload = {
                "json_data": json_data,
                "signature": signature
            }
            
            encrypted_data = self.symmetric_encrypt(json.dumps(payload, separators=(',', ':')))
            if not encrypted_data:
                return None
            
            return {"encrypted_data": encrypted_data}
            
        except Exception as e:
            print(f"Erreur lors de la création de la requête chiffrée: {e}")
            return None

    def verify_signature(self, data: str, signature: str) -> bool:
        """Vérifie la signature SHA512 avec la clé publique du serveur (compatible avec openssl_sign PHP)"""
        try:
            signature_bytes = base64.b64decode(signature)
            
            # PHP openssl_sign utilise PKCS1v15 par défaut
            self.server_public_key_obj.verify(
                signature_bytes,
                data.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA512()
            )
            return True
            
        except Exception as e:
            print(f"Erreur de vérification de signature: {e}")
            return False

    def decrypt_response(self, response_data: dict) -> dict:
        """Décrypte et vérifie une réponse du serveur"""
        try:            

            encrypted_data = response_data.get('encrypted_data')
            if not encrypted_data:
                print("Aucune donnée chiffrée trouvée")
                return None
                        
            decrypted_json = self.symmetric_decrypt(encrypted_data)
            if not decrypted_json:
                print("Erreur lors du décryptage")
                return None
                        
            decrypted_data = json.loads(decrypted_json)
            
            json_data = decrypted_data.get('json_data')
            signature = decrypted_data.get('signature')
            
            if not json_data or not signature:
                print("Données ou signature manquantes")
                return None
                        
            if not self.verify_signature(json_data, signature):
                print("✗ Signature invalide!")
                return None
            
            print("✓ Signature vérifiée")
            
            return json.loads(json_data)
            
        except Exception as e:
            print(f"Erreur lors du décryptage de la réponse: {e}")
            return None

    def get(self, endpoint):
        """Effectue une requête GET et décrypte la réponse"""
        try:
            response = self.session.get(f"{self.base_url}{endpoint}")
            response.raise_for_status()
            
            response_data = response.json()
            
            return self.decrypt_response(response_data)
         
        except requests.exceptions.RequestException as e:
            print(f"Erreur GET {endpoint}: {e}")
            return None

    def post(self, endpoint, data=None):
        """Effectue une requête POST et décrypte la réponse"""
        try:
            print(f"Données à envoyer: {data}")  # Debug
            
            if self.symmetric_key and data is not None:
                encrypted_request = self.create_encrypted_request(data)
                if not encrypted_request:
                    print("Erreur lors de la création de la requête chiffrée")
                    return None
                print(f"Requête chiffrée: {encrypted_request}")  # Debug
                response = self.session.post(
                    f"{self.base_url}{endpoint}",
                    json=encrypted_request,
                    headers={'Content-Type': 'application/ld+json'}
                )
        
            if response.status_code != 200:
                # Afficher le contenu de la réponse d'erreur
                print(f"Erreur {response.status_code}: {response.text}")
                response.raise_for_status()
            
            response_data = response.json()
            return self.decrypt_response(response_data)

                
        except requests.exceptions.RequestException as e:
            print(f"Erreur POST {endpoint}: {e}")
            return None

    def put(self, endpoint, data=None):
        """Effectue une requête PUT avec chiffrement"""
        try:
            if self.symmetric_key and data is not None:
                encrypted_request = self.create_encrypted_request(data)
                print(f"Données à envoyer: {encrypted_request}")  # Debug
                if not encrypted_request:
                    print("Erreur lors de la création de la requête chiffrée")
                    return None
                
                response = self.session.put(
                    f"{self.base_url}{endpoint}",
                    json=encrypted_request,
                    headers={'Content-Type': 'application/ld+json'}
                )
            else:
                response = self.session.put(
                    f"{self.base_url}{endpoint}", 
                    json=data, 
                    headers={'Content-Type': 'application/ld+json'}
                )
            response.raise_for_status()
            response_data = response.json()
            # Vérifier si c'est une réponse chiffrée
            if 'encrypted_data' in response_data:
                return self.decrypt_response(response_data)
            else:
                return response_data
        except requests.exceptions.RequestException as e:
            print(f"Erreur PUT {endpoint}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Réponse d'erreur: {e.response.text}")
            return None

    def delete(self, endpoint):
        """Effectue une requête DELETE avec chiffrement"""
        try:
            if self.symmetric_key:
                encrypted_request = self.create_encrypted_request({})
                if not encrypted_request:
                    print("Erreur lors de la création de la requête chiffrée")
                    return False
                
                response = self.session.post(
                    f"{self.base_url}{endpoint}",
                    json=encrypted_request,
                    headers={'Content-Type': 'application/ld+json', 'X-HTTP-Method-Override': 'DELETE'}
                )
            else:
                response = self.session.delete(f"{self.base_url}{endpoint}")
            
            response.raise_for_status()
            
            # Pour DELETE, on peut avoir une réponse vide ou avec données
            if response.text.strip():
                response_data = response.json()
                if 'encrypted_data' in response_data:
                    result = self.decrypt_response(response_data)
                    return result is not None
                else:
                    return True
            else:
                return True
                
        except requests.exceptions.RequestException as e:
            print(f"Erreur DELETE {endpoint}: {e}")
            return False


    def postNoCypher(self, endpoint, data=None):
        """Effectue une requête POST et décrypte la réponse"""
        try:
            print(f"Données à envoyer: {data}")  # Debug

            response = self.session.post(
                f"{self.base_url}{endpoint}", 
                json=data,
                headers={'Content-Type': 'application/ld+json'}
            )
        
            if response.status_code != 200:
                print(f"Erreur {response.status_code}: {response.text}")
                response.raise_for_status()
            
            response_data = response.json()
            
            # Si pas de chiffrement, retourner directement
            if not self.symmetric_key or 'encrypted_data' not in response_data:
                return response_data
            
            return self.decrypt_response(response_data)

                
        except requests.exceptions.RequestException as e:
            print(f"Erreur POST {endpoint}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Réponse d'erreur: {e.response.text}")
            return None
    
    def patch(self, endpoint, data=None):
        """Effectue une requête PATCH avec chiffrement"""
        try:
            if self.symmetric_key and data is not None:
                encrypted_request = self.create_encrypted_request(data)
                if not encrypted_request:
                    print("Erreur lors de la création de la requête chiffrée")
                    return None
                response = self.session.patch(
                    f"{self.base_url}{endpoint}",
                    json=encrypted_request,
                    headers={'Content-Type': 'application/merge-patch+json'}
                )
            else:
                response = self.session.patch(
                    f"{self.base_url}{endpoint}",
                    json=data,
                    headers={'Content-Type': 'application/merge-patch+json'}
                )
            response.raise_for_status()
            response_data = response.json()
            if 'encrypted_data' in response_data:
                return self.decrypt_response(response_data)
            else:
                return response_data
        except requests.exceptions.RequestException as e:
            print(f"Erreur PATCH {endpoint}: {e}")
            return None

def test_api():
    """Fonction de test pour l'API"""
    api = APIClient("http://localhost:8080")
    print("=== TEST DE L'API ===\n")
    
    # Test de connectivité
    print("0. Test de connectivité:")
    try:
        response = api.session.get(api.base_url)
        print(f"   ✓ Serveur accessible: Status {response.status_code}")
    except Exception as e:
        print(f"   ✗ Erreur de connexion: {e}")
        return
    print()
    
    # Login avec gestion du token
    print("1. Login:")
    response = api.login("admin", "admin")
    if response :
        print("   ✓ Connexion réussie")
        print(f"   Token: {api.token[:50]}..." if api.token else "   Pas de token")
    else:
        print("   ✗ Échec de la connexion")
        return
    print()
    
    # Envoie la clef public à l'API POST /exchange 
    # L'api doit répondre avec sa clef publique et la clef sysmetrique
    print("1.5. Échange de clés:")
    try:
        # Générer une paire de clés RSA côté client
        
        exchange_response = api.exchange_keys()
        if exchange_response:
            print("   ✓ Échange de clés réussi")
            print(f"   Clé publique serveur reçue: {exchange_response.get('server_public_key', 'Non trouvée')[:50]}...")
            print(f"   Clé symétrique reçue: {exchange_response.get('symmetric_key', 'Non trouvée')[:50]}...")
        else:
            print("   ✗ Erreur lors de l'échange de clés")
            return
            
    except ImportError:
        print("   ✗ Module cryptography non installé. Installez avec: pip install cryptography")
        return
    except Exception as e:
        print(f"   ✗ Erreur lors de l'échange de clés: {e}")
        return
    print()
    
    # Test CRUD complet pour les livres
    print("2. Test CRUD des livres:")
    
    # Créer un livre
    print("   2.1. Création d'un livre:")
    
    new_book = {
        "title": "Le Guide du Développeur",
        "author": "Test Author",
        "type": "informatique",
        "stock": 13,
    }
    
    create_response = api.post("/api/books", new_book)
    
    if create_response:
        book_id = create_response.get('id')  # Ajoutez cette ligne
        print(f"   ✓ Livre créé avec succès, ID: {book_id}")
    else:
        print("   ✗ Erreur lors de la création du livre")
        return
    print()
    
    # Lire le livre créé
    print("   2.2. Récupération du livre:")

    get_response = api.get(f"/api/books/{book_id}")

    if get_response:
        print(get_response)
        print("   ✓ Livre récupéré avec succès")
        print(f"   ID: {get_response.get('id')}")
        print(f"   Titre: {get_response.get('title')}")
        print(f"   Auteur: {get_response.get('author')}")
    else:
        print("   ✗ Erreur lors de la récupération du livre")
        return
    print()
    
    # Modifier le livre
    print("   2.3.1 PATCH Modification du livre:")

    updated_book = {
        "title": "Le Guide du Développeur - Édition Révisée",
        "author": "Test Authoraqzsdfghjkl (Mis à jour)"
    }
    update_response = api.patch(f"/api/books/142ab884-1dfb-472f-9801-57b12640ac7b", updated_book)
    if update_response:
        print("   ✓ Livre modifié avec succès")
        print(f"   Nouveau titre: {update_response.get('title')}")
        print(f"   Nouvel auteur: {update_response.get('author')}")
    else:
        print("   ✗ Erreur lors de la modification du livre")
    print()

    print("   2.3.2 PUT Modification du livre:")
    updated_book = {
        "title": "Le Guide du Développeur - Édition Révisée",
        "author": "Test Author (Mis à jour)",
        "type": "new type - informatique",
        "stock": 10
    }
    update_response = api.put(f"/api/books/142ab884-1dfb-472f-9801-57b12640ac7b", updated_book)
    if update_response:
        print("   ✓ Livre modifié avec succès")
        print(f"   Nouveau titre: {update_response.get('title')}")
        print(f"   Nouvel auteur: {update_response.get('author')}")
        print(f"   Nouveau titre: {update_response.get('type')}")
        print(f"   Nouveau titre: {update_response.get('stock')}")
    else:
        print("   ✗ Erreur lors de la modification du livre")
    print() 
   
    
    # Lister tous les livres pour vérifier
    print("   2.4. Liste de tous les livres:")
    books_list = api.get("/api/books")
    if books_list:
        print(f"   ✓ {len(books_list)} livre(s) trouvé(s)")
        for book in books_list.get('member'):
            print(f"   - ID: {book.get('id')}, Titre: {book.get('title')}")
    else:
        print("   ✗ Erreur lors de la récupération de la liste des livres")
    print()
    
    # Supprimer le livre
    print("   2.5. Suppression du livre:")
    if book_id:
        delete_response = api.delete(f"/api/books/{book_id}")
        if delete_response:
            print("   ✓ Livre supprimé avec succès")
        else:
            print("   ✗ Erreur lors de la suppression du livre")
    print()
    
    # Vérifier que le livre a été supprimé
    print("   2.6. Vérification de la suppression:")
    if book_id:
        verify_response = api.get(f"/api/books/{book_id}")
        if verify_response is None:
            print("   ✓ Livre correctement supprimé (non trouvé)")
        else:
            print("   ✗ Le livre existe encore après suppression")
    print()
    
    print("=== FIN DES TESTS ===")


# Utilisation
if __name__ == "__main__":
    n = int(input("Combien de fois voulez-vous tester l'API ? "))
    if n == 0:
        while True:
            print(f"\n=== TEST {n} ===")
            test_api()
            n += 1
    else:
        for i in range(n):
            print(f"\n=== TEST {i + 1} ===")
            test_api()