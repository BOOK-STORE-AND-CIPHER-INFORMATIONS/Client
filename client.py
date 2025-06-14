#!/usr/bin/env python3
import requests
import json
import urllib3
import base64  
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Désactiver les avertissements InsecureRequestWarning de urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class APIClient:
    def __init__(self, base_url="http://localhost:8080"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.verify = False
        self.token = None  # Stocker le token JWT
        self.public_key_server = None  # Stocker la clé publique du serveur
        self.public_key = None
        self.private_key = None
        self.symmetric_key = None  # Stocker la clé symétrique si nécessaire
    
    def login(self, username, password):
        """Effectue la connexion et stocke le token"""
        try:
            response = self.session.post(
                f"{self.base_url}/api/login", 
                json={"username": username, "password": password},
                headers={'Content-Type': 'application/json'}
            )
            
            response.raise_for_status()
            
            # Vérifier si la réponse est vide
            if not response.text.strip():
                print("✗ Réponse vide du serveur")
                return False
            
            # Vérifier si c'est du JSON
            if 'application/json' not in response.headers.get('content-type', ''):
                print(f"✗ Type de contenu inattendu: {response.headers.get('content-type')}")
                return False
            
            data = response.json()
            
            # Récupérer le token (peut être 'token' ou 'access_token' selon votre API)
            self.token = data.get('token') or data.get('access_token')
            
            if self.token:
                # Ajouter le token à toutes les futures requêtes
                # Merge the Authorization header without overwriting other headers
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
            # Vérifier que nous sommes connectés
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
            response = self.session.post(
                f"{self.base_url}/api/exchange",
                json={"publicKey": public_key_b64},  # Changé de "public_key" à "publicKey"
                headers={
                    'Content-Type': 'application/ld+json',
                    'Authorization': f'Bearer {self.token}'
                }
            )
            
            response.raise_for_status()

            # Récupérer la réponse du serveur
            data = response.json()
            
            # Le serveur renvoie les clés avec les noms "publicKey" et "symmetricKey"
            server_public_key_b64 = data.get('publicKey')
            symmetric_key_b64 = data.get('symmetricKey')

            if not server_public_key_b64 or not symmetric_key_b64:
                print("✗ Clé publique du serveur ou clé symétrique manquante dans la réponse")
                print(f"Données reçues: {data}")
                return None

            # Décoder les clés base64
            self.public_key_server = base64.b64decode(server_public_key_b64).decode('utf-8')
            self.symmetric_key_encrypted = base64.b64decode(symmetric_key_b64)

            print("✓ Échange de clés réussi")
            return {
                "server_public_key": self.public_key_server,
                "symmetric_key": self.symmetric_key_encrypted
            }

        except requests.exceptions.RequestException as e:
            print(f"Erreur lors de l'échange de clés: {e}")
            return None
    
    def get(self, endpoint):
        """Effectue une requête GET"""
        try:
            response = self.session.get(f"{self.base_url}{endpoint}")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Erreur GET {endpoint}: {e}")
            return None
    
    def post(self, endpoint, data=None):
        """Effectue une requête POST"""
        try:
            # Ne pas écraser les headers de session, les fusionner
            headers = {'Content-Type': 'application/json'}
            if 'Authorization' in self.session.headers:
                headers['Authorization'] = self.session.headers['Authorization']
            
            
            
            response = self.session.post(
                f"{self.base_url}{endpoint}", 
                json=data
            )
            
            # Debug: voir la requête envoyée
            print(f"Debug - URL finale: {response.url}")
            print(f"Debug - Headers envoyés: {response.request.headers}")
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Erreur POST {endpoint}: {e}")
            return None

    def put(self, endpoint, data=None):
        """Effectue une requête PUT"""
        try:
            headers = {'Content-Type': 'application/json'}
            response = self.session.put(
                f"{self.base_url}{endpoint}", 
                json=data, 
                headers=headers
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Erreur PUT {endpoint}: {e}")
            return None

    def delete(self, endpoint):
        """Effectue une requête DELETE"""
        try:
            response = self.session.delete(f"{self.base_url}{endpoint}")
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            print(f"Erreur DELETE {endpoint}: {e}")
            return False

def test_api():
    """Fonction de test pour l'API"""
    api = APIClient("https://localhost")
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
    
   

def interactive_mode():
    """Mode interactif pour tester l'API"""
    api = APIClient("http://localhost:8080")  # Port 8080
    
    while True:
        print("\n=== CLIENT API INTERACTIF ===")
        print("1. Lister les livres")
        print("2. Lister les comptes")
        print("3. Créer un livre")
        print("4. Requête GET personnalisée")
        print("5. Requête POST personnalisée")
        print("0. Quitter")
        
        choice = input("\nChoisissez une option: ")
        
        if choice == "0":
            break
        elif choice == "1":
            books = api.get("/api/books")
            if books:
                print(json.dumps(books, indent=2))
            else:
                print("Aucun livre ou erreur")
        elif choice == "2":
            accounts = api.get("/api/accounts")
            if accounts:
                print(json.dumps(accounts, indent=2))
            else:
                print("Aucun compte ou erreur")
        elif choice == "3":
            title = input("Titre du livre: ")
            author = input("Auteur: ")
            book_data = {"title": title, "author": author}
            result = api.post("/api/books", book_data)
            if result:
                print("Livre créé:", json.dumps(result, indent=2))
        elif choice == "4":
            endpoint = input("Endpoint (ex: /api/books): ")
            result = api.get(endpoint)
            if result:
                print(json.dumps(result, indent=2))
        elif choice == "5":
            endpoint = input("Endpoint (ex: /api/books): ")
            data_str = input("Données JSON (ou appuyez sur Entrée pour vide): ")
            data = json.loads(data_str) if data_str else None
            result = api.post(endpoint, data)
            if result:
                print(json.dumps(result, indent=2))

# Utilisation
if __name__ == "__main__":
    print("Choisissez le mode:")
    print("1. Test automatique")
    print("2. Mode interactif")
    
    mode = input("Mode (1 ou 2): ")
    
    if mode == "1":
        test_api()
    elif mode == "2":
        interactive_mode()
    else:
        print("Mode invalide, lancement du test automatique:")
        test_api()