from hvac import Client
import argparse
from dotenv import dotenv_values

config = dotenv_values(".env")

vaultClient = Client(url=config['VAULT_ADDR'])
vaultPath = "ssl_certs"
certsDir = "certs"

def checkAuth():
    if not vaultClient.is_authenticated():
        print(f'Vault is not authenticated. Please login to vault using "vault login -address {config['VAULT_ADDR']}".')
        exit(1)

def writeSecret(domain: str):
    """
    Writes the secret data for a given domain to the Vault.

    Args:
        domain (str): The domain for which the secret data is being written.

    Returns:
        dict: The response from the Vault API indicating the success or failure of the operation.
              If the operation is successful, the response will contain the created or updated secret path.
              If the operation fails due to a file not found error, the response will contain an error message.
    """
    try:
        intermediateOpen = open(f'{certsDir}/{domain}_intermediate.crt', "r")
        rootOpen = open(f'{certsDir}/{domain}_root.crt', "r")
        serverOpen = open(f'{certsDir}/{domain}_server.crt', "r")
        keyOpen = open(f'{certsDir}/{domain}_key.key', "r")

        data = {
            f'{domain}_intermediate.crt': intermediateOpen.read(),
            f'{domain}_root.crt': rootOpen.read(),
            f'{domain}_server.crt': serverOpen.read(),
            f'{domain}_server.key': keyOpen.read(),
        }
    
        create_response = vaultClient.secrets.kv.v2.create_or_update_secret(
            path=f'{vaultPath}/{domain}',
            secret=data,
        )

        intermediateOpen.close()
        rootOpen.close()
        serverOpen.close()  
        keyOpen.close() 
        return create_response
    
    except FileNotFoundError as e:
        return {"error": f"File not found: {e}"}
   
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", help="Domain to add the record for")
    args = parser.parse_args()
    if not args.d:
        print("Provide the domain name via --domain option")
        exit(1)
    checkAuth()
    write = writeSecret(args.d)
    if "error" in write:
        print(f"Error: {write['error']}")
    else:  
        print(f"Secret written successfully at {vaultPath}/{args.d} with version: {write['data']['version']}")