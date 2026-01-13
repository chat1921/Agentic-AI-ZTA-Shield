import os
import requests
import json
from dotenv import load_dotenv

# Load the API token from your .env file
load_dotenv()
HUGGINGFACE_API_TOKEN = os.getenv("HUGGINGFACE_API_TOKEN")

# The same API URL and headers from our agents.py file
API_URL = "https://api-inference.huggingface.co/models/mistralai/Mixtral-8x7B-Instruct-v0.1"
headers = {"Authorization": f"Bearer {HUGGINGFACE_API_TOKEN}"}

def run_test():
    print("--- Starting Hugging Face API Connection Test ---")

    if not HUGGINGFACE_API_TOKEN:
        print("ERROR: HUGGINGFACE_API_TOKEN not found in .env file. Please check your file.")
        return

    print(f"Attempting to contact model at: {API_URL}")

    payload = { "inputs": "Hello, can you see this message?" }

    try:
        response = requests.post(API_URL, headers=headers, json=payload, timeout=30)
        
        print(f"\nTest completed with Status Code: {response.status_code}")

        if response.status_code == 200:
            print("\nSUCCESS! ✅ Connection to Hugging Face API is working correctly.")
            print("The problem is likely with how the Flask server is being run.")
        else:
            print("\nFAILURE! ❌ Connection failed.")
            print("The server responded with an error.")
            print("\n--- Full Error Response ---")
            print(response.text)
            print("--------------------------")
            print("\nThis confirms a network or authentication problem. Please double-check your API token and any firewall or proxy settings.")

    except requests.exceptions.RequestException as e:
        print("\nCRITICAL FAILURE! ❌ Could not connect to the server at all.")
        print("This strongly indicates a network problem on your computer (firewall, proxy, or no internet connection).")
        print("\n--- Full Error Details ---")
        print(e)
        print("--------------------------")

if __name__ == "__main__":
    run_test()