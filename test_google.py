import os
import google.generativeai as genai
from dotenv import load_dotenv

print("--- Starting Google API Connection Test ---")

# 1. Load the .env file
load_dotenv()
api_key = os.getenv("GOOGLE_API_KEY")

if api_key is None:
    print("\n[FAILURE] ❌")
    print("Could not find GOOGLE_API_KEY in your .env file.")
else:
    print("Successfully loaded API key from .env file.")
    
    try:
        # 2. Configure the API
        genai.configure(api_key=api_key)
        
        # 3. Try to list the models (a simple, safe test)
        print("\nAttempting to connect to Google AI and list models...")
        model_list = [m.name for m in genai.list_models()]
        
        print("\n[SUCCESS] ✅")
        print("Successfully connected to the Google API.")
        
        # 4. Check if gemini-flash-latest is in the list
        if 'models/gemini-flash-latest' in model_list:
            print("The 'gemini-flash-latest' model is available and ready to use.")
        else:
            print("[WARNING] ⚠️")
            print("Connected, but 'gemini-flash-latest' was not found.")

    except Exception as e:
        print("\n[FAILURE] ❌")
        print("An error occurred while trying to connect to the Google API.")
        print("\n--- ERROR DETAILS ---")
        print(e)
        print("---------------------")

print("\n--- Test Complete ---")