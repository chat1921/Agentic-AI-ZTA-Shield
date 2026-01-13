import os
import google.generativeai as genai
from dotenv import load_dotenv

print("--- Starting Google API Connection Test (v2) ---")

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
        
        # 3. Try to list the models
        print("\nAttempting to connect to Google AI and list models...")
        models_list = list(genai.list_models())
        
        print("\n[SUCCESS] ✅")
        print("Successfully connected to the Google API.")
        
        # 4. Print all available models
        print("\n--- Your Available Models ---")
        if not models_list:
            print("No models found for your API key.")
        else:
            for m in models_list:
                print(f"- {m.name}")
        print("----------------------------")

    except Exception as e:
        print("\n[FAILURE] ❌")
        print("An error occurred while trying to connect to the Google API.")
        print("\n--- ERROR DETAILS ---")
        print(e)
        print("---------------------")

print("\n--- Test Complete ---")