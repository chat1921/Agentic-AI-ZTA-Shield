import os
import google.generativeai as genai
from dotenv import load_dotenv

print("--- Starting Google AI Generation Test ---")

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
        
        # 3. Select the model
        model = genai.GenerativeModel(model_name='gemini-flash-latest')
        
        # 4. Ask a simple question
        print("\nAttempting to generate content...")
        prompt = "What is 2 + 2?"
        response = model.generate_content(prompt)
        
        print("\n[SUCCESS] ✅")
        print("Successfully generated content from the Google API.")
        print(f"\nAI Response: {response.text}")

    except Exception as e:
        print("\n[FAILURE] ❌")
        print("An error occurred while trying to *generate* content.")
        print("\n--- ERROR DETAILS ---")
        print(e)
        print("---------------------")

print("\n--- Test Complete ---")