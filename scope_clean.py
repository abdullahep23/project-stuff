import pandas as pd
import sys

# Ensure SCoPE modules can be imported
sys.path.append("src")  

from controllers.ProcessCodeController import ProcessCodeController

# Use the fixed file
file_path = "C:/Users/Techcom/OneDrive/Desktop/sem 7/fyp/maybe datasets/split_data/diversevul_chunk_0_fixed.json"

# Read JSON file
try:
    df = pd.read_json(file_path)
except ValueError as e:
    print(f"❌ Error loading JSON: {e}")
    sys.exit(1)
except FileNotFoundError:
    print(f"❌ File not found: {file_path}")
    sys.exit(1)

print("📄 Loaded DataFrame:")
print(df.head())

# Check if 'func' column exists
if 'func' not in df.columns:
    raise KeyError("❌ Column 'func' not found in dataset. Check JSON format!")

# Drop rows where 'func' is missing
df = df.dropna(subset=['func'])

# Initialize the SCoPE processor
processor = ProcessCodeController()
processed_functions = []

# Process each function safely
for code in df['func']:
    try:
        result = processor.run(code)
        processed_functions.append(result[1] if result[0] == 0 else None)
    except Exception as e:
        print(f"⚠ Error processing function: {e}")
        processed_functions.append(None)

# Add processed functions to the DataFrame
df['processed_code'] = processed_functions

# Save the cleaned dataset
output_file = "C:/Users/Techcom/OneDrive/Desktop/sem 7/fyp/maybe datasets/split_data/cleaned_diversevul_0.json"
df.to_json(output_file, orient='records', lines=True)

print(f"✅ Processing complete. Cleaned dataset saved as '{output_file}'.")