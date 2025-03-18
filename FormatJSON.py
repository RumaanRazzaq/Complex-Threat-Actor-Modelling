import json

def fix_json_file(input_file, output_file):
    try:
        # Read the contents of the file
        with open(input_file, 'r') as file:
            raw_data = file.read()
        
        # Preprocess the data: wrap objects in a list and separate them with commas
        fixed_data = '[\n' + raw_data.replace('}\n{', '},\n{') + '\n]'

        # Validate the fixed JSON
        try:
            json_data = json.loads(fixed_data)
        except json.JSONDecodeError as e:
            print(f"Error validating JSON: {e}")
            return

        # Write the fixed JSON to the output file
        with open(output_file, 'w') as file:
            file.write(json.dumps(json_data, indent=4))
        
        print(f"Successfully fixed and saved the JSON to '{output_file}'.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Input and output file paths
input_file = 'PulsediveInfo_Unformatted.json'  # Replace with your input file path
output_file = 'PulsediveInfo.json'  # Replace with your desired output file path

# Fix the JSON file
fix_json_file(input_file, output_file)