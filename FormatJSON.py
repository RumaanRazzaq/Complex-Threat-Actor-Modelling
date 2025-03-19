import json

def fix_json_file(input_file, output_file):
    try:
        with open(input_file, 'r') as file:
            raw_data = file.read()
        
        '''
        I found that the PulseDive data i collected was stored as seperate dictionaries, without commas. This code reads the contents of the file.
        It then preprocess the data by wrapping objects in a list and separate them with commas . 
        '''
        fixed_data = '[\n' + raw_data.replace('}\n{', '},\n{') + '\n]'

        '''
        The data is then validated to ensure it is in proper JSON format. An error is printed if the JSON is still invalid.
        '''
        try:
            json_data = json.loads(fixed_data)
        except json.JSONDecodeError as e:
            print(f"Error validating JSON: {e}")
            return

        '''
        The contents is then written to the output file with proper formatting
        '''
        with open(output_file, 'w') as file:
            file.write(json.dumps(json_data, indent=4))
        
        print(f"Successfully fixed and saved the JSON to '{output_file}'.")
    except Exception as e:
        print(f"An error occurred: {e}")

input_file = 'PulsediveInfo_Unformatted.json'
output_file = 'PulsediveInfo.json'

fix_json_file(input_file, output_file)