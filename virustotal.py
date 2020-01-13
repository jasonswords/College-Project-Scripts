import requests
import json
###### Important
###### Please install requests manually using pip or pip3.
###### pip3 install requests (Unix and Linux)
###### python -m pip install requests (Windows)

# Api key
API_KEY = 'insert api key here'

# Variables to aid stats function
num_av = 0
num_of_av_true = 0
malware_names = []
unique_malware_samples = []

# List of possible malware keywords
malware = {
    "Trojan" : 0,
    "Backdoor" : 0,
    "Generic" : 0,
    "Spyware": 0,
    "Crypto" : 0,
    "Wanna" : 0,
    "Ransom" : 0,
    "DDoS" : 0
}

# Function to count occurences of each malware keyword
def count_occurrances(malware_list):
    for x in malware_list:
        if 'Trojan' in x:
            malware['Trojan'] += 1
        elif 'Backdoor' in x:
            malware['Backdoor'] += 1
        elif 'Generic' in x:
            malware['Generic'] += 1
        elif 'Spyware' in x:
            malware['Spyware'] += 1
        elif 'Crypto' in x:
            malware['Crypto'] += 1
        elif 'Wanna' in x:
            malware['Wanna'] += 1
        elif 'Ransom' in x:
            malware['Ransom'] += 1
        elif 'DDoS' in x:
            malware['DDoS'] +=1

# Function that takes a file name(json file) and filters it for
# statistical information
# This function returns a list of unique malware occurences
def filter_malware_report(file_name):
    global num_av, num_of_av_true, malware_names
    num_av = 0
    num_of_av_true = 0
    unique_malware_samples = []
    with open(file_name, "r") as json_object: # Open file
        json_file = json.load(json_object)
        num_of_av_true = json_file['positives']
        num_av = json_file['total']
        for key, value in json_file.items():
            if key == 'scans': # Filter the scan results
                for y in json_file['scans']:
                    #num_av += 1 # Count number of av used
                    if json_file['scans'][y]['detected'] != False: # Filter out av that do not recognise the malware
                        #num_of_av_true += 1 # Count the number of positive recognitions
                        malware_names.append(json_file['scans'][y]['result']) # Add positive recognitions to list
                        if json_file['scans'][y]['result'] not in unique_malware_samples: # Check if malware is unique, if it is, add to unique malware sample list
                            unique_malware_samples.append(json_file['scans'][y]['result'])
    return unique_malware_samples # Return list of unique malwares

# Function to print the ststistical information to screen
# Parameter is file name
def print_statistical_data(report_name):
    unique_list = filter_malware_report(report_name)
    count_occurrances(unique_list)
    print_empty_lines(5)
    print('        Statistical Printout')
    print_empty_lines(2)
    for x in unique_list:
        print("{} ----- was identified {} times".format(x, malware_names.count(x)))
    print()
    print('------------------------------------------------------------------')
    print()
    print("From {} anti-virus systems, {} detected this as malicious".format(num_av, num_of_av_true))
    print()
    print('------------------------------------------------------------------')
    print()
    for m, n in malware.items():
        if n > 0:
            print("Malware Type : {}, Number of occurrences {}".format(m, n))

# Print out json responses
# Parameter in json object
def print_json(json_response):
    for key, value in json_response.items():
        if key == 'scans':
            for y in json_response['scans']:
                if json_response['scans'][y]['detected'] != False:
                    print("Scanner name: ", y, "| Detected:", json_response['scans'][y]['detected'], "| Result: ",
                          json_response['scans'][y]['result'])
        else:
            print("{} : {} ".format(key, value))

# Write json response to file
# Parameters are json object and file name variable
def write_to_file(json_object, file_name):
    if json_object['response_code'] == 0:
        print_empty_lines(2)
        print(json_object['verbose_msg'])
    elif json_object['response_code'] == 1:
        try:
            with open(file_name+'.json','w') as json_file:
                json.dump(json_object, json_file, indent=4)
                print("File: {} was created successfully".format(file_name+'.json'))
        except:
            print('Error, file was not created')
    elif json_object['response_code'] == -2:
        print_empty_lines(2)
        print(json_object['verbose_msg'])

# upload file to VirusTotal
# Parameter is file to be uploaded
def upload_file(file_name):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': API_KEY}
    files = {'file': (file_name, open(file_name, 'rb'))}
    response = requests.post(url, files=files, params=params).json()
    print_json(response)

# Get report using hash value from VirusTotal
# Parameter is hash of malware and name for the report
def get_file_report(hash, file_name):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': API_KEY, 'resource': hash}
    response = requests.get(url, params=params).json()
    write_to_file(response, file_name)

# Upload URL to VirusTotal for analysis
# Parameter is possible malicious URL
def upload_url(user_url):
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': API_KEY, 'url': user_url }
    response = requests.post(url, data=params).json()
    print_json(response)

# Get report results about a specific URL from VirusTotal
# Parameters are  URL and name of the json file
def get_url_report(user_url, file_name):
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': API_KEY , 'resource': user_url}
    response = requests.get(url, params=params).json()
    write_to_file(response, file_name)

# Simple function to print empty lines
# Parameter is integer value for number of lines
def print_empty_lines(num):
    for i in range(0,num):
        print()

# Main menu string
menu = """Please select your choice:

                        1: Upload file to VirusTotal
                        2: Get report using hash/scan ID
                        3: Upload URL for scanning
                        4: Get report from URL
                        5: Get statistics
                        6: Exit
                        """
# Menu for upload file function
def upload_file_menu():
    print("""***  Upload File  ***
    Please provide full path and file name you want scanned""")
    file = input("Enter file name:   ").strip()
    if not file:
        print("Name must not be empty")
        return
    print_empty_lines(2)
    try:
        open(file) # test if file exists
        upload_file(file)
        print("File successfully uploaded")
    except FileNotFoundError:
        print("Error, File not found")

# Menu for get file report function
def get_file_report_menu():
    print("""***  Get a Report on a File ***
    Please provide hash for file required""")
    report = input("Enter hash value        ").strip()
    if not report:
        print_empty_lines(2)
        print("Value must not be empty")
        return
    file_name = input("""Enter name for the report, \nIf left empty, hash will be used           """).strip()
    if not file_name.strip():# if filename is empty, use hash as file name
        file_name = report
    try:
        get_file_report(report, file_name)
    except:
        print("Error occurred with get file report function")

# Menu for upload URL function
def upload_url_menu():
    print("""***  Upload URL  ***
    Please provide URL you want scanned""")
    user_url = input("Enter URL:     ").strip()
    if not user_url:
        print("URL must not be empty")
        return
    try:
        upload_url(user_url)
    except:
        print("Error occurred with URL upload function")

# Menu for get URL report function
def get_url_report_menu():
    print("""***  Get URL report ***
    Please provide scan id for report required""")
    report_id = input("Enter ID        ").strip()
    if not report_id:
        print("Scan ID must not be empty")
        return
    url_report_name = input("""Enter name for the report, \nIf left empty, scan ID will be used           """).strip()
    if not url_report_name:
        url_report_name = report_id
    try:
        get_url_report(report_id, url_report_name)
    except:
        print("Error occurred with get URL report function")

# Menu for statistical function
def report_stats_menu():
    print("""***  Malware Statistics  ***
    Please provide json file to be examined""")
    name = input("Enter json file name:     ").strip()
    if not name:
        print("File name must not be empty")
        return
    try:
        json_file = filter_file_extensiona(name)
        #print(json_file)
        open(json_file) #check if file exists
        try:
            print_statistical_data(json_file)
        except:
            print("Error occurred with statistical function")
    except:
        print("Error, File not found")

# Filter file input parameter.
# checks for presence of .json extension
# checks for no extension
# checks for presence of . operator, and attempt to change to file extension
def filter_file_extensiona(file_name):
    if file_name.lower().endswith('.json'):
        return file_name
    elif '.' in file_name:
        split_file = file_name.split('.')
        return split_file[0].strip()+'.json'
    elif not file_name.lower().endswith('.json'):
        return file_name+'.json'

# Display main menu
def main_program():
    ans = 0
    while ans != 6:
        print_empty_lines(2)
        print(menu)
        try:
            ans = int(input("Please choose an option:   ").strip())

            print("Inputted value is {}".format(ans))

            if ans == 1:
                upload_file_menu()
            elif ans == 2:
                get_file_report_menu()
            elif ans == 3:
                upload_url_menu()
            elif ans == 4:
                get_url_report_menu()
            elif ans == 5:
                report_stats_menu()
            elif ans == 6:
                print("     ** Goodbye **")
                break
            else:
                print_empty_lines(2)
                print('            Invalid option')
                print("        ** Please try again **")
                print_empty_lines(2)
        except ValueError:
            print_empty_lines(2)
            print("-----  Error.........Please input valid choice  -----")

# Run program
main_program()









