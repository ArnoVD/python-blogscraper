import requests
from bs4 import BeautifulSoup
import sys, getopt
import re
import json

# Fetch json data from certain url and write it to a json file
def fetch_json_data_from_href(headers,url, title):
    response = requests.request("GET", url, headers=headers)
    response_json = response.json()

    # Replace spaces with underscores (Best practice for filenames)
    title = title.replace(" ", "_")

    # Write JSON response to file
    write_json(title + ".json",response_json)

#Writing JSON file to disk (same folder)
def write_json(json_name,file):
    #This function writes a json file to the same folder
    with open(json_name, 'w+') as output_file:
        json.dump(file, output_file, indent=4)

# Function to remove duplicates in lists
def check_for_duplicates(list):
        final_list = []
        for x in list:
            if x not in final_list:
                final_list.append(x)
        return final_list

def get_threat_roundup_urls(soup):
    # Initialize
    threat_roundup_urls = []

    # Get all hrefs that contain "Threat Rounup for"
    for a in soup.find_all("a", string=re.compile(r"Threat Roundup for")):
        # Check for duplicates
        if a['href'] not in threat_roundup_urls:
            threat_roundup_urls.append(a['href'])
    return threat_roundup_urls

def get_threat_roundup_titles(soup):
    # Initialize
    threat_roundup_titles = []

    # Get all titles that contain "Threat Rounup for" and check for duplicates
    for a in soup.find_all("a", string=re.compile(r"Threat Roundup for")):
        # Check for duplicates
        if a.get_text() not in threat_roundup_titles:
            threat_roundup_titles.append(a.get_text())
        else:
            threat_roundup_titles.append("Not defined")
    return threat_roundup_titles

def get_all_blog_urls(soup):
    # Initialize
    all_blog_urls = []

    # Get all ul's with class = 'posts'
    for ul in soup.find_all('ul', class_='posts'):
        # Get all links (a) inside the ul's
        for a in ul.find_all("a", string=re.compile(r"")):
            # Exclude threat roundup hrefs
            if "Threat Roundup for" not in a.get_text():
                # Check for duplicates
                if a['href'] not in all_blog_urls:
                    all_blog_urls.append(a['href'])
    return all_blog_urls

def check_if_list_empty(list):
    if len(list) == 0:
        return "Nothing found."
    else:
        return list

#Main code procedure
def main(argv):

    # Spoofing header to make the request look like a legitimate browser
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0'}

    url = "https://blog.talosintelligence.com/"
    req = requests.get(url, headers=headers).text
    soup = BeautifulSoup(req, 'html.parser')

    # Writes the soup to a html file
    """
    with open("beautifulSoup_output.html", "w", encoding='utf-8') as file:
        file.write(str(soup.prettify()))"""

    # Initialize
    json_hrefs = []
    threat_roundup_titles = get_threat_roundup_titles(soup)
    threat_roundup_urls = get_threat_roundup_urls(soup)
    all_blog_urls = get_all_blog_urls(soup)
    hashes = []
    ips = []
    text_string = ""
    data_dict = {}
    ips_1_bracket_removed = []
    ips_brackets_removed = []

    # Read the file data.json
    # 'try' is for running the code in vscode
    # 'except' is for running the code in cmd
    try:
        with open(r"blogscraper\data.json", 'r') as myfile:
            data=myfile.read()
    except FileNotFoundError:
        with open("data.json", 'r') as myfile:
            data=myfile.read()

    # parse file
    obj = json.loads(data)

    #Cisco connect URL from JSON file
    last_url_scraped = obj['Last url scraped']

    if last_url_scraped != all_blog_urls[0]:

        # Loop through all threat roundup urls
        for url in range(len(threat_roundup_urls)):
            # Make a request by url x from list
            req = requests.get(str(threat_roundup_urls[url]), headers=headers).text
            soup = BeautifulSoup(req, 'html.parser')

            # Get all divs with class "threat-roundup-content"
            divs = soup.find_all("div", class_="threat-roundup-content")

            # Loop through divs and get all paragraphs
            for div in divs:
                all_paragraphs = div.find_all("p")
                # Loop through all paragraphs and find all links
                for p in all_paragraphs:
                    # Loop through all links and get there href if it contains "https://storage.googleapis.com/"
                    for a in p.find_all("a"):
                        if "https://storage.googleapis.com/" in a['href']:
                            json_hrefs.append(a['href'])

            # Remove duplicates
            json_hrefs = check_for_duplicates(json_hrefs)

        # Loop through all json hrefs found and fetch the data
        for x in range(len(json_hrefs)):
            fetch_json_data_from_href(headers, str(json_hrefs[x]), str(threat_roundup_titles[x]))

        # Crawl through all the urls found
        for url in range(len(all_blog_urls)):

            req = requests.get(str(all_blog_urls[url]), headers=headers).text
            soup = BeautifulSoup(req, 'html.parser')

            # Find all the text on the webpage from the url
            text = soup.find_all(text=True)

            # Exlusion set of special characters
            chars = set(r'!"#$%&()*+,.?-_/\:;@><=^[]{}`|~')

            # Loop through all the text found
            for t in text:
                # Add all the text into one long string
                    # This is needed for 're.findall()' since this method requires a string
                text_string = text_string + str(t)
                # Check for no spaces in the text
                if ' ' not in t:
                    # Check for no special characters
                    if not any((c in chars) for c in t):
                        # Check if the text is 64 characters long
                        if len(t) == 64:
                            # Check for duplicates
                            if t not in hashes:
                                hashes.append(t)


            # Pattern to find ips (example: 192[.]168[.]1[.]5)
            pattern = r"[0-9]{1,3}\[\.\][0-9]{1,3}\[\.\][0-9]{1,3}\[\.\][0-9]{1,3}"
            # Find all the ips in the long string made above
            ip_crawl_result = re.findall(pattern, str(text_string))

            # Loop through all ips found
            for ip in range(len(ip_crawl_result)):
                # Check for duplicates
                if ip_crawl_result[ip] not in ips:
                    ips.append(ip_crawl_result[ip])

        # For loops for removing the square brackets but leaving the dot (.) and slash (\)
        for x in range(len(ips)):
            new_ip = ips[x].replace("[", "")
            ips_1_bracket_removed.append(new_ip)
        for x in range(len(ips_1_bracket_removed)):
            new_ip = ips_1_bracket_removed[x].replace("]", "")
            ips_brackets_removed.append(new_ip)

        # Set last url scraped as the first element in the url list
        data_dict["Last url scraped"] = all_blog_urls[0]
        # Check if lists are empty and put return value in 'data_dict'
        data_dict["Scraped urls"] = check_if_list_empty(all_blog_urls)
        data_dict["Hashes found"] = check_if_list_empty(hashes)
        data_dict["Ips found"] = check_if_list_empty(ips_brackets_removed)

        # Write result to json file
        with open('data.json', 'w') as fp:
            json.dump(data_dict, fp, indent=4)

    else:
        print("No new posts found.")

if __name__ == "__main__":
    # Hold all arguments except the first one (first argument is the scriptname)
    main(sys.argv[1:])
