import requests
from urllib.parse import urlparse

def get_http_headers(url):
    """
    Fetches HTTP headers from the provided URL.
    
    Parameters:
    url (str): The URL from which to fetch HTTP headers.
    
    Returns:
    dict: A dictionary containing HTTP headers.
    """
    try:
        response = requests.get(url)
        # Return headers if the request is successful
        if response.status_code == 200:
            return response.headers
        else:
            print(f"Failed to retrieve headers: {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"An error occurred: {e}")
        return None

def analyze_headers(headers):
    """
    Analyzes the HTTP headers for security-related information.
    
    Parameters:
    headers (dict): A dictionary of HTTP headers.
    
    Returns:
    None
    """
    security_headers = ['Content-Security-Policy', 'Strict-Transport-Security', 
                        'X-Content-Type-Options', 'X-Frame-Options', 
                        'X-XSS-Protection']
    
    print("\nSecurity Header Analysis:")
    for header in security_headers:
        if header in headers:
            print(f"{header}: {headers[header]}")
        else:
            print(f"{header}: Not present")

def main():
    """
    Main function to execute the script.
    
    Prompts user for a URL, fetches headers, and analyzes them.
    
    Returns:
    None
    """
    url = input("Enter a URL to analyze (e.g., https://example.com): ")
    parsed_url = urlparse(url)

    if not parsed_url.scheme:
        print("Invalid URL. Please include the scheme (http or https).")
        return

    print(f"\nFetching HTTP headers for: {url}")
    headers = get_http_headers(url)
    
    if headers:
        print("\nHTTP Headers:")
        for key, value in headers.items():
            print(f"{key}: {value}")
        analyze_headers(headers)

if __name__ == "__main__":
    main()
```