import requests 
import hashlib 
import sys


def request_api_data(query_char): #query_char is the hash
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    #hash version to keep things more secure, K anonymity allows someone receive information and doesn't know who the person are, 
    # the company receives only the first 5 caracters from the password
    #the API never will know the full hash it will just compare the first 5 caracters with what they have stored
    res = requests.get(url)
    if res.status_code!= 200:
        raise RuntimeError (f'Error fetching: {res.status_code}, check the api and try again')
    return res

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h , count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # print(hashlib.sha1(password.encode('utf-8')).hexdigest().upper())
    #this will give the hash version of the password using sha1
    first5_char, tail = sha1password[:5],sha1password[5:]
    response = request_api_data(first5_char)
    #so in here the request function will take the first 5 characters variable 
    return get_password_leaks_count(response, tail)
    #this gives all the matches that we have with the password
    #also the output shows how many times the password was hacked
    
def main (args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should probably chang your download')
        else:
            print(f'{password} was NOT found. Carry on!')
    return 'done!'

if  __name__ =='__main__':
    sys.exit(main(sys.argv[1:]))


