# This script enables QRadar users to export QRadar assets from QRadar into a CSV file. For usage information, type: export_assets.py --help. 
import sys, os
import json, time
from urllib2 import Request
from urllib2 import urlopen
from urllib2 import HTTPError
#from urllib2 import ssl
from optparse import OptionParser
from optparse import BadOptionError
from optparse import AmbiguousOptionError

# A simple HTTP client that can be used to access the REST API
class RestApiClient:

    # Constructor for the RestApiClient Class
    def __init__(self,args):

        # Gets configuration information from config.ini. See ReadConfig
        # for more details.

        # Set up the default HTTP request headers
        self.headers = {b'Accept': 'application/json' }
        self.headers['Version'] = '3.0' 
        self.headers['Content-Type'] = 'application/json' 

        # Set up the security credentials. We can use either an encoded
        # username and password or a security token
        self.auth = {'SEC': args[0].token}

        self.headers.update(self.auth)

        # Set up the server's ip address and the base URI that will be used for
        # all requests
        self.server_ip = args[0].ip
        self.base_uri = '/api/'

        self.quiet = not args[0].verbose;

    # This method is used to set up an HTTP request and send it to the server
    def call_api(self, endpoint, method, headers=None, params=[], data=None, quiet=False):

        path = self.parse_path(endpoint, params)

        # If custom headers are not specified we can merge the default headers
        if not headers:
            headers = self.headers
        else:
            for key, value in self.headers.items():
                if headers.get( key,'') == '':
                    headers[ key ] = value

        # Send the request and receive the response
        if not self.quiet:
            print('\nSending ' + method + ' request to: ' + 'https://' +self.server_ip+self.base_uri+path+'\n')

        # This disables all SSL certificate verification
        #context = ssl._create_unverified_context()
		
        request = Request(
            'https://'+self.server_ip+self.base_uri+path, headers=headers)
        request.get_method = lambda: method
        try:
            #returns response object for opening url.
            #return urlopen(request, data, context=context)
            return urlopen(request, data,None)
        except HTTPError as e:
            #an object which contains information similar to a request object
            return e

    # This method constructs the query string
    def parse_path(self, endpoint, params):

        path = endpoint + '?'

        if isinstance(params, list):

            for kv in params:
                if kv[1]:
                    path += kv[0]+'='+(kv[1].replace(' ','%20')).replace(',','%2C')+'&'

        else:
            for k, v in params.items():
                if params[k]:
                    path += k+'='+v.replace(' ','%20').replace(',','%2C')+'&'

        # removes last '&' or hanging '?' if no params.
        return path[:len(path)-1]

class PassThroughOptionParser(OptionParser):
    def _process_args(self, largs, rargs, values):
        while rargs:
            try:
                OptionParser._process_args(self,largs,rargs,values)

            except (BadOptionError,AmbiguousOptionError) as e:
                largs.append(e.opt_str)
def get_parser():

    parser = PassThroughOptionParser(add_help_option=False)
    parser.add_option('-h', '--help', help='Show help message', action='store_true')
    parser.add_option('-i', '--ip', default="127.0.0.1", help='IP or Host of the QRadar console, or localhost if not present', action='store')
    parser.add_option('-t', '--token', help='QRadar authorized service token', action='store')
    parser.add_option('-f', '--file', help='File exports assets into.', action='store')
    parser.add_option('-s', '--search', help='Asset search to run',action='store')
    parser.add_option('-v', '--verbose', help='Verbose output',action='store_true')
    
    return parser

def main():

    parser = get_parser()
    args = parser.parse_args()

    if args[0].help or not (args[0].file or args[0].fields) or not args[0].ip or not args[0].token :
        print >> sys.stderr, "A simple utility to export an asset saved search to a CSV file. The file can then be reloaded using the update script"
        print >> sys.stderr, "The first column of the first line of the file will be 'ipaddress'"
        print >> sys.stderr, "The remaining columns of the file will contain the values custom field values"
        print >> sys.stderr, "";
        print >> sys.stderr, "example:"
        print >> sys.stderr, "";
        print >> sys.stderr, "ipaddress,Technical Owner,Location,Description"
        print >> sys.stderr, "172.16.129.128,Chris Meenan,UK,Email Server"
        print >> sys.stderr, "172.16.129.129,Joe Blogs,Altanta,Customer Database Server"
        print >> sys.stderr, "172.16.129.130,Jason Corbin,Boston,Application Server"
        print >> sys.stderr, "";
        print >> sys.stderr, parser.format_help().strip() 
        exit(0)

    # Creates instance of APIClient. It contains all of the API methods.
    api_client = RestApiClient(args)

    # retrieve all the asset fields
    print("Retrieving asset searches");
    asset_search_filter = {}
    response = api_client.call_api('asset_model/saved_searches', 'GET',{}, {},None)

    # Each response contains an HTTP response code.
    response_json = json.loads(response.read().decode('utf-8'))
    if response.code != 200:
        print("Error retrieving search : " + str(response.code))
        print(json.dumps(response_json, indent=2, separators=(',', ':')))
        exit(1)

    asset_search_id = -1;
    asset_file_fields = list() 
    for asset_search in response_json:
        if asset_search['name'] == args[0].search:
            asset_search_id = asset_search['id']
            # We need to get a list of all the column names in the results
            for asset_custom_fields in asset_search['columns']:
	        if asset_custom_fields['type'] == 'custom':
                    asset_file_fields.append(asset_custom_fields['name']);

    if asset_search_id == -1:
        print("Asset search " + args[0].search + " not found");
        exit(1)

    if( not args[0].file ):
        exit(1)

    # open file and write header
    file = open(args[0].file, 'w+')
    file.write("ipaddress");
    for prop_name in asset_file_fields:
        file.write(","+prop_name);
    file.write("\n");

    if file == None:
        print("File not found " + args[0].file)
        exit(1)

        
    # retrieve all the assets
    print("Running asset search " + args[0].search);
    response = api_client.call_api('asset_model/saved_searches/' + str(asset_search_id) + '/results', 'GET',None, {},None)


    # Each response contains an HTTP response code.
    response_json = json.loads(response.read().decode('utf-8'))
    if response.code != 200:
        print("When retrieving assets : " + str(response.code))
        print(json.dumps(response_json, indent=2, separators=(',', ':')))
        exit(1)
    
    print( str(len(response_json)) + " assets retrieved");

    for asset in response_json:
        interfaces = asset['interfaces'];
        max_last_seen = -1;
        last_ipaddress = "1.1.1.1";
        for interface in interfaces:
            for ipaddresses in interface['ip_addresses']:

                # get the largest last seen we have from this asset
                this_last_seen = ipaddresses['last_seen_scanner']
                if ( this_last_seen > max_last_seen ):
                    max_last_seen = this_last_seen;
                    last_ipaddress =  ipaddresses['value'];
                this_last_seen = ipaddresses['last_seen_profiler']
                if ( this_last_seen > max_last_seen ):
                    max_last_seen = this_last_seen;
                    last_ipaddress =  ipaddresses['value'];

        file.write(last_ipaddress);
        properties = asset['properties'];
        for property_to_output in asset_file_fields:
            file.write(",");
            for property in properties:
	        if property['name'] == property_to_output:
                    file.write(property['value']);
        file.write("\n");
if __name__ == "__main__":
    main()
