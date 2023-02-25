# Louisiana Cyber Investigators Alliance (LCIA) - www.la-safe.org
# developed by: Darrell Miller : darrell.miller@la.gov

# simple script that pulls sha-1 values from a windows amcache then queries the sha-1 values
# with virus total. Basic results are printed to stdout. More comprehensive results saved in
# a csv file.
# (i often use these scripts as teaching tools, so there is far more documentation than necessary)

# --- modules needed ---
#  core python modules needed
from regipy.registry import RegistryHive                # Registry Parser
from regipy.plugins.utils import run_relevant_plugins
import virustotal3.core                                 # Virustotal API
import argparse
from os.path import exists

# just for making display better/prettier ---
from pprint import pprint                               # pretty print (json display)
from termcolor import cprint                            # color print
from tqdm import tqdm                                   # progress bar

# virus total query class/object
class queryVirusTotal:
    # vt_api_token = None #MUST SUPPLY YOUR TOKEN HERE

    def __init__(self):
        print ("Initializing queryVirusTotal")
        if self.vt_api_token is None: #checks if user added their own api token
            print ("ERROR: You must supply a vt_api_token")
            exit(1)
        else:
            self.vt_files = virustotal3.core.Files(self.vt_api_token) # creates virus total object

    def query_virustotal(self, sha1):
        try:
            info = self.vt_files.info_file(sha1, timeout=60)
            if info.get('data'):
                if info['data'].get('attributes'):
                    if info['data']['attributes'].get('total_votes'):
                        return info['data']['attributes']['total_votes']

        except Exception as e:
            errorLine = "ERROR:" + str(e) + "\n"
            # cprint (errorLine, "blue")

class amcacheParser:
    amcache_file = None # amcache file to parse
    amcache_data = None # amcache dadta converted to json
    limit_query = False # True/False to limit the query to the query limit, used for testing
    query_limit = 0 # used for testing purposes, stops a loop after 20 queries
    results = []

    def __init__(self, amcache_file, output_filename, limit):
        print ("Initializing amcacheParser:", amcache_file)
        self.vt_obj = queryVirusTotal()
        self.amcache_file = amcache_file
        self.output_filename = output_filename

        if limit:
            self.limit_query = True
            self.query_limit = int(limit)

        self.read_amcache(amcache_file)
        self.process_amcache_data()

    def read_amcache(self, amcache_file):
        try:
            reg=RegistryHive(amcache_file)
            self.amcache_data = run_relevant_plugins(reg, as_json=True)

        except Exception as e:
            errorLine = "ERROR:" + str(e) + "\n"
            cprint (errorLine,'red')

    def process_amcache_data(self):
        counter=0 # used for testing purposes, to stop super long queries

        for item in tqdm(self.amcache_data.get('amcache')):
            if item.get('sha1'):
                item['total_votes'] = self.vt_obj.query_virustotal(item['sha1'])
                if item.get('total_votes'):
                    if item['total_votes']['harmless'] > item['total_votes']['malicious']:
                        item['consensus'] = 'harmless'
                    elif item['total_votes']['harmless'] < item['total_votes']['malicious']:
                        item['consensus'] = 'malicious'
                    elif item['total_votes']['harmless'] == item['total_votes']['malicious'] and item['total_votes']['harmless'] >0:
                        item['consensus'] = 'questionable'
                    else:
                        item['consensus'] = 'unknown'
                if item.get('full_path')==None:
                    item['full_path'] = ''
                if item.get('total_votes') == None:
                    item['total_votes'] = {'harmless': 0, 'malicious': 0}
                    item['consensus'] = "unknown"
                if item.get('last_modified_timestamp_2')==None:
                    item['last_modified_timestamp_2'] = ''

                if counter > self.query_limit and self.limit_query==True:
                    print ("Query limit reached")
                    return
                self.results.append(item)
            counter+=1

    def display_results(self):
        cprint("[+] Amcache Results", 'green')
        cprint("   ========================", 'green')
        cprint("   [Harmless/Malicious Votes] :  concensus : filepath : sha1", 'green')
        cprint("   ========================", 'green')
        for item in self.results:
            if item.get('sha1'):
                displayLine = "   [H:" + str(item['total_votes']['harmless']) + " / M:" + \
                              str(item['total_votes']['malicious']) + "] : " + str(item['consensus']) \
                              + " : " + str(item['full_path']) + " : " + item['sha1']
                if item['consensus'] == 'unknown':
                    cprint(displayLine, 'yellow')
                elif item['consensus'] == 'malicious':
                    cprint(displayLine, 'red')
                elif item['consensus'] == 'questionable':
                    cprint(displayLine, 'cyan')
                elif item['consensus'] == 'harmless':
                    cprint(displayLine, 'green')

        cprint("   -------------------------", 'green')

    def save_csv_results(self):

        csvWriter = open(self.output_filename, 'w')
        csvWriter.write('timestamp,last_modified_timestamp,sha1,full_path,harmless,malicious,consensus,\n')

        for item in self.results:
            csvLine = str(item['timestamp']) + ',' + str(item['last_modified_timestamp_2']) + ',' + str(
                item['sha1']) + "," + str(item['full_path']) + ',' + str(item['total_votes']['harmless']) \
                + ',' + str(item['total_votes']['malicious']) + "," + str(item['consensus']) + '\n'

            csvWriter.write(csvLine)
        csvWriter.close()
        line="[+] Results of: " + self.amcache_file + " saved to: " + self.output_filename
        cprint (line, 'green')


#command line argument parser
def argParser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--amcache", help="amcache file to parse", required=True)
    parser.add_argument("-o", "--output", help="output file name", required=True)
    parser.add_argument("-l", "--limit", help="limit the number of queries", required=False)
    args = vars(parser.parse_args())
    return args

# --- main driving method ---
if __name__ == '__main__':
    args = argParser()

    if exists(args['amcache']):
        amcache_obj=amcacheParser(args['amcache'], args['output'], args['limit'])
        amcache_obj.display_results()
        amcache_obj.save_csv_results()
    else:
        cprint ("Error: amcache file does not exist", 'red')

