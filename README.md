# jirascan
Simple script to retrieve information from JIRA server. You must have valid credentials. 

# Functions

- Collects users with emails
- Collects all issues with attachments
- Collects all attachments
- Find issues with certain words
- Output to sqlite3 bd 


## Usage

To get a list of basic options and switches use:

`python3 jirascan.py -h`

`python3 jirascan.py --url JIRAURL --username USERNAME --password PASSWORD --w [Words for search in JIRA] --F [output file for db]`


