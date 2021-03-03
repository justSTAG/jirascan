# jirascan

Simple script to retrieve information from JIRA server. You must have valid credentials. 

# Functions

- Collects users with emails
- Collects all issues with attachments
- Collects all attachments
- Find issues with certain words
- Output to sqlite3 db 


## Usage

To get a list of all options and switches use:

`python3 jirascan.py -h`

Simple Usage:

`python3 jirascan.py --url JIRAURL --username USERNAME --password PASSWORD `


## SQL queries

For better search, you have to execute sql to get some information. I recommend to use "DB for SQLite browser"

1. Select issues with "bad" words

`SELECT * FROM issues as i INNER JOIN bad_words AS bw on i.id=bw.issue_id`

2. Select issues with comments:

`SELECT * from comments AS c INNER JOIN  issues AS i WHERE c.issue_id =  i.id`
