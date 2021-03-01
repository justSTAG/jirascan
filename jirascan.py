import requests
import urllib3
import argparse
import sys
import sqlite3
from multiprocessing.dummy import Pool as ThreadPool
from iter2 import iter2
import operator
import time

urllib3.disable_warnings()


HOST = None


TABLE_SCHEMAS = {
    'issues': dict(
        id='VARCHAR(32) PRIMARY KEY',
        key='TEXT',
        summary='TEXT',
        description='TEXT',
        link='TEXT'
    ),
    'comments': dict(
        issue_id='VARCHAR(32)',
        comment_idx='INTEGER',
        content='TEXT'
    ),
    'attachments': dict(
        attachment_id='VARCHAR(32)',
        issue_id='VARCHAR(32)',
        file_name='TEXT',
        mime_type='TEXT',
        link='TEXT'
    ),
    'bad_words': dict(
        word='TEXT',
        issue_id='VARCHAR(32)'
    ),
    'users': dict(
        name='TEXT',
        display_name='TEXT',
        email='TEXT'
        ),
    'projects': dict(
        key='VARCHAR(32)',
        name='TEXT'
    )
}

def generate_schema(schema_dict):
    return (iter2(schema_dict.items())
            .map_t(lambda field_name, field_type: f'{field_name} {field_type}')
            .join(',\n')
            )


def generate_table(cur, name, schema):
    cur.execute(f"CREATE TABLE {name} ({schema})")


def init_tables(cur):
    for name, schema_dict in TABLE_SCHEMAS.items():
        generate_table(cur, name, generate_schema(schema_dict))


def insert(cur, table, values):
    schema = TABLE_SCHEMAS[table]
    names = iter2(schema).join(', ')
    values_tmpl = iter2.repeat('?', len(schema)).join(',')
    sql = f'INSERT INTO {table}({names}) VALUES ({values_tmpl})'
    cur.executemany(sql, values)


LOGIN_OK, LOGIN_FAILED, LOGIN_DENIED = object(), object(), object()
LOGIN_STATUS = {
    "OK": LOGIN_OK,
    "AUTHENTICATED_FAILED": LOGIN_FAILED,
    "AUTHENTICATION_DENIED": LOGIN_DENIED
}


def login(username, password):
    resp = requests.post(
        f'{HOST}/rest/gadget/1.0/login',
        data=dict(
            os_username=username,
            os_password=password
        ),
        verify=False
    )

    login_status = LOGIN_STATUS.get(resp.headers.get("X-Seraph-LoginReason"))
    if login_status is LOGIN_OK:
        cookies = resp.cookies
        headers = {
            'X-AUSERNAME': resp.headers['X-AUSERNAME'],
            'User-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:84.0) Gecko/20100101 Firefox/84.0'
        }


        def getter(url, *, params=None):
            params = params or {}
            time.sleep(DELAY)            
            return requests.get(url, params=params, headers=headers, cookies=cookies, verify=False, proxies=PROXIES)

        return login_status, getter
    else:
        return login_status, None


def get_server_info(getter):
    resp = getter(f'{HOST}/rest/api/2/serverInfo')
    settings = resp.json()
    return settings['baseUrl'], settings['version'], settings['buildNumber']


def get_password_policy(getter):
    resp = getter(f'{HOST}/rest/api/2/password/policy')
    policy = resp.json()
    return policy


def get_user_settings(getter):
    resp = getter(f'{HOST}/rest/api/2/myself')
    settings = resp.json()
    return settings['key'], settings['name'], settings['emailAddress']


def get_comments(getter, issue_link):
    resp = getter(issue_link)
    raw_comments = resp.json()["fields"]["comment"]["comments"]
    return tuple(
        raw_comment['body'].strip()
        for raw_comment in raw_comments
    )


PERMISSION_KEYS = (
    "SYSTEM_ADMIN", "ADMINISTER_PROJECTS", "PROJECT_ADMIN",
    "CREATE_ISSUE", "CREATE_ATTACHMENTS", "USER_PICKER"
)


def get_user_permissions(getter):
    resp = getter(f'{HOST}/rest/api/2/mypermissions')
    permissions = resp.json()['permissions']
    return tuple(
        (
            permissions[perm_key]['key'],
            permissions[perm_key]['havePermission']
            )
        for perm_key in PERMISSION_KEYS
    )


def get_all_users(getter):
    resp = getter(f'{HOST}/rest/api/2/user/search', params=dict(
        username='.',
        maxResults=1000000
    ))
    users = resp.json()
    return tuple(
        dict(
            name=user['name'],
            display_name=user['displayName'],
            email=user['emailAddress']
        )
        for user in users
    )


def get_all_projects(getter):
    resp = getter(f'{HOST}/rest/api/2/project')
    projects = resp.json()
    return tuple(
        dict(
            key=project['key'], 
            name=project['name']
        )
        for project in projects
    )


def search_issues_with_pagination(getter, jql, *, offset=0, max_results=1000):
    resp = getter(f'{HOST}/rest/api/2/search', params=dict(
        jql=jql,
        startAt=offset,
        maxResults=max_results
    ))

    json_data = resp.json()
    return json_data['total'], json_data.get('issues', tuple())


# generator
def search_issues(getter, jql, *, max_results=1000):
    offset = 0
    read_issues = 0
    while True:
        total, chunk = search_issues_with_pagination(getter, jql, offset=offset, max_results=max_results)
        yield from chunk
        read_issues += len(chunk)
        if total <= read_issues:
            break
        else:
            offset += len(chunk)


def search_issues_by_word(getter, word):
    jql = f'text ~ "\\"{word}\\""'
    return tuple(
        issue['id']
        for issue in search_issues(getter, jql)
    )


def search_issues_with_attachments(getter):
    jql = f'attachments IS NOT EMPTY'
    return tuple(
        issue['id']
        for issue in search_issues(getter, jql)
    )


def get_issue_info(getter, issue_id):
    resp = getter(f'{HOST}/rest/api/2/issue/{issue_id}')
    issue = resp.json()
    return dict(
        id=issue_id or '',
        link=issue['self'] or '',
        key=issue['key'] or '',
        summary=issue['fields']['summary'] or '',
        description=issue['fields']['description'] or '',
        comments=tuple(
            comment['body'].strip()
            for comment in issue['fields']['comment']['comments'] or ''
        ),
        attachments=tuple(
            dict(
                id=attachment['id'] or '',
                file_name=attachment['filename'] or '',
                mime_type=attachment['mimeType'] or '',
                link=attachment['content'] or ''
            )
            for attachment in issue['fields']['attachment'] or ''
        )
    )


def dump_to_db(path, users, projects, issues_info, issues_with_words):
    connection = sqlite3.connect(path)
    cursor = connection.cursor()

    init_tables(cursor)
    connection.commit()

    insert(cursor, 
        'users',
        (iter2(users)
            .map(operator.itemgetter('name', 'email', 'display_name')))
        )
    connection.commit()

    insert(cursor, 
        'projects',
        (iter2(projects)
            .map(operator.itemgetter('key', 'name')))
        )
    connection.commit()

    insert(cursor,
           'issues',
           (iter2(issues_info)
            .map(operator.itemgetter('id', 'key', 'summary', 'description', 'link')))
           )
    connection.commit()

    comment_records = (
        iter2(issues_info)
        .flatmap(lambda issue: (
            iter2(issue['comments'])
            .enumerate()
            .map_t(lambda idx, content: (
                issue['id'], idx, content
            ))
        ))
    )

    attachment_records = (
        iter2(issues_info)
            .flatmap(lambda issue: (
            iter2(issue['attachments'])
                .map(lambda attachment: (
                attachment['id'],
                issue['id'],
                attachment['file_name'],
                attachment['mime_type'],
                attachment['link']
            ))
        ))
    )

    insert(cursor, 'comments', comment_records)
    insert(cursor, 'attachments', attachment_records)
    connection.commit()

    insert(cursor, 'bad_words', (
        iter2(issues_with_words)
            .flatmap_t(lambda word, issue_ids: (
            iter2(issue_ids)
                .map(lambda issue_id: (
                word, issue_id
            ))
        ))
    ))
    connection.commit()

    connection.close()


def main():
    try:
        arg_parser = argparse.ArgumentParser()
        arg_parser.add_argument('--url', type=str, required=True)
        arg_parser.add_argument('--username', type=str, required=True)
        arg_parser.add_argument('--password', type=str, required=True)
        arg_parser.add_argument('--w', type=str)
        arg_parser.add_argument('--f', type=str, default='jira.db')
        arg_parser.add_argument('--threads', type=int, default=100)
        arg_parser.add_argument('--delay', type=int, default=0)
        arg_parser.add_argument('--proxies', type=str, default="")

        args = arg_parser.parse_args()

        global HOST
        HOST = args.url

        global DELAY
        DELAY = args.delay

        global PROXIES
        PROXIES = {"http":args.proxies,"https":args.proxies} if args.proxies else {}

        status, getter = login(args.username, args.password)

        if status is not LOGIN_OK:
            raise RuntimeError('Login failed')

        print("Login successful!")

        print("Server info:")
        server_info = get_server_info(getter)
        print(iter2(server_info).map(str).join(' '))
        print('------')

        print("Passwod policy:")
        password_policy = get_password_policy(getter)
        print(iter2(password_policy).map(str).join(' '))
        print('------')

        print('User permissions:')
        permissions = get_user_permissions(getter)
        print(iter2(permissions)
            .map_t(lambda perm, val: f'{perm} = {val}')
            .join('\n')
        )
        print(permissions)
        
        print('------')
        print("Collecting users...")
        users = get_all_users(getter)

        print("Collecting projects...")
        projects = get_all_projects(getter)

        pool = ThreadPool(args.threads)
        print("Collecting attachments...")
        print("It can take a lot of time, pls, be patient :)")
        issues_with_attachments = search_issues_with_attachments(getter)

        print("Collecting issues with words...")
        if args.w == None:
            words_for_search = [
                "vpn", "pass", "openvpn", "ssh", "password",
                "id_rsa", "admin", "credentials", "админ",
                "впн", "ключ", "пароль", "секрет", "secret"
            ]
        else:
            words_for_search = tuple(map(str.strip, args.w.split(',')))
            words_for_search = (
                iter2(args.w.split(','))
                .map(str.strip)
                .to_tuple()
            )

        issues_with_words = pool.map(
            lambda word: (word, search_issues_by_word(getter, word)),
            words_for_search
        )

        all_intersting_issues = iter2.chain(
            issues_with_attachments,
            (iter2(issues_with_words)
             .flatmap_t(lambda word, issues: issues)
             )
        ).collect(frozenset)

        issues_info = pool.map(
            lambda issue_id: get_issue_info(getter, issue_id),
            all_intersting_issues
        )


        print("Dumping info into", args.f)
        dump_to_db(args.f, users, projects, issues_info, issues_with_words)

        print("DONE")


    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == '__main__':
    main()
