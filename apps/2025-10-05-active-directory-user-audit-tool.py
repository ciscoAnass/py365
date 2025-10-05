import ldap3
import ssl
import datetime
import html
import base64
from typing import List, Dict, Any
from dataclasses import dataclass

@dataclass
class ADUserReport:
    username: str
    display_name: str
    email: str
    last_logon: datetime.datetime
    password_last_set: datetime.datetime
    account_status: str
    group_memberships: List[str]

class ActiveDirectoryAuditTool:
    def __init__(self, server_address: str, bind_username: str, bind_password: str):
        self.server_address = server_address
        self.bind_username = bind_username
        self.bind_password = bind_password
        self.connection = None

    def connect(self):
        try:
            tls_config = ldap3.Tls(
                validate=ssl.CERT_REQUIRED,
                version=ssl.PROTOCOL_TLSv1_2
            )
            server = ldap3.Server(
                self.server_address, 
                use_ssl=True, 
                tls=tls_config, 
                port=636
            )
            self.connection = ldap3.Connection(
                server, 
                user=self.bind_username, 
                password=self.bind_password, 
                auto_bind=True
            )
        except Exception as e:
            print(f"Connection error: {e}")
            return False
        return True

    def get_expired_password_users(self, max_password_age_days: int = 90) -> List[ADUserReport]:
        if not self.connection:
            return []

        current_time = datetime.datetime.now()
        expired_users = []

        search_filter = '(&(objectClass=user)(objectCategory=person))'
        attributes = [
            'sAMAccountName', 'displayName', 'mail', 
            'lastLogon', 'pwdLastSet', 'userAccountControl'
        ]

        self.connection.search(
            search_base='DC=domain,DC=com',  # Adjust base DN
            search_filter=search_filter,
            attributes=attributes
        )

        for entry in self.connection.entries:
            try:
                username = entry.sAMAccountName.value
                display_name = entry.displayName.value if entry.displayName.value else username
                email = entry.mail.value if entry.mail.value else 'N/A'
                
                last_logon = entry.lastLogon.value
                pwd_last_set = entry.pwdLastSet.value
                
                account_control = entry.userAccountControl.value
                is_disabled = bool(account_control & 0x0002)
                
                status = 'Disabled' if is_disabled else 'Active'
                
                if pwd_last_set and last_logon:
                    pwd_age = (current_time - pwd_last_set).days
                    
                    if pwd_age > max_password_age_days:
                        expired_users.append(ADUserReport(
                            username=username,
                            display_name=display_name,
                            email=email,
                            last_logon=last_logon,
                            password_last_set=pwd_last_set,
                            account_status=status,
                            group_memberships=self._get_user_groups(username)
                        ))
            except Exception as e:
                print(f"Error processing user {username}: {e}")

        return expired_users

    def _get_user_groups(self, username: str) -> List[str]:
        try:
            self.connection.search(
                search_base='DC=domain,DC=com',
                search_filter=f'(sAMAccountName={username})',
                attributes=['memberOf']
            )
            
            if self.connection.entries:
                return [group.split(',')[0].split('=')[1] for group in self.connection.entries[0].memberOf]
        except Exception:
            pass
        return []

    def generate_html_report(self, users: List[ADUserReport]) -> str:
        html_template = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>AD User Password Audit Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; }}
                tr:nth-child(even) {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>Active Directory User Password Audit</h1>
            <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Display Name</th>
                        <th>Email</th>
                        <th>Last Logon</th>
                        <th>Password Last Set</th>
                        <th>Account Status</th>
                        <th>Group Memberships</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join([f'''
                    <tr>
                        <td>{html.escape(user.username)}</td>
                        <td>{html.escape(user.display_name)}</td>
                        <td>{html.escape(user.email)}</td>
                        <td>{user.last_logon}</td>
                        <td>{user.password_last_set}</td>
                        <td>{user.account_status}</td>
                        <td>{', '.join(html.escape(group) for group in user.group_memberships)}</td>
                    </tr>
                    ''' for user in users])}
                </tbody>
            </table>
        </body>
        </html>
        '''
        return html_template

def main():
    ad_tool = ActiveDirectoryAuditTool(
        server_address='ldaps://your-ad-server.domain.com',
        bind_username='audit_service_account',
        bind_password='secure_password'
    )

    if ad_tool.connect():
        expired_users = ad_tool.get_expired_password_users(max_password_age_days=90)
        report_html = ad_tool.generate_html_report(expired_users)
        
        with open('ad_user_audit_report.html', 'w') as f:
            f.write(report_html)
        
        print(f"Generated report with {len(expired_users)} expired password users.")

if __name__ == '__main__':
    main()