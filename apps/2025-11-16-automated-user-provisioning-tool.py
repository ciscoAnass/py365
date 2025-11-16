import csv
import os
import subprocess
import ldap3
import hashlib
import random
import string
import datetime

def generate_password(length=12):
    """
    Generates a random password of the specified length.
    """
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

def hash_password(password):
    """
    Hashes a password using the SHA-256 algorithm.
    """
    return hashlib.sha256(password.encode()).hexdigest()

def create_user_account(username, password, department, role, groups):
    """
    Creates a new user account in Active Directory or Linux.
    """
    # Connect to the directory service
    server = ldap3.Server('ldap://example.com')
    connection = ldap3.Connection(server, user='cn=admin,dc=example,dc=com', password='password')
    connection.bind()

    # Create the user object
    user_dn = f'cn={username},ou={department},dc=example,dc=com'
    user_object = {
        'objectClass': ['person', 'organizationalPerson', 'user'],
        'cn': username,
        'sAMAccountName': username,
        'userPrincipalName': f'{username}@example.com',
        'displayName': username,
        'department': department,
        'title': role,
        'userPassword': hash_password(password)
    }

    # Add the user to the directory
    connection.add(user_dn, attributes=user_object)

    # Add the user to the appropriate security groups
    for group in groups:
        group_dn = f'cn={group},ou=Groups,dc=example,dc=com'
        connection.extend.microsoft.add_members_to_groups(user_dn, [group_dn])

    # Close the connection
    connection.unbind()

def provision_users_from_csv(csv_file):
    """
    Provisions new user accounts from a CSV file.
    """
    with open(csv_file, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            name = row['Name']
            department = row['Department']
            role = row['Role']
            password = generate_password()
            groups = ['Domain Users', 'Sales']  # Example groups

            # Split the name into first and last name
            first_name, last_name = name.split(' ')

            # Generate the username
            username = f'{first_name[0]}{last_name}'.lower()

            # Create the user account
            create_user_account(username, password, department, role, groups)

            # Print the user information
            print(f'Created user account for {name} ({username}) in the {department} department with the role of {role}.')
            print(f'Initial password: {password}')

def main():
    """
    Main entry point for the script.
    """
    csv_file = 'new_hires.csv'
    provision_users_from_csv(csv_file)

if __name__ == '__main__':
    main()