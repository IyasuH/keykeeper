import click
import pyperclip

import string
import random
import os
import uuid
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def validate_length(ctx, param, value):
    if value < 0:
        raise click.BadParameter(click.style('[ERROR] Length should be a positive, integer.', fg = 'red'))
    elif value > 100:
        raise click.BadParameter(click.style('[ERROR] Length should be less than 100.', fg = 'red'))
    elif value < 10:
        raise click.BadParameter(click.style('[ERROR] Length should be greater than 10.', fg = 'red'))
    return value


def save_password(password, database_file, site, add_info):
    salt_ = uuid.uuid4().bytes
    kdf = Scrypt(
        salt=salt_,
        length=32,
        n=2**16,
        r=8,
        p=1
    )
    hashed_password = kdf.derive(password.encode())
    # check if there is db connection
    # save the hash, salt and hash_type to database
    click.echo(click.style(f'[DEBUG] password {password}',fg = 'yellow'))
    click.echo(click.style(f'[DEBUG] hashed_password {hashed_password.hex()}',fg = 'yellow'))
    click.echo(click.style('[INFO] saving password to database', fg = 'cyan'))

@click.command()
@click.option('--length', '-l', default = 15, callback = validate_length, help = 'length of password')
@click.option('--copy', '-c', is_flag = True, help = 'copy password to clipboard', default=True, show_default=True)
@click.option('--special', '-s', is_flag = True, help = 'use special characters', default=True, show_default=True)
@click.option('--save', is_flag = True, help = 'save password to database', default=False, show_default=True)
def genrate_password(length, copy, special, save):
    """
    A simple password generator and manager cli tool.
    """
    click.echo(click.style(f'''[INFO] genrating password with: length {length}''', fg = 'cyan'))
    
    uppercase_letters = string.ascii_uppercase
    lowercase_letters = string.ascii_lowercase
    digits = string.digits

    random_uppercase = random.choice(uppercase_letters)
    random_lowercase = random.choice(lowercase_letters)
    random_digit = random.choice(digits)

    remaining_length = length - len([random_uppercase, random_lowercase, random_digit])
    random_chars = random.choices(string.digits, k = remaining_length)
    if special:
        click.echo(click.style('[INFO] using special characters', fg = 'cyan'))
        special_chars = string.punctuation
        random_special_char = random.choice(special_chars)
        remaining_length = length - len([random_uppercase, random_lowercase, random_digit, random_special_char])
        random_chars = random.choices(string.ascii_letters + string.digits + string.punctuation, k = remaining_length)
        password = ''.join([random_uppercase, random_lowercase, random_digit, random_special_char] + random_chars)
    else:
        password = ''.join([random_uppercase, random_lowercase, random_digit] + random_chars)
    password_list = list(password)
    random.shuffle(password_list)
    password = ''.join(password_list)
    click.echo(click.style('[INFO] password generated', fg = 'green'))

    if copy:
        pyperclip.copy(password)
        click.echo(click.style('[INFO] password copied!!', fg = 'green'))

    if save:
        database_file = click.prompt('Enter the database location to save password', default="__.db")
        if not os.path.exists(database_file):
            click.echo(click.style(f'[INFO] Database file {database_file} does not exist', fg = 'cyan'))
            click.echo(click.style('[INFO] Creating database file', fg = 'cyan'))
            open(database_file, 'a').close()
        site = click.prompt('Enter the site name', type=click.STRING, default="no site name")
        add_info = click.prompt('Enter any additional info to save to database', type=click.STRING, default="")
        save_password(password, database_file, site, add_info)
