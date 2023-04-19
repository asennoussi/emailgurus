from django import template

register = template.Library()


@register.filter
def obfuscate_email(email):
    email_parts = email.split('@')
    if len(email_parts) != 2:
        return email

    username, domain = email_parts

    if len(username) <= 3:
        return email

    obfuscated_username = username[:2] + '*' * \
        (len(username) - 3) + username[-1]
    obfuscated_email = obfuscated_username + '@' + domain

    return obfuscated_email
