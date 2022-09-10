![enter image description here](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)
![enter image description here](https://img.shields.io/badge/Django-092E20?style=for-the-badge&logo=django&logoColor=green)
![enter image description here](https://img.shields.io/badge/redis-CC0000.svg?&style=for-the-badge&logo=redis&logoColor=white)
# All the love to supporters ❤️
You are fantastic if you're using emailgurus.xyz. Thank you so much for your support. 

# Welcome to Emailgurus!
Hi! Here is the open-source repository of emailgurus.xyz. 
Emailgurus.xyz is a SAAS, helping you cancel all noise from emails you don't care about. 

# Why Opensource Emailgurus?
Emailgurus do an excellent job. I love it; other users love it too. 
However, to do the incredible job, we ask for access to sensitive data you might feel uncomfortable granting us access to. 

No matter what we write in our privacy policy or marketing copy, showing the actual code is the ultimate proof that your data is not our business model. You pay for a service (Thank you for that); hence, you're not the product. 


# How it works

After you grant access to your Contacts list and Gmail inbox, Emailgurus pull the list of contacts and irreversibly encrypts them: SHA256, so no one knows who is on your contact list. That's private, and only you own that data.
Then we create a label on your inbox called `EG:OUTSIDERS`, and its color is purple.  

Then we kick off a listener on your inbox. The listener does only one thing: Listen to any changes happening to your inbox (excluding the SPAM box) 

When there is an incoming email, we read the metadata: `FROM`, SHA256 it, and compare it against the saved records in the database. 

If there is a match, the email comes from one of your contact lists; we don't do anything. Otherwise, it means that the email is coming from an outsider, then archive it and apply the `EG:OUTSIDERS` label. 

In the background, we launch two jobs: 
- Update contacts (every 1 hour) to make sure that we pull a fresh list of contacts
- Inbox listener (Every 24 hours) To make sure we refresh the inbox listener access


# Build & Run

**Install requirements:** 

    apt install Redis
    apt  install PostgreSQL PostgreSQL-contrib

**To build:** 
```
cd emailgurus
pip install -r requirements.txt
./manage.py migrate
```
**To Run:** 
```
./manage.py runserver 
# Run the scheduler (either on the same line or a new terminal)
./manage.py rqworker --with-scheduler
```

## Deployment Gunicorn (Requires supervisor)
Once you have the files on your server, follow the steps: 
```
python manage.py collectstatic --noinput

python manage.py migrate

supervisorctl restart emailgurus:
```

## Important settings values
These are the values that are important to have your project run on your own Google API credentials: 

`GOOGLE_APP_SECRET_JSON_PATH` 
This variable points to the APP secret JSON file from Google's API console. 
It's important to set to kick off the login flow correctly. 


Create a new project on Google console -> Credentials -> Configure Oauth2.0 -> Download the JSON file. 



## Community
Please join our community for walkthroughs, discussions, feature requests, enhancements, etc. 

[![enter image description here](https://img.shields.io/badge/Slack-4A154B?style=for-the-badge&logo=slack&logoColor=white)](https://emailgurus.slack.com)
## Features & Roadmap 

- ✅ Filter out emails from outsiders 
- ✅ Pause / Resume service 
- ✅ Allowlist domains 
- ✅ Performance Dashboard 
- ✅ Multiple accounts support 
- ✅ Archive / Not outsider emails 
- ✅ AutoSync of contacts & Auto-refresh of inbox listeners. 
- ⚪️ Transactional Emails (Welcome, Receipts, reminders of trial expiry, etc..)
- ⚪️ Advanced filtering logic 
- ⚪️ Analytics on user behavior (Airbyte or rudderstack)
- ⚪️ Outlook support 


