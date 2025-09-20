import os
import base64
import pickle
import time
import re
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import openai
from todoist_api_python.api import TodoistAPI

class EmailTaskAutomation:
    def __init__(self):
        # Load environment variables
        self.OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
        self.TODOIST_API_TOKEN = os.getenv('TODOIST_API_TOKEN')
        self.GMAIL_LABEL = os.getenv('GMAIL_LABEL')  # Made optional at build time

        # Validate that GMAIL_LABEL is set when the script actually runs
        if not self.GMAIL_LABEL:
            print("ERROR: GMAIL_LABEL environment variable is not set. Please add it in your Railway service's 'Variables' tab.")
            exit(1)  # Stop the script if the label is missing

        self.SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
        self.setup_apis()

    def setup_apis(self):
        """Authenticates with Google and initializes API clients."""
        creds = None
        # The file token.pickle stores the user's access and refresh tokens, and is
        # created automatically when the authorization flow completes for the first time.
        if os.path.exists('token.pickle'):
            with open('token.pickle', 'rb') as token:
                creds = pickle.load(token)
        
        # If there are no (valid) credentials available, let the user log in.
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', self.SCOPES)
                creds = flow.run_local_server(port=0)
            # Save the credentials for the next run
            with open('token.pickle', 'wb') as token:
                pickle.dump(creds, token)
        
        self.gmail = build('gmail', 'v1', credentials=creds)
        openai.api_key = self.OPENAI_API_KEY
        self.todoist = TodoistAPI(self.TODOIST_API_TOKEN)

    def get_labeled_emails(self):
        """Fetches unread emails with the specified Gmail label."""
        query = f"label:{self.GMAIL_LABEL} is:unread"
        result = self.gmail.users().messages().list(userId='me', q=query).execute()
        return result.get('messages', [])

    def get_email_content(self, message_id):
        """Extracts subject, sender, and body from an email."""
        message = self.gmail.users().messages().get(userId='me', id=message_id).execute()
        headers = message['payload'].get('headers', [])
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
        sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
        body = self.extract_body(message['payload'])
        return {'id': message_id, 'subject': subject, 'sender': sender, 'body': body}

    def extract_body(self, payload):
        """Recursively extracts the plain text body from an email payload."""
        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    data = part['body'].get('data', '')
                    return base64.urlsafe_b64decode(data).decode('utf-8')
        elif payload.get('mimeType') == 'text/plain':
            data = payload['body'].get('data', '')
            return base64.urlsafe_b64decode(data).decode('utf-8')
        return ''

    def process_with_openai(self, email_data):
        """Uses OpenAI to format the email content into a structured task."""
        prompt = f"""
From: {email_data['sender']}
Subject: {email_data['subject']}

Body:
{email_data['body']}

---
Based on the email above, create a concise task. Format the output exactly as follows, with no extra text:
TITLE: [A short, clear task title]
DESCRIPTION: [A detailed description of the task]
PRIORITY: [High, Medium, or Low]
DUE_DATE: [A due date like 'tomorrow' or 'next Friday' if mentioned, otherwise None]
"""
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are an assistant that converts emails into structured tasks."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=400,
            temperature=0.5
        )
        return response.choices[0].message.content

    def parse_ai_response(self, ai_text):
        """Parses the structured text from the AI into a dictionary."""
        title = re.search(r"TITLE:\s*(.*)", ai_text)
        description = re.search(r"DESCRIPTION:\s*([\s\S]*?)(?=PRIORITY:)", ai_text)
        priority = re.search(r"PRIORITY:\s*(High|Medium|Low)", ai_text, re.IGNORECASE)
        due_date = re.search(r"DUE_DATE:\s*(.*)", ai_text)

        return {
            'title': title.group(1).strip() if title else 'Untitled Task',
            'description': description.group(1).strip() if description else ai_text,
            'priority': priority.group(1).capitalize() if priority else 'Medium',
            'due_date': due_date.group(1).strip() if due_date and 'none' not in due_date.group(1).lower() else None
        }

    def create_todoist_task(self, task_data, email_data):
        """Creates a new task in Todoist."""
        priority_map = {'High': 4, 'Medium': 2, 'Low': 1}
        full_description = (
            f"{task_data['description']}\n\n"
            f"--- Email Context ---\n"
            f"From: {email_data['sender']}\n"
            f"Subject: {email_data['subject']}"
        )
        
        self.todoist.add_task(
            content=task_data['title'],
            description=full_description,
            priority=priority_map.get(task_data['priority'], 2),
            due_string=task_data['due_date'],
            labels=["FromEmail"]
        )
        print(f"Created task: {task_data['title']}")

    def mark_email_as_processed(self, message_id):
        """Marks the email as read so it is not processed again."""
        self.gmail.users().messages().modify(
            userId='me', id=message_id, body={'removeLabelIds': ['UNREAD']}
        ).execute()

    def run(self):
        """The main execution loop for the automation."""
        print("Checking for new emails to process...")
        emails_to_process = self.get_labeled_emails()
        if not emails_to_process:
            print("No new emails found.")
            return

        for message_summary in emails_to_process:
            try:
                email_content = self.get_email_content(message_summary['id'])
                if not email_content['body'].strip():
                    print(f"Skipping email with no content: {email_content['subject']}")
                    self.mark_email_as_processed(message_summary['id'])
                    continue

                ai_response = self.process_with_openai(email_content)
                task_details = self.parse_ai_response(ai_response)
                self.create_todoist_task(task_details, email_content)
                self.mark_email_as_processed(message_summary['id'])
                time.sleep(1)  # Small delay to avoid hitting API rate limits
            except Exception as e:
                print(f"Failed to process email {message_summary['id']}. Error: {e}")

if __name__ == '__main__':
    automation = EmailTaskAutomation()
    automation.run()
