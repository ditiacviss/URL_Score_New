# email_sender.py
import smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

smtp_server = "smtp.gmail.com"
port = 587
context = ssl.create_default_context()

def sendmail(sender_email, receivers, subject, message, password):
    if isinstance(receivers, str):
        receivers = [email.strip() for email in receivers.split(",")]

    try:
        with smtplib.SMTP(smtp_server, port) as server:
            server.starttls(context=context)
            server.login(sender_email, password)

            msg = MIMEMultipart()
            msg["From"] = sender_email
            msg["To"] = ", ".join(receivers)  # Join all receivers in a single "To" header
            msg["Subject"] = subject
            msg.attach(MIMEText(message, "plain", "utf-8"))

            server.sendmail(sender_email, receivers, msg.as_string())  # Send to all receivers in one go
            print("Emails sent successfully.")
    except Exception as e:
        print("Error sending email:", e)
