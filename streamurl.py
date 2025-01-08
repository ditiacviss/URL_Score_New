from Features.Features import get_fullDomain, check_favicon, havingIP, haveAtSign, check_robots_txt, redirection, \
    tinyURL, prefixSuffix, domainAge
from Features.Features import forwarding, get_security_headers, check_honeypot, check_cookies, check_entropy_domain
from Features.Features import evaluate_url_safety, check_for_ads, is_free_certificate, check_caching_and_compression
from sklearn.preprocessing import LabelEncoder
from logger.logs import logger_info
from bs4 import BeautifulSoup
import numpy as np
import pandas as pd
import yaml
import boto3
import re
from io import StringIO
import requests
import tldextract
import streamlit as st
from joblib import load
from email_sender import sendmail


# Load model and scaler
model = load('rf_model.pkl')
scaler = load('scaler_rf.pkl')


def preprocess_data(df):
    df.replace((True, 'TRUE', 'True'), 0, inplace=True)
    df.replace((False, 'FALSE', 'False'), 1, inplace=True)
    df.fillna(-1, inplace=True)
    df.replace('Error', -1, inplace=True)

    df['security headers'] = df['security headers'].astype(str)
    label_encoder = LabelEncoder()
    df['security headers'] = label_encoder.fit_transform(df['security headers'])

    df = df.drop(['url', 'TLD', 'Url Safety', 'HasSocialNet', 'HasHiddenFields', 'HasPasswordField'], axis=1)
    return df


def getDomain_n(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url  # Default to HTTP
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    return domain


def load_aws_credentials(content):
    """
    Load AWS credentials from YAML content.
    """
    try:
        credentials = yaml.safe_load(content)
        return credentials['aws']['access_key'], credentials['aws']['secret_key']
    except yaml.YAMLError as e:
        raise ValueError(f"Error loading YAML content: {e}")
    except KeyError as e:
        raise ValueError(f"Missing key in the YAML content: {e}")


def main():
    st.title("URL Legitimacy Tracker")

    sender_email = st.text_input("Sender email:")
    password = st.text_input('Email password:', type="password")
    receiver_emails = st.text_area("Receiver email(s), separated by commas:")
    keys_file = st.file_uploader("Upload Keys.yaml")
    user_input = st.text_area("Enter the URL:")

    if st.button("Enter") and user_input:
        try:
            url = user_input

            # Initialize feature lists
            features = {
                'Is Free': [],
                'Compressed': [],
                'DomainLength': [],
                'TLD': [],
                'TLDLength': [],
                'NoOfSubDomain': [],
                'LetterRatioInURL': [],
                'DigitRatioInURL': [],
                'NoOfOtherSpecialCharsInURL': [],
                'SpecialCharRatioInURL': [],
                'NoOfiFrame': [],
                'HasExternalFormSubmit': [],
                'HasSocialNet': [],
                'HasHiddenFields': [],
                'HasPasswordField': [],
                'HasCopyrightInfo': [],
                'NoOfImage': [],
                'NoOfCSS': [],
                'NoOfJS': [],
                'Have ip': [],
                'Have at sign': [],
                'Redirection': [],
                'favicon': [],
                'Robot txt': [],
                'security headers': [],
                'Honeypot': [],
                'Cookies': [],
                'Url Safety': [],
                'Ads': [],
                'Domain Age': [],
                'forwarding': [],
                'tiny URL': [],
                'Pre-suffix': [],
                'domain entropy': []
            }

            domain = get_fullDomain(url)
            domain_n = getDomain_n(url)

            try:
                features['Is Free'].append(is_free_certificate(url=url))
            except:
                features['Is Free'].append("Error")

            try:
                _, compressed = check_caching_and_compression(url=url)
                features['Compressed'].append(compressed)
            except:
                features['Compressed'].append("Error")

            try:
                features['DomainLength'].append(len(domain))
                features['TLD'].append(domain.split('.')[-1] if '.' in domain else '')
                features['TLDLength'].append(len(domain.split('.')[-1]) if '.' in domain else 0)
                features['NoOfSubDomain'].append(domain.count('.') - 1)
            except:
                features['DomainLength'].append("Error")
                features['TLD'].append("Error")
                features['TLDLength'].append("Error")
                features['NoOfSubDomain'].append("Error")

            # Check website content
            try:
                response = requests.get(url, timeout=20)
                soup = BeautifulSoup(response.content, 'html.parser')
                features['NoOfiFrame'].append(len(soup.find_all('iframe')))
                features['HasExternalFormSubmit'].append(
                    bool(soup.find('form', action=lambda a: a and not a.startswith('/'))))
                features['HasSocialNet'].append(any(link for link in soup.find_all('a', href=True) if
                                                    'facebook.com' in link['href'] or 'twitter.com' in link['href']))
                features['HasHiddenFields'].append(bool(soup.find('input', type='hidden')))
                features['HasPasswordField'].append(bool(soup.find('input', type='password')))
                features['HasCopyrightInfo'].append(bool(re.search(r'©|\bcopyright\b', soup.get_text(), re.I)))
                features['NoOfImage'].append(len(soup.find_all('img')))
                features['NoOfCSS'].append(len([link for link in soup.find_all('link', rel='stylesheet')]))
                features['NoOfJS'].append(len(soup.find_all('script')))
            except:
                for key in ['NoOfiFrame', 'HasExternalFormSubmit', 'HasSocialNet', 'HasHiddenFields', 
                            'HasPasswordField', 'HasCopyrightInfo', 'NoOfImage', 'NoOfCSS', 'NoOfJS']:
                    features[key].append("Error")

            # Extract additional features
            for func, key in zip(
                [havingIP, haveAtSign, redirection, check_favicon, check_robots_txt, 
                 get_security_headers, check_honeypot, check_cookies, evaluate_url_safety,
                 check_for_ads, domainAge, forwarding, tinyURL, prefixSuffix, check_entropy_domain],
                ['Have ip', 'Have at sign', 'Redirection', 'favicon', 'Robot txt',
                 'security headers', 'Honeypot', 'Cookies', 'Url Safety', 'Ads', 
                 'Domain Age', 'forwarding', 'tiny URL', 'Pre-suffix', 'domain entropy']
            ):
                try:
                    features[key].append(func(url))
                except:
                    features[key].append("Error")

            # Construct DataFrame
            df = pd.DataFrame(features)
            df['url'] = [url]
            df_processed = preprocess_data(df)
            df_scaled = scaler.transform(df_processed)

            # Handle predictions
            if keys_file is not None:
                file_content = keys_file.read()
                aws_access_key, aws_secret_key = load_aws_credentials(file_content)

                s3 = boto3.client('s3', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
                response = s3.get_object(Bucket='marketplace-scanner', Key='top10milliondomains.csv')
                csv_content = response['Body'].read().decode('utf-8')
                df_10m = pd.read_csv(StringIO(csv_content))

                if domain_n in df_10m['Domain'].values:
                    outcome_message = "The URL is predicted to be safe."
                else:
                    probabilities = model.predict_proba(df_scaled)
                    predicted_class = np.argmax(probabilities[0])
                    confidence = np.max(probabilities[0])
                    if predicted_class == 0 and confidence > 0.80:
                        outcome_message = "The URL is predicted to be safe."
                    else:
                        outcome_message = "The URL is predicted to be suspicious."

                st.write(outcome_message)
                logger_info(f"Outcome for URL {url} is {outcome_message}")
                sendmail(sender_email, receiver_emails, f'Outcome for {url}', 
                         f'Outcome for {url} is ---> {outcome_message}', password)
        except Exception as e:
            st.error(f"Error processing the URL: {e}")


if __name__ == "__main__":
    main()
