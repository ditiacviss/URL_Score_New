from Features.Features import get_fullDomain,check_favicon, havingIP,haveAtSign, check_robots_txt,redirection,tinyURL, prefixSuffix,domainAge
from Features.Features import forwarding,get_security_headers,check_honeypot, check_cookies, check_entropy_domain
from Features.Features import evaluate_url_safety,check_for_ads, is_free_certificate, check_caching_and_compression
from sklearn.preprocessing import LabelEncoder
import io
import datetime
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
    print(df.head())
    return df


def getDomain_n(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url  # Default to HTTP
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    return domain

def load_aws_credentials(file_content):
    try:
        credentials = yaml.safe_load(file_content)
        return credentials['aws']['access_key'], credentials['aws']['secret_key']
    except yaml.YAMLError as e:
        print(f"Error loading YAML content: {e}")
        raise
    except KeyError as e:
        print(f"Missing key in the YAML content: {e}")
        raise

def main():
    st.title("URL Legitimacy Tracker")
    keys_file = st.file_uploader('Upload your Keys.yaml')

    user_input = st.text_area("Enter the URL:")
    if st.button("Enter") and user_input:
        try:
            url = user_input

            Is_Free = []
            compressed_list = []
            DomainLength = []
            TLD = []
            TLDLength = []
            NoOfSubDomain = []
            LetterRatioInURL = []
            DigitRatioInURL = []
            NoOfOtherSpecialCharsInURL = []
            SpecialCharRatioInURL = []
            NoOfiFrame = []
            HasExternalFormSubmit = []
            HasSocialNet = []
            HasHiddenFields = []
            HasPasswordField = []
            HasCopyrightInfo = []
            NoOfImage = []
            NoOfCSS = []
            NoOfJS = []
            have_ip = []
            haveatsign = []
            Redirection = []
            favicon = []
            robot_txt = []
            security_headers = []
            honeypot = []
            cookies = []
            domain_entropy = []
            url_safety = []
            ads = []
            Domain_age = []
            forwarding_to = []
            tiny_URL = []
            prefix_Suffix = []
            url_list = []

            domain = get_fullDomain(url)
            domain_n = getDomain_n(url)
            print(domain_n)
            url_list.append(url)

            try:
                is_free = is_free_certificate(url=url)
                Is_Free.append(is_free)
            except:
                Is_Free.append("Error")

            try:
                caching, compressed = check_caching_and_compression(url=url)
                compressed_list.append(compressed)
            except:
                compressed_list.append("Error")

            try:
                DomainLength.append(len(domain))
            except:
                DomainLength.append("Error")

            try:
                TLD.append(domain.split('.')[-1] if '.' in domain else '')
            except:
                TLD.append("Error")

            try:
                TLDLength.append(len(domain.split('.')[-1]) if '.' in domain else 0)
            except:
                TLDLength.append("Error")

            try:
                subdomain_count = domain.count('.') - 1
                if subdomain_count > 0:
                    NoOfSubDomain.append(subdomain_count)
                else:
                    NoOfSubDomain.append(None)
            except:
                NoOfSubDomain.append("Error")

            try:
                LetterRatioInURL.append(sum(c.isalpha() for c in url) / len(url))
            except:
                LetterRatioInURL.append("Error")

            try:
                DigitRatioInURL.append(sum(c.isdigit() for c in url) / len(url))
            except:
                DigitRatioInURL.append("Error")

            try:
                NoOfOtherSpecialCharsInURL.append(sum(not c.isalnum() for c in url))
            except:
                NoOfOtherSpecialCharsInURL.append("Error")

            try:
                SpecialCharRatioInURL.append(sum(not c.isalnum() for c in url) / len(url))
            except:
                SpecialCharRatioInURL.append("Error")

            try:
                response = requests.get(url, timeout=20)
                soup = BeautifulSoup(response.content, 'html.parser')
                try:
                    NoOfiFrame.append(len(soup.find_all('iframe')))
                except:
                    NoOfiFrame.append("Error")

                try:
                    HasExternalFormSubmit.append(
                        bool(soup.find('form', action=lambda a: a and not a.startswith('/'))))
                except:
                    HasExternalFormSubmit.append("Error")

                try:
                    HasSocialNet.append(any(link for link in soup.find_all('a', href=True) if
                                            'facebook.com' in link['href'] or 'twitter.com' in link['href']))
                except:
                    HasSocialNet.append("Error")

                try:
                    HasHiddenFields.append(bool(soup.find('input', type='hidden')))
                except:
                    HasHiddenFields.append("Error")

                try:
                    HasPasswordField.append(bool(soup.find('input', type='password')))
                except:
                    HasPasswordField.append("Error")

                try:
                    HasCopyrightInfo.append(bool(re.search(r'©|\bcopyright\b', soup.get_text(), re.I)))
                except:
                    HasCopyrightInfo.append("Error")

                try:
                    NoOfImage.append(len(soup.find_all('img')))
                except:
                    NoOfImage.append("Error")

                try:
                    NoOfCSS.append(len([link for link in soup.find_all('link', rel='stylesheet')]))
                except:
                    NoOfCSS.append("Error")

                try:
                    NoOfJS.append(len(soup.find_all('script')))
                except:
                    NoOfJS.append("Error")

            except Exception as e:
                NoOfiFrame.append("Error")
                HasExternalFormSubmit.append("Error")
                HasSocialNet.append("Error")
                HasHiddenFields.append("Error")
                HasPasswordField.append("Error")
                HasCopyrightInfo.append("Error")
                NoOfImage.append("Error")
                NoOfCSS.append("Error")
                NoOfJS.append("Error")

            have_ip.append(havingIP(url))
            haveatsign.append(haveAtSign(url))
            Redirection.append(redirection(url))
            favicon.append(check_favicon(url))
            robot_txt.append(check_robots_txt(url))
            security_headers.append(get_security_headers(url))
            honeypot.append(check_honeypot(url))
            cookies.append(check_cookies(url))
            url_safety.append(evaluate_url_safety(url))
            ads.append(check_for_ads(url))
            Domain_age.append(domainAge(domain))
            forwarding_to.append(forwarding(url))
            tiny_URL.append(tinyURL(url))
            prefix_Suffix.append(prefixSuffix(url))
            domain_entropy.append(check_entropy_domain(url))

            data = pd.DataFrame({
                "url": url_list,
                'Is Free': Is_Free,
                'Compressed': compressed_list,
                'DomainLength': DomainLength,
                'TLD': TLD,
                'TLDLength': TLDLength,
                'NoOfSubDomain': NoOfSubDomain,
                'LetterRatioInURL': LetterRatioInURL,
                'DigitRatioInURL': DigitRatioInURL,
                'NoOfOtherSpecialCharsInURL': NoOfOtherSpecialCharsInURL,
                'SpecialCharRatioInURL': SpecialCharRatioInURL,
                'NoOfiFrame': NoOfiFrame,
                'HasExternalFormSubmit': HasExternalFormSubmit,
                'HasSocialNet': HasSocialNet,
                'HasHiddenFields': HasHiddenFields,
                'HasPasswordField': HasPasswordField,
                'HasCopyrightInfo': HasCopyrightInfo,
                'NoOfImage': NoOfImage,
                'NoOfCSS': NoOfCSS,
                'NoOfJS': NoOfJS,
                'Have ip': have_ip,
                'Have at sign': haveatsign,
                'Redirection': Redirection,
                'favicon': favicon,
                'Robot txt': robot_txt,
                'security headers': security_headers,
                'Honeypot': honeypot,
                'Cookies': cookies,
                'Url Safety': url_safety,
                'Ads': ads,
                'Domain Age': Domain_age,
                'forwarding': forwarding_to,
                'tiny URL': tiny_URL,
                'Pre-suffix': prefix_Suffix,
                'domain entropy': domain_entropy
            })

            data_processed = preprocess_data(data)
            data_scaled = scaler.transform(data_processed)

            if keys_file is not None:
                file_content = keys_file.read()
                aws_access_key, aws_secret_key = load_aws_credentials(file_content)
                s3 = boto3.client('s3', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)

                ##Features.csv
                Bucket = 'marketplace-scanner'
                csv_name = 'Test_Diti/features.csv'

                try:
                    # Try downloading the existing `features.csv`
                    existing_csv_buffer = io.BytesIO()
                    s3.download_fileobj(Bucket, csv_name, existing_csv_buffer)
                    existing_csv_buffer.seek(0)
                    existing_csv_content = existing_csv_buffer.read().decode('utf-8')
                    updated_csv = pd.read_csv(io.StringIO(existing_csv_content))
                    updated_csv = pd.concat([updated_csv, data], ignore_index=True)

                except s3.exceptions.NoSuchKey:
                    updated_csv = data
                    st.warning("`features.csv` not found on S3. Creating a new file.")

                csv_buffer = io.StringIO()
                updated_csv.to_csv(csv_buffer, index=False)
                csv_buffer.seek(0)
                s3.upload_fileobj(io.BytesIO(csv_buffer.getvalue().encode('utf-8')), Bucket, csv_name)
                
                file_keys = [
                    'Test_Diti/chunked_file_part_1.csv', 'Test_Diti/chunked_file_part_2.csv', 'Test_Diti/chunked_file_part_3.csv',
                    'Test_Diti/chunked_file_part_4.csv', 'Test_Diti/chunked_file_part_5.csv', 'Test_Diti/chunked_file_part_6.csv',
                    'Test_Diti/chunked_file_part_7.csv', 'Test_Diti/chunked_file_part_8.csv', 'Test_Diti/chunked_file_part_9.csv',
                    'Test_Diti/chunked_file_part_10.csv'
                ]

                df_10m = pd.DataFrame()

                for key in file_keys:
                    try:
                        response = s3.get_object(Bucket='marketplace-scanner', Key=key)
                        csv_content = response['Body'].read().decode('utf-8')
                        chunk_df = pd.read_csv(StringIO(csv_content))
                        df_10m = pd.concat([df_10m, chunk_df], ignore_index=True)
                    except Exception as e:
                        st.error(f"Error fetching file {key}: {e}")
                        continue

                if domain_n in df_10m['Domain'].values:
                    outcome_message = "The URL is predicted to be safe."
                else:
                    probabilities = model.predict_proba(data_scaled)
                    predicted_class = np.argmax(probabilities[0])
                    confidence = np.max(probabilities[0])
                    if predicted_class == 0:
                        st.write(confidence)
                        if confidence > 0.80:
                            outcome_message = "The URL is predicted to be Safe."
                        else:
                            outcome_message = "The URL is predicted to be Suspicious."
                    else:
                        st.write(confidence)
                        if predicted_class == 1:
                            if confidence > 0.85:
                                outcome_message = "The URL is predicted to be Suspicious."
                            else:
                                outcome_message = "The URL is predicted to be Safe."
                st.write(outcome_message)

                logger_msg = f"{datetime.datetime.now()}   Outcome for URL- {url} is {outcome_message}"
                Bucket = 'marketplace-scanner'
                file_name = 'Test_Diti/logs.txt'

                try:
                    existing_log_buffer = io.BytesIO()
                    s3.download_fileobj(Bucket, file_name, existing_log_buffer)
                    existing_log_buffer.seek(0)
                    existing_log_content = existing_log_buffer.read().decode('utf-8')
                    timestamp = datetime.datetime.now()
                    new_log_entry = f"{timestamp} - {logger_msg}\n"
                    updated_log_content = existing_log_content + new_log_entry

                except s3.exceptions.NoSuchKey:
                    timestamp = datetime.datetime.now()
                    updated_log_content = f"{timestamp} - {logger_msg}\n"
                    st.warning("`logs.txt` not found on S3. Creating a new log file.")

                log_buffer = io.BytesIO(updated_log_content.encode('utf-8'))
                s3.upload_fileobj(log_buffer, Bucket, file_name)
                st.success("`features.csv` updated successfully.")
                st.success("`logs.txt` updated successfully.")

        except Exception as e:
            st.error(f"Error processing the URL: {e}")

if __name__ == "__main__":
    main()
