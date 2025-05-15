import os
import sqlite3
import hashlib
import cv2
import pytesseract
import numpy as np
import keyring
import secrets
import string
import threading
import base64
import json
from keyring.errors import PasswordDeleteError
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory, render_template_string, Response
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_cors import CORS
from d3graph import d3graph, vec2adjmat
from werkzeug.utils import secure_filename
import pandas as pd
from datetime import datetime, timedelta
import plotly.graph_objects as go
from plotly.subplots import make_subplots

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_BUILD = BASE_DIR.parent / 'frontend' / 'build'
STATIC_DIR = BASE_DIR / 'static'
UPLOAD_DIR = BASE_DIR / 'uploads'
UPLOAD_DIR.mkdir(exist_ok=True)
STATIC_DIR.mkdir(exist_ok=True)
app = Flask(__name__, static_folder=str(FRONTEND_BUILD), static_url_path='/')
app.secret_key = 'replace-with-a-secure-secret'
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
CORS(app, supports_credentials=True)

DB_PATH = BASE_DIR / 'federal_data.db'
EO_DB_PATH = BASE_DIR / 'eos.db'
root_username = os.environ.get("ROOT_USERNAME", "aloha@teamtulsi.com")
root_password = os.environ.get("ROOT_PASSWORD", "TulsiGabbard")
root_pw_hash = bcrypt.generate_password_hash(root_password).decode('utf-8')
aloha_admin = root_username

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, pw_hash TEXT NOT NULL, is_admin INTEGER NOT NULL)')
    c.execute('CREATE TABLE IF NOT EXISTS documents (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT NOT NULL, uploader TEXT NOT NULL)')
    c.execute('CREATE TABLE IF NOT EXISTS user_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, doc_id INTEGER, action TEXT)')
    c.execute('CREATE TABLE IF NOT EXISTS user_gpg (username TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, passphrase TEXT NOT NULL)')
    c.execute('CREATE TABLE IF NOT EXISTS user_credentials (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, cred_type TEXT, enc_data TEXT)')
    c.execute('SELECT * FROM users WHERE username=?', (root_username,))
    if not c.fetchone():
        c.execute('INSERT INTO users (username, pw_hash, is_admin) VALUES (?,?,?)', (root_username, root_pw_hash, 1))
        conn.commit()
    conn.close()

init_db()

def init_eo_db():
    DATA = [
        {"eo_number": 14147, "title": "Ending the Weaponization of the Federal Government", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14148, "title": "Initial Rescissions of Harmful Executive Orders and Actions", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14149, "title": "Restoring Freedom of Speech and Ending Federal Censorship", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14150, "title": "America First Policy Directive to the Secretary of State", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14151, "title": "Ending Radical and Wasteful Government DEI Programs and Preferencing", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14152, "title": "Holding Former Government Officials Accountable for Election Interference and Improper Disclosure of Sensitive Governmental Information", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14153, "title": "Unleashing Alaska's Extraordinary Resource Potential", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14154, "title": "Unleashing American Energy", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14155, "title": "Withdrawing the United States From the World Health Organization", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14156, "title": "Declaring a National Energy Emergency", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14157, "title": "Designating Cartels and Other Organizations as Foreign Terrorist Organizations and Specially Designated Global Terrorists", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14158, "title": "Establishing and Implementing the President's \"Department of Government Efficiency\"", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14159, "title": "Protecting the American People Against Invasion", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14160, "title": "Protecting the Meaning and Value of American Citizenship", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14161, "title": "Protecting the United States from Foreign Terrorists and Other National Security and Public Safety Threats", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14162, "title": "Putting America First in International Environmental Agreements", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14163, "title": "Realigning the United States Refugee Admissions Program", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14164, "title": "Restoring the Death Penalty and Protecting Public Safety", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14165, "title": "Securing Our Borders", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14166, "title": "Application of Protecting Americans From Foreign Adversary Controlled Applications Act to TikTok", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14167, "title": "Clarifying the Military's Role in Protecting the Territorial Integrity of the United States", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14168, "title": "Defending Women From Gender Ideology Extremism and Restoring Biological Truth to the Federal Government", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14169, "title": "Reevaluating and Realigning United States Foreign Aid", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14170, "title": "Reforming the Federal Hiring Process and Restoring Merit to Government Service", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14171, "title": "Restoring Accountability to Policy-Influencing Positions Within the Federal Workforce", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14172, "title": "Restoring Names That Honor American Greatness", "issue_date": "2025-01-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14173, "title": "Ending Illegal Discrimination and Restoring Merit-Based Opportunity", "issue_date": "2025-01-21", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14174, "title": "Revocation of Certain Executive Orders", "issue_date": "2025-01-21", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14175, "title": "Designation of Ansar Allah as a Foreign Terrorist Organization", "issue_date": "2025-01-22", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14176, "title": "Declassification of Records Concerning the Assassinations of President John F. Kennedy, Senator Robert F. Kennedy, and the Reverend Dr. Martin Luther King, Jr.", "issue_date": "2025-01-23", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14177, "title": "President's Council of Advisors on Science and Technology", "issue_date": "2025-01-23", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14178, "title": "Strengthening American Leadership in Digital Financial Technology", "issue_date": "2025-01-23", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14179, "title": "Removing Barriers to American Leadership in Artificial Intelligence", "issue_date": "2025-01-23", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14180, "title": "Council To Assess the Federal Emergency Management Agency", "issue_date": "2025-01-24", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14181, "title": "Emergency Measures To Provide Water Resources in California and Improve Disaster Response in Certain Areas", "issue_date": "2025-01-24", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14182, "title": "Enforcing the Hyde Amendment", "issue_date": "2025-01-24", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14183, "title": "Prioritizing Military Excellence and Readiness", "issue_date": "2025-01-27", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14184, "title": "Reinstating Service Members Discharged Under the Military's COVID-19 Vaccination Mandate", "issue_date": "2025-01-27", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14185, "title": "Restoring America's Fighting Force", "issue_date": "2025-01-27", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14186, "title": "The Iron Dome for America", "issue_date": "2025-01-27", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14187, "title": "Protecting Children From Chemical and Surgical Mutilation", "issue_date": "2025-01-28", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14188, "title": "Additional Measures To Combat Anti-Semitism", "issue_date": "2025-01-29", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14189, "title": "Celebrating America's 250th Birthday", "issue_date": "2025-01-29", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14190, "title": "Ending Radical Indoctrination in K-12 Schooling", "issue_date": "2025-01-29", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14191, "title": "Expanding Educational Freedom and Opportunity for Families", "issue_date": "2025-01-29", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14192, "title": "Unleashing Prosperity Through Deregulation", "issue_date": "2025-01-31", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14193, "title": "Imposing Duties To Address the Flow of Illicit Drugs Across Our Northern Border", "issue_date": "2025-02-01", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14194, "title": "Imposing Duties To Address the Situation at Our Southern Border", "issue_date": "2025-02-01", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14195, "title": "Imposing Duties To Address the Synthetic Opioid Supply Chain in the People's Republic of China", "issue_date": "2025-02-01", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14196, "title": "A Plan for Establishing a United States Sovereign Wealth Fund", "issue_date": "2025-02-03", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14197, "title": "Progress on the Situation at Our Northern Border", "issue_date": "2025-02-03", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14198, "title": "Progress on the Situation at Our Southern Border", "issue_date": "2025-02-03", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14199, "title": "Withdrawing the United States From and Ending Funding to Certain United Nations Organizations", "issue_date": "2025-02-04", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14200, "title": "Amendment to Duties Addressing the Synthetic Opioid Supply Chain in the People's Republic of China", "issue_date": "2025-02-05", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14201, "title": "Keeping Men Out of Women's Sports", "issue_date": "2025-02-05", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14202, "title": "Eradicating Anti-Christian Bias", "issue_date": "2025-02-06", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14203, "title": "Imposing Sanctions on the International Criminal Court", "issue_date": "2025-02-06", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14204, "title": "Addressing Egregious Actions of the Republic of South Africa", "issue_date": "2025-02-07", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14205, "title": "Establishment of the White House Faith Office", "issue_date": "2025-02-07", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14206, "title": "Protecting Second Amendment Rights", "issue_date": "2025-02-07", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14207, "title": "Eliminating the Federal Executive Institute", "issue_date": "2025-02-10", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14208, "title": "Ending Procurement and Forced Use of Paper Straws", "issue_date": "2025-02-10", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14209, "title": "Pausing Foreign Corrupt Practices Act Enforcement To Further American Economic and National Security", "issue_date": "2025-02-10", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14210, "title": "Implementing the President's \"Department of Government Efficiency\" Workforce Optimization Initiative", "issue_date": "2025-02-11", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14211, "title": "One Voice for America's Foreign Relations", "issue_date": "2025-02-12", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14212, "title": "Establishing the President's Make America Healthy Again Commission", "issue_date": "2025-02-13", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14213, "title": "Establishing the National Energy Dominance Council", "issue_date": "2025-02-14", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14214, "title": "Keeping Education Accessible and Ending COVID-19 Vaccine Mandates in Schools", "issue_date": "2025-02-14", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14215, "title": "Ensuring Accountability for All Agencies", "issue_date": "2025-02-18", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14216, "title": "Expanding Access to In Vitro Fertilization", "issue_date": "2025-02-18", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14217, "title": "Commencing the Reduction of the Federal Bureaucracy", "issue_date": "2025-02-19", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14218, "title": "Ending Taxpayer Subsidization of Open Borders", "issue_date": "2025-02-19", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14219, "title": "Ensuring Lawful Governance and Implementing the President's \"Department of Government Efficiency\" Deregulatory Initiative", "issue_date": "2025-02-19", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14220, "title": "Addressing the Threat to National Security From Imports of Copper", "issue_date": "2025-02-25", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14221, "title": "Making America Healthy Again by Empowering Patients With Clear, Accurate, and Actionable Healthcare Pricing Information", "issue_date": "2025-02-25", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14222, "title": "Implementing the President's \"Department of Government Efficiency\" Cost Efficiency Initiative", "issue_date": "2025-02-26", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14223, "title": "Addressing the Threat to National Security From Imports of Timber, Lumber, and Their Derivative Products", "issue_date": "2025-03-01", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14224, "title": "Designating English as the Official Language of the United States", "issue_date": "2025-03-01", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14225, "title": "Immediate Expansion of American Timber Production", "issue_date": "2025-03-01", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14226, "title": "Amendment to Duties To Address the Flow of Illicit Drugs Across Our Northern Border", "issue_date": "2025-03-02", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14227, "title": "Amendment to Duties To Address the Situation at Our Southern Border", "issue_date": "2025-03-02", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14228, "title": "Further Amendment to Duties Addressing the Synthetic Opioid Supply Chain in the People's Republic of China", "issue_date": "2025-03-03", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14229, "title": "Honoring Jocelyn Nungaray", "issue_date": "2025-03-04", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14230, "title": "Addressing Risks From Perkins Coie LLP", "issue_date": "2025-03-06", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14231, "title": "Amendment to Duties To Address the Flow of Illicit Drugs Across Our Northern Border", "issue_date": "2025-03-06", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14232, "title": "Amendment to Duties To Address the Flow of Illicit Drugs Across Our Southern Border", "issue_date": "2025-03-06", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14233, "title": "Establishment of the Strategic Bitcoin Reserve and United States Digital Asset Stockpile", "issue_date": "2025-03-06", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14234, "title": "Establishing the White House Task Force on the FIFA World Cup 2026", "issue_date": "2025-03-07", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14235, "title": "Restoring Public Service Loan Forgiveness", "issue_date": "2025-03-07", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14236, "title": "Additional Rescissions of Harmful Executive Orders and Actions", "issue_date": "2025-03-14", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14237, "title": "Addressing Risks From Paul Weiss", "issue_date": "2025-03-14", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14238, "title": "Continuing the Reduction of the Federal Bureaucracy", "issue_date": "2025-03-14", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14239, "title": "Achieving Efficiency Through State and Local Preparedness", "issue_date": "2025-03-18", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14240, "title": "Eliminating Waste and Saving Taxpayer Dollars by Consolidating Procurement", "issue_date": "2025-03-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14241, "title": "Immediate Measures To Increase American Mineral Production", "issue_date": "2025-03-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14242, "title": "Improving Education Outcomes by Empowering Parents, States, and Communities", "issue_date": "2025-03-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14243, "title": "Stopping Waste, Fraud, and Abuse by Eliminating Information Silos", "issue_date": "2025-03-20", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14244, "title": "Addressing Remedial Action by Paul Weiss", "issue_date": "2025-03-21", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14245, "title": "Imposing Tariffs on Countries Importing Venezuelan Oil", "issue_date": "2025-03-24", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14246, "title": "Addressing Risks From Jenner & Block", "issue_date": "2025-03-25", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14247, "title": "Modernizing Payments To and From America's Bank Account", "issue_date": "2025-03-25", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14248, "title": "Preserving and Protecting the Integrity of American Elections", "issue_date": "2025-03-25", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14249, "title": "Protecting America's Bank Account Against Fraud, Waste, and Abuse", "issue_date": "2025-03-25", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14250, "title": "Addressing Risks From WilmerHale", "issue_date": "2025-03-27", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14251, "title": "Exclusions From Federal Labor-Management Relations Programs", "issue_date": "2025-03-27", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14252, "title": "Making the District of Columbia Safe and Beautiful", "issue_date": "2025-03-27", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14253, "title": "Restoring Truth and Sanity to American History", "issue_date": "2025-03-27", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14254, "title": "Combating Unfair Practices in the Live Entertainment Market", "issue_date": "2025-03-31", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14255, "title": "Establishing the United States Investment Accelerator", "issue_date": "2025-03-31", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14256, "title": "Further Amendment to Duties Addressing the Synthetic Opioid Supply Chain in the People's Republic of China as Applied to Low-Value Imports", "issue_date": "2025-04-02", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14257, "title": "Regulating Imports With a Reciprocal Tariff To Rectify Trade Practices That Contribute to Large and Persistent Annual United States Goods Trade Deficits", "issue_date": "2025-04-02", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14258, "title": "Extending the TikTok Enforcement Delay", "issue_date": "2025-04-04", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14259, "title": "Amendment to Reciprocal Tariffs and Updated Duties as Applied to Low-Value Imports From the People's Republic of China", "issue_date": "2025-04-08", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14260, "title": "Protecting American Energy From State Overreach", "issue_date": "2025-04-08", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14261, "title": "Reinvigorating America's Beautiful Clean Coal Industry and Amending Executive Order 14241", "issue_date": "2025-04-08", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14262, "title": "Strengthening the Reliability and Security of the United States Electric Grid", "issue_date": "2025-04-08", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14263, "title": "Addressing Risks From Susman Godfrey", "issue_date": "2025-04-09", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14264, "title": "Maintaining Acceptable Water Pressure in Showerheads", "issue_date": "2025-04-09", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14265, "title": "Modernizing Defense Acquisitions and Spurring Innovation in the Defense Industrial Base", "issue_date": "2025-04-09", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14266, "title": "Modifying Reciprocal Tariff Rates To Reflect Trading Partner Retaliation and Alignment", "issue_date": "2025-04-09", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14267, "title": "Reducing Anti-Competitive Regulatory Barriers", "issue_date": "2025-04-09", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14268, "title": "Reforming Foreign Defense Sales To Improve Speed and Accountability", "issue_date": "2025-04-09", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14269, "title": "Restoring America's Maritime Dominance", "issue_date": "2025-04-09", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14270, "title": "Zero-Based Regulatory Budgeting To Unleash American Energy", "issue_date": "2025-04-09", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14271, "title": "Ensuring Commercial, Cost-Effective Solutions in Federal Contracts", "issue_date": "2025-04-15", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14272, "title": "Ensuring National Security and Economic Resilience Through Section 232 Actions on Processed Critical Minerals and Derivative Products", "issue_date": "2025-04-15", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14273, "title": "Lowering Drug Prices by Once Again Putting Americans First", "issue_date": "2025-04-15", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14274, "title": "Restoring Common Sense to Federal Office Space Management", "issue_date": "2025-04-15", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14275, "title": "Restoring Common Sense to Federal Procurement", "issue_date": "2025-04-15", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14276, "title": "Restoring American Seafood Competitiveness", "issue_date": "2025-04-17", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14277, "title": "Advancing Artificial Intelligence Education for American Youth", "issue_date": "2025-04-23", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14278, "title": "Preparing Americans for High-Paying Skilled Trade Jobs of the Future", "issue_date": "2025-04-23", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14279, "title": "Reforming Accreditation To Strengthen Higher Education", "issue_date": "2025-04-23", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14280, "title": "Reinstating Commonsense School Discipline Policies", "issue_date": "2025-04-23", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14281, "title": "Restoring Equality of Opportunity and Meritocracy", "issue_date": "2025-04-23", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14282, "title": "Transparency Regarding Foreign Influence at American Universities", "issue_date": "2025-04-23", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14283, "title": "White House Initiative To Promote Excellence and Innovation at Historically Black Colleges and Universities", "issue_date": "2025-04-23", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14284, "title": "Strengthening Probationary Periods in the Federal Service", "issue_date": "2025-04-24", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14285, "title": "Unleashing America's Offshore Critical Minerals and Resources", "issue_date": "2025-04-24", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14286, "title": "Enforcing Commonsense Rules of the Road for America's Truck Drivers", "issue_date": "2025-04-28", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14287, "title": "Protecting American Communities From Criminal Aliens", "issue_date": "2025-04-28", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14288, "title": "Strengthening and Unleashing America's Law Enforcement To Pursue Criminals and Protect Innocent Citizens", "issue_date": "2025-04-28", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14289, "title": "Addressing Certain Tariffs on Imported Articles", "issue_date": "2025-04-29", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14290, "title": "Ending Taxpayer Subsidization of Biased Media", "issue_date": "2025-05-01", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14291, "title": "Establishment of the Religious Liberty Commission", "issue_date": "2025-05-01", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14292, "title": "Improving the Safety and Security of Biological Research", "issue_date": "2025-05-05", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None},
        {"eo_number": 14293, "title": "Regulatory Relief To Promote Domestic Production of Critical Medicines", "issue_date": "2025-05-05", "status": "issued", "rejection_date": None, "link": None, "rejection_link": None}
    ]
    conn = sqlite3.connect(EO_DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS eos(
        eo_number INTEGER PRIMARY KEY,
        title TEXT,
        issue_date TEXT,
        status TEXT,
        rejection_date TEXT,
        link TEXT,
        rejection_link TEXT
    )""")
    for d in DATA:
        c.execute(
            """
            INSERT INTO eos(eo_number, title, issue_date, status, rejection_date, link, rejection_link)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(eo_number) DO UPDATE SET
                title=excluded.title,
                issue_date=excluded.issue_date,
                status=excluded.status,
                rejection_date=COALESCE(excluded.rejection_date, eos.rejection_date),
                link=COALESCE(excluded.link, eos.link),
                rejection_link=COALESCE(excluded.rejection_link, eos.rejection_link)
            """,
            (
                d["eo_number"],
                d["title"],
                d["issue_date"],
                d["status"],
                d["rejection_date"],
                d["link"],
                d["rejection_link"],
            ),
        )
    conn.commit()
    conn.close()

init_eo_db()

aes_master_key = Fernet.generate_key()
cipher_suite = Fernet(aes_master_key)

class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT username, pw_hash, is_admin FROM users WHERE username=?', (username,))
    row = c.fetchone()
    conn.close()
    if row:
        u = User()
        u.id = row[0]
        u.is_admin = bool(row[2])
        return u
    return None

@app.after_request
def after_request(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers.pop('ETag', None)
    if response.status_code == 304:
        response.status_code = 200
    return response

@app.post('/api/register')
def register():
    data = request.get_json()
    if not data or not all(k in data for k in ('username', 'password')):
        return jsonify(success=False), 400
    username = data['username']
    password = data['password']
    if username == root_username:
        return jsonify(success=False), 403
    pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, pw_hash, is_admin) VALUES (?,?,?)', (username, pw_hash, 0))
        conn.commit()
    except:
        conn.close()
        return jsonify(success=False), 400
    conn.close()
    return jsonify(success=True)

@app.post('/api/login')
def login():
    data = request.get_json()
    if not data:
        return jsonify(success=False), 400
    username = data.get('username')
    password = data.get('password')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT pw_hash, is_admin FROM users WHERE username=?', (username,))
    row = c.fetchone()
    conn.close()
    if row and bcrypt.check_password_hash(row[0], password):
        u = User()
        u.id = username
        u.is_admin = bool(row[1])
        login_user(u)
        return jsonify(success=True)
    return jsonify(success=False), 401

@app.post('/api/logout')
@login_required
def logout():
    logout_user()
    return jsonify(success=True)

@app.get('/api/graph')
@login_required
def graph():
    source = ['node A','node F','node B','node B','node B','node A','node C','node Z']
    target = ['node F','node B','node J','node F','node F','node M','node M','node A']
    weight = [5.56,0.5,0.64,0.23,0.9,3.28,0.5,0.45]
    adjmat = vec2adjmat(source, target, weight=weight)
    d3 = d3graph()
    d3.graph(adjmat)
    filepath = STATIC_DIR / 'graph.html'
    d3.show(filepath=str(filepath))
    return send_from_directory(STATIC_DIR, 'graph.html')

@app.post('/api/upload')
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify(success=False), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify(success=False), 400
    filename = secure_filename(file.filename)
    file.save(str(UPLOAD_DIR / filename))
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO documents (filename, uploader) VALUES (?,?)', (filename, current_user.id))
    doc_id = c.lastrowid
    c.execute('INSERT INTO user_logs (username, doc_id, action) VALUES (?,?,?)', (current_user.id, doc_id, 'upload'))
    conn.commit()
    conn.close()
    return jsonify(success=True)

@app.get('/api/docs')
@login_required
def list_docs():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, filename, uploader FROM documents')
    rows = c.fetchall()
    docs = [{'id':r[0], 'filename':r[1], 'uploader':r[2]} for r in rows]
    conn.close()
    return jsonify(docs=docs)

@app.get('/api/leak_risk')
@login_required
def leak_risk():
    if not hasattr(current_user, 'is_admin') or not current_user.is_admin:
        return jsonify(success=False), 403
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT username FROM users')
    all_users = c.fetchall()
    conn.close()
    risk = {}
    for u in all_users:
        risk[u[0]] = float(np.random.rand(1))
    return jsonify(risk=risk)

@app.post('/api/set_admin')
@login_required
def set_admin():
    if not hasattr(current_user, 'is_admin') or not current_user.is_admin:
        return jsonify(success=False), 403
    data = request.get_json()
    username = data.get('username')
    is_admin_flag = data.get('is_admin', False)
    if username == root_username:
        return jsonify(success=False), 403
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE users SET is_admin=? WHERE username=?', (1 if is_admin_flag else 0, username))
    conn.commit()
    conn.close()
    return jsonify(success=True)

@app.get('/api/tesseract_ocr')
@login_required
def tesseract_ocr():
    filename = request.args.get('filename')
    if not filename:
        return jsonify(success=False), 400
    path = UPLOAD_DIR / filename
    if not path.exists():
        return jsonify(success=False), 404
    img = cv2.imread(str(path))
    text = pytesseract.image_to_string(img)
    return jsonify(ocr=text)

@app.post('/api/create_gpg_key')
@login_required
def create_gpg_key():
    passphrase = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    private_pem = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(passphrase.encode())).decode()
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    fingerprint = hashlib.sha256(public_pem.encode()).hexdigest()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT fingerprint FROM user_gpg WHERE username=?', (current_user.id,))
    existing = c.fetchone()
    if existing:
        conn.close()
        return jsonify(success=False), 400
    c.execute('INSERT INTO user_gpg (username, fingerprint, passphrase) VALUES (?,?,?)', (current_user.id, fingerprint, passphrase))
    conn.commit()
    conn.close()
    keyring.set_password('app_private', current_user.id, private_pem)
    keyring.set_password('app_public', current_user.id, public_pem)
    return jsonify(success=True, fingerprint=fingerprint, passphrase=passphrase)

@app.post('/api/sign_gpg')
@login_required
def sign_gpg():
    if current_user.id != aloha_admin and not (hasattr(current_user, 'is_admin') and current_user.is_admin):
        return jsonify(success=False), 403
    data = request.get_json()
    message = data.get('message', '')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT passphrase FROM user_gpg WHERE username=?', (current_user.id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify(success=False), 400
    passphrase = row[0]
    priv_pem = keyring.get_password('app_private', current_user.id)
    if not priv_pem:
        return jsonify(success=False), 500
    private_key = serialization.load_pem_private_key(priv_pem.encode(), password=passphrase.encode(), backend=default_backend())
    signature = private_key.sign(message.encode(), asym_padding.PKCS1v15(), hashes.SHA256())
    signed_message = json.dumps({'msg': message, 'sig': base64.b64encode(signature).decode()})
    return jsonify(success=True, signature=signed_message)

@app.post('/api/verify_gpg')
@login_required
def verify_gpg():
    data = request.get_json()
    signed_message = data.get('signed_message', '')
    try:
        obj = json.loads(signed_message)
        msg = obj['msg']
        sig = base64.b64decode(obj['sig'])
    except:
        return jsonify(verified=False)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT username, fingerprint, passphrase FROM user_gpg')
    rows = c.fetchall()
    conn.close()
    for username, fp, pp in rows:
        pub_pem = keyring.get_password('app_public', username)
        if not pub_pem:
            continue
        pub_key = serialization.load_pem_public_key(pub_pem.encode(), backend=default_backend())
        try:
            pub_key.verify(sig, msg.encode(), asym_padding.PKCS1v15(), hashes.SHA256())
            return jsonify(verified=True, fingerprint=fp)
        except:
            continue
    return jsonify(verified=False)

@app.post('/api/encrypt_gpg')
@login_required
def encrypt_gpg():
    data = request.get_json()
    recipient_username = data.get('recipient')
    plaintext = data.get('plaintext', '')
    pub_pem = keyring.get_password('app_public', recipient_username)
    if not pub_pem:
        return jsonify(success=False), 400
    pub_key = serialization.load_pem_public_key(pub_pem.encode(), backend=default_backend())
    aes_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend()).encryptor()
    ct = encryptor.update(plaintext.encode()) + encryptor.finalize()
    tag = encryptor.tag
    enc_key = pub_key.encrypt(aes_key, asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    payload = {'ekey': base64.b64encode(enc_key).decode(),'nonce': base64.b64encode(nonce).decode(),'tag': base64.b64encode(tag).decode(),'ct': base64.b64encode(ct).decode()}
    return jsonify(success=True, ciphertext=json.dumps(payload))

@app.post('/api/decrypt_gpg')
@login_required
def decrypt_gpg():
    data = request.get_json()
    ciphertext = data.get('ciphertext', '')
    try:
        payload = json.loads(ciphertext)
        enc_key = base64.b64decode(payload['ekey'])
        nonce = base64.b64decode(payload['nonce'])
        tag = base64.b64decode(payload['tag'])
        ct = base64.b64decode(payload['ct'])
    except:
        return jsonify(success=False), 400
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT passphrase FROM user_gpg WHERE username=?', (current_user.id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify(success=False), 400
    passphrase = row[0]
    priv_pem = keyring.get_password('app_private', current_user.id)
    if not priv_pem:
        return jsonify(success=False), 500
    private_key = serialization.load_pem_private_key(priv_pem.encode(), password=passphrase.encode(), backend=default_backend())
    try:
        aes_key = private_key.decrypt(enc_key, asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend()).decryptor()
        plaintext = decryptor.update(ct) + decryptor.finalize()
        return jsonify(success=True, plaintext=plaintext.decode())
    except:
        return jsonify(success=False), 500

@app.post('/api/aes_encrypt')
@login_required
def aes_encrypt():
    data = request.get_json()
    plaintext = data.get('plaintext', '')
    encrypted = cipher_suite.encrypt(plaintext.encode()).decode()
    return jsonify(encrypted=encrypted)

@app.post('/api/aes_decrypt')
@login_required
def aes_decrypt():
    data = request.get_json()
    ciphertext = data.get('ciphertext', '')
    try:
        dec = cipher_suite.decrypt(ciphertext.encode()).decode()
        return jsonify(decrypted=dec)
    except:
        return jsonify(success=False), 400

@app.post('/api/add_credential')
@login_required
def add_credential():
    data = request.get_json()
    cred_type = data.get('type', '')
    cred_value = data.get('value', '')
    enc_data = cipher_suite.encrypt(cred_value.encode()).decode()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO user_credentials (username, cred_type, enc_data) VALUES (?,?,?)', (current_user.id, cred_type, enc_data))
    conn.commit()
    conn.close()
    return jsonify(success=True)

@app.get('/api/get_credentials')
@login_required
def get_credentials():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, cred_type, enc_data FROM user_credentials WHERE username=?', (current_user.id,))
    rows = c.fetchall()
    creds = []
    for r in rows:
        try:
            dec_data = cipher_suite.decrypt(r[2].encode()).decode()
            creds.append({'id': r[0], 'type': r[1], 'value': dec_data})
        except:
            creds.append({'id': r[0], 'type': r[1], 'value': 'Error'})
    conn.close()
    return jsonify(credentials=creds)

@app.get('/api/file_hash')
@login_required
def file_hash():
    filename = request.args.get('filename')
    if not filename:
        return jsonify(success=False), 400
    path = UPLOAD_DIR / filename
    if not path.exists():
        return jsonify(success=False), 404
    hasher = hashlib.sha256()
    with open(path, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return jsonify(hash=hasher.hexdigest())

@app.post('/api/leak_detect')
@login_required
def leak_detect():
    data = request.get_json()
    text = data.get('text', '')
    leaked_words = ['topsecret', 'classified', 'nuclear', 'attackplan']
    for w in leaked_words:
        if w in text.lower():
            return jsonify(leaked=True, word=w)
    return jsonify(leaked=False)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    target = FRONTEND_BUILD / path
    if path and target.exists():
        return send_from_directory(FRONTEND_BUILD, path)
    return send_from_directory(FRONTEND_BUILD, 'index.html')

def load_data():
    conn = sqlite3.connect(EO_DB_PATH)
    df = pd.read_sql_query("SELECT * FROM eos", conn)
    conn.close()
    df["issue_date"] = pd.to_datetime(df["issue_date"])
    df["rejection_date"] = pd.to_datetime(df["rejection_date"])
    TODAY = datetime.utcnow().date()
    RECENT_CUT = TODAY - timedelta(days=90)
    def status(r):
        if pd.notna(r["rejection_date"]):
            return "rejected"
        if r["issue_date"].date() >= RECENT_CUT:
            return "pending"
        return "issued"
    df["status"] = df.apply(status, axis=1)
    df["display_date"] = df["issue_date"]
    return df.sort_values("issue_date")

@app.route("/trump")
@login_required
def trump():
    df = load_data()
    if df.empty:
        return "<p>No data available.</p>"
    counts = df["status"].value_counts().reindex(["issued","pending","rejected"], fill_value=0)
    fig = make_subplots(rows=2, cols=1, shared_xaxes=False, vertical_spacing=0.15, row_heights=[0.7, 0.3])
    for _, r in df.iterrows():
        start = r["issue_date"]
        end = r["rejection_date"] if pd.notna(r["rejection_date"]) else datetime.utcnow()
        fig.add_trace(
            go.Scatter(
                x=[start, end],
                y=[r["eo_number"], r["eo_number"]],
                mode="lines",
                line=dict(color="#FFD700", width=4),
                showlegend=False,
            ), row=1, col=1,
        )
        if r["status"] == "rejected":
            fig.add_trace(
                go.Scatter(
                    x=[r["rejection_date"]],
                    y=[r["eo_number"]],
                    mode="markers",
                    marker=dict(color="green", symbol="x", size=9, line=dict(width=1, color="black")),
                    showlegend=False,
                ), row=1, col=1,
            )
        elif r["status"] == "pending":
            fig.add_trace(
                go.Scatter(
                    x=[r["issue_date"]],
                    y=[r["eo_number"]],
                    mode="markers",
                    marker=dict(color="yellow", symbol="triangle-up", size=9, line=dict(width=1, color="black")),
                    showlegend=False,
                ), row=1, col=1,
            )
    fig.add_trace(
        go.Bar(
            x=list(counts.index),
            y=counts.values,
            marker_color=["#FFD700","yellow","green"],
            text=counts.values,
            textposition="auto",
        ), row=2, col=1,
    )
    fig.update_layout(
        title="Trump Executive Orders",
        xaxis_title="Date",
        yaxis_title="EO Number",
        xaxis2_title="Status",
        yaxis2_title="Count",
        template="plotly_white",
        height=750,
        showlegend=False,
    )
    graph_html = fig.to_html(full_html=False, include_plotlyjs="cdn")
    df_issued = df[df["status"]=="issued"].sort_values("issue_date").copy()
    df_issued["date"] = df_issued["issue_date"].dt.strftime("%B %d, %Y")
    issued_list = df_issued[["eo_number","title","date"]].to_dict("records")
    df_rej = df[df["status"]=="rejected"].sort_values("rejection_date").copy()
    df_rej["date"] = df_rej["rejection_date"].dt.strftime("%B %d, %Y")
    rejected_list = df_rej[["eo_number","title","date"]].to_dict("records")
    return render_template_string(
        """<!doctype html><meta charset="utf-8"><title>Trump EO Graph</title>
        <h1>Trump EO d3/Plotly Hybrid</h1>
        <div>{{ graph|safe }}</div>
        <hr>
        <h2>Issued ({{ issued_count }})</h2>
        <ul>{% for i in issued %}<li>EO {{ i.eo_number }}: {{ i.title }} ({{ i.date }})</li>{% endfor %}</ul>
        <h2>Rejected ({{ rejected_count }})</h2>
        <ul>{% for x in rejected %}<li>EO {{ x.eo_number }}: {{ x.title }} ({{ x.date }})</li>{% endfor %}</ul>""",
        graph=graph_html,
        issued=issued_list,
        rejected=rejected_list,
        issued_count=len(issued_list),
        rejected_count=len(rejected_list),
    )

@app.route("/data.csv")
@login_required
def data_csv():
    df = load_data()
    return Response(df.to_csv(index=False), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=gop_trump_eos.csv"})

@app.route("/data.json")
@login_required
def data_json():
    df = load_data()
    return Response(df.to_json(orient="records", date_format="iso"), mimetype="application/json")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
