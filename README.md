Phishing Web Detector

This project is a phishing URL detection system developed using machine learning and a FastAPI backend.
It helps identify whether a given website link is phishing or legitimate by analyzing characteristics of the URL.

Overview

Phishing attacks commonly use fake or misleading links to steal sensitive information.
This project focuses on building a backend service that accepts a URL as input, processes it using feature extraction techniques, and returns a prediction using a trained machine learning model.

The goal is to understand how machine learning and backend APIs can be combined to solve real-world cybersecurity problems.

Technologies Used

Python
FastAPI
Scikit-learn
Pandas
NumPy

Working Flow

User provides a URL as input
The system extracts important features from the URL
A machine learning model evaluates the extracted features
The result is returned as an API response

Project Structure

Phising_Web_Detector-KKlab
dataset
app.py – FastAPI backend application
feature_extraction.py – URL feature processing logic
model.py – Machine learning model handling
requirements.txt
README.md

How to Run the Project

Clone the repository

git clone https://github.com/KK-coders-SDE/Phising_Web_Detector-KKlab.git

Install required dependencies

pip install -r requirements.txt

Start the FastAPI server

uvicorn app:app --reload

Open the API documentation in the browser

http://127.0.0.1:8000/docs

Use Cases

Learning machine learning based classification
Understanding backend API development using FastAPI
Exploring basic cybersecurity concepts related to phishing detection

Author

Koushik Kumar
GitHub: https://github.com/KK-coders-SDE
