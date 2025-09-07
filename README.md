SmartCareOptimizer
A healthcare management system that helps patients find the best healthcare providers based on their needs, location, and insurance coverage.

Features
Find healthcare providers by specialty and location

Calculate insurance coverage and costs

Book appointments with providers

Get detailed reports with provider information

User accounts with secure login

Installation
Clone this repository:

bash
git clone https://github.com/Hema1006/SmartCareOptimizer.git
cd SmartCareOptimizer
Install required packages:

bash
pip install -r requirements.txt
Set up the database:

Make sure you have MySQL installed

Create a database named smart_care

Update the database connection in the code if needed

Add your data files:

Place member data in dataset/members_large_deterministic.csv

Place provider data in dataset/providers_enhanced.csv

Run the application:

bash
python app.py
Open your browser and go to http://localhost:5000

Usage
Create an account or login

Enter a member ID to find suitable healthcare providers

View provider details, costs, and quality ratings

Book appointments with providers

Download PDF reports with provider information

Data Requirements
The system needs two CSV files:

Member data with ID, location, and insurance information

Provider data with specialty, location, and quality metrics

Support
For questions or issues, please contact the repository owner.
