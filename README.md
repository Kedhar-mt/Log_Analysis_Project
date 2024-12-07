# Log_Analysis_Project
This project performs log file analysis by parsing server log files to extract useful insights such as IP request counts, most accessed endpoints, and suspicious activities like failed login attempts. It helps monitor web application behavior, identify potential security threats, and gain insights into user activity.

# Features
IP Request Count: Counts the number of requests made by each IP address in the log file. Most Accessed Endpoint: Identifies the most frequently accessed endpoint (e.g., /login, /home). Suspicious Activity Detection: Flags IP addresses with failed login attempts exceeding a specified threshold (e.g., more than 10 failed login attempts). CSV Output: Results are saved in a CSV file for easy viewing and analysis.

# Files Included
sample.log: Sample log file for analysis (you can replace it with your own log files). log_analysis.py: Main Python script that parses the log file, processes data, and generates reports. log_analysis_results.csv: CSV output file containing the analysis results, including IP request counts, most accessed endpoints, and suspicious activity.

# Prerequisites
Python 3.x re and csv modules (comes with Python standard library) Sample log file (sample.log) formatted similarly to common web server logs.

# How to Run
Clone this repository: git clone https://github.com/your-username/your-repository-name.git Navigate to the project directory:

cd your-repository-name Run the Python script:

python log_analysis.py Check the results in the log_analysis_results.csv file generated in the project directory.

# Sample Output
Requests per IP: Displays the count of requests per IP address. Most Accessed Endpoint: Shows the most accessed endpoint with the number of times it was requested. Suspicious Activity: Lists IP addresses with failed login attempts exceeding the defined threshold.

#License
This project is licensed under the MIT License - see the LICENSE file for details.
