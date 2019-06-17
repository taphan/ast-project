# CS453 - Automated Software Testing Project
## Installation Guide
Install the Damn Vulnerable Web Application (DVWA) by following guides such as: https://youtu.be/cak2lQvBRAo

After following the guide, at **xampp/htdocs** directory, paste in the **dvwa** folder in this project at that directory. This is to prevent errors caused by using deprecated methods in PHP 7.0, which the original DVWA code contains.

Selenium looks for a **localhost** link, therefore before running the code, make sure to run the Apache server on XAMPP (or other server if desired). Also start connection to MySQL server. 

To run Selenium, first install Chrome webdriver. Then, navigate to **tool/** then run the **injection.py** file. Afterward, in the terminal, paste in a file path for the PHP files that contains link to the database. This is a user input required by fileParser.py. In this project it is located under **xampp/htdocs/dvwa/vulnerabilities/sqli/source/<file.php>** where <file.php> is either low.php, medium.php, high.php or impossible.php. Afterward, a Chrome browser will go through the DVWA and start injecting values. Check the terminal for output.
