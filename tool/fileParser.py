class Parser:
	def __init__(self, file_name):
		self.sql = ""
		self.table_name = ""
		self.file = file_name
		self.num_params_output = 0
		self.preventions = []
		self.prevention_type = 0
		self.parse_for_prevention()

	def parse_for_prevention(self):
		print(self.file)
		with open(self.file) as f:
			lines = f.readlines()
			print("lines open")
			for i in range(len(lines)):
				if "SELECT" in lines[i] and "FROM" in lines[i]:
					self.get_table_name(lines[i])
					self.get_param_nums(lines[i])
				if "real_escape_string" in lines[i]:
					self.preventions.append("real_escape_string")
					self.prevention_type = 1
				if "prepare" in lines[i]:
					self.preventions.append("prepare")
					self.prevention_type = 2
				if "bind_param" in lines[i]:
					self.preventions.append("bind")
					self.prevention_type = 2

	def get_table_name(self, line):
		query_split = line.split("FROM")[-1]
		self.table_name = query_split.split()[0]

	def get_param_nums(self, line):
		select_and_params = line.split("FROM")[0]
		params = select_and_params.split("SELECT")[-1]
		if "*" in params:
			self.num_params_output = 0						# num_param_output = 0 --> SELECT ALL
		else:
			self.num_params_output = len(params.split(","))

def add(a, b):
	return a + b
# file_name = input("file name: ")
# print(file_name)
# p = Parser(file_name)
# print(p.table_name)
# print(p.num_params_output)
# print(p.prevention_type)
