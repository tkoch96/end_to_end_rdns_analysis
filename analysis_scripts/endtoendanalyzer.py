import glob, os, numpy as np, re, datetime, pickle, json
from subprocess import call, check_output

class E2E_Analyzer:
	def __init__(self, skip_load_captures=False, original_captures_dir=None, active_browsing_times={}):

		self.data_dir = "../data"
		self.pkl_dir = "../pickles"
		self.captures_dir = "../captures"
		# Copy data from capture dir to processing dir
		if True: # toggle this if you want to copy data
			if original_captures_dir is None:
				raise ValueError("Set original_captures_dir to the directory where dumpcap saves pcaps, or set this check to False.")
			original_captures_dir = original_captures_dir
			for capture_file in glob.glob(os.path.join(original_captures_dir, "wireshark*")):
				call("cp \"{}\" \"{}\"".format(capture_file, self.captures_dir), shell=True)

		self.active_browsing_times = active_browsing_times

		self.queries = {} # dns queries
		self.plt_stats = {} # plt stats

		self.root_msmt_meta = {
			"a": {
				"meas_id": 5009,
				"asn": 396574,
				"ip": "198.41.0.4",
			},
			"b": {
				"meas_id": 5010,
				"asn": 394353,
				"ip": "192.228.79.201",
			},
			"c": {
				"meas_id": 5011,
				"asn": 2149,
				"ip": "192.33.4.12",
			},
			"d": {
				"meas_id": 5012,
				"asn": 10886,
				"ip": "199.7.91.13",
			},
			"e": {
				"meas_id": 5013,
				"asn": 21556,
				"ip": "192.203.230.10",
			},
			"f": {
				"meas_id": 5004,
				"asn": 3557,
				"ip": "192.5.5.241",
			},
			"g": {
				"meas_id": 5014,
				"asn": 5927,
				"ip": "192.112.36.4",
			},
			"h": {
				"meas_id": 5015,
				"asn": 1508,
				"ip": "198.97.190.53",
			},
			"i": {
				"meas_id": 5005,
				"asn": 29216,
				"ip": "192.36.148.17",
			},
			"j": {
				"meas_id": 5016,
				"asn": 396574,
				"ip": "192.58.128.30",
			},
			"k": {
				"meas_id": 5001,
				"asn": 25152,
				"ip": "193.0.14.129",
			},
			"l": {
				"meas_id": 5008,
				"asn": 20144,
				"ip": "199.7.83.42",
			},
			"m": {
				"meas_id": 5069,
				"asn": 7500,
				"ip": "202.12.27.33",
			},
		}
		self.root_ips = [self.root_msmt_meta[root]["ip"] for root in self.root_msmt_meta]
		self.resolver_ip = "192.168.1.152"
		self.local_ip = "127.0.0.1"
		tlds = ["."]
		with open(os.path.join(self.data_dir, "tld.txt"),'r') as f:
			for row in f:
				tlds.append(row.rstrip())
		self.tlds = set(tlds)

		# Since parsing captures takes a while, I save a temporary pkl for iterating on this file and 
		# give myself the option of skipping parsing of the captures
		# when you have new captures to parse, set this to false
		self.skip_load_captures = skip_load_captures

	def load_captures(self):
		if self.skip_load_captures: return
		print("Reading captures, this may take a second.")
		for capture_file in glob.glob(os.path.join(self.captures_dir, "*.pcapng")):
			# it is assumed the capture file has only DNS traffic
			tshark_cmd = "tshark -2 -r \"{}\" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e udp.srcport -e udp.dstport -e tcp.srcport -e tcp.dstport "\
				"-e dns.qry.name -e dns.qry.type".format(os.path.join(self.captures_dir, capture_file))
			try:
				dns_transaction_summaries = check_output(tshark_cmd, shell=True).decode('utf-8')
			except:
				print("Tshark command failed\n{}".format(tshark_cmd))
				continue
			for summary in dns_transaction_summaries.split('\n'):
				if summary.strip() == '': continue
				try:
					t, src_ip, dst_ip, src_port, dst_port, tcp_src_port, tcp_dst_port, hostname, query_type = summary.split('\t')
					# group queries by day
					# mmddyy
					capture_key = datetime.datetime.fromtimestamp(
						float(t)
					).strftime('%m%d%y')
					try:
						self.queries[capture_key]
					except KeyError:
						self.queries[capture_key] = []
					if src_port == "":
						# tcp DNS
						src_port = tcp_src_port
						dst_port = tcp_dst_port
					self.queries[capture_key].append({
						"time": float(t),
						"src_ip": src_ip,
						"dst_ip": dst_ip,
						"src_port": int(src_port), 
						"dst_port": int(dst_port),
						"hostname": hostname,
						"query_type": int(query_type),
						"to_root": dst_ip in self.root_ips and int(query_type) in [1,28,2],
					})
				except Exception as ex:
					# TCP overhead packets
					continue
		pickle.dump(self.queries, open(os.path.join(self.pkl_dir, "local_root_queries.pkl"),'wb'))


	def print_relevant_statistics(self):
		# Looks at statistics I'm inteested in tabulating for the paper
		# outputs the relevant statistics to a csv in captures_dir

		self.queries = pickle.load(open(os.path.join(self.pkl_dir, "local_root_queries.pkl"), 'rb'))

		# clear out file
		with open(os.path.join(self.captures_dir, 'out.txt'), 'w') as f:
			pass

		for capture_key in sorted(list(self.queries.keys())):
			try:
				self.active_browsing_times[capture_key]
			except KeyError:
				continue

			# print("Day: {}".format(capture_key))
			these_queries = self.queries[capture_key]
			all_times = [query["time"] for query in these_queries]
			start_time = np.min(all_times)
			total_time = (np.max(all_times) - start_time) / 3600 # hours

			root_queries = [query for query in these_queries if query["to_root"]]
			valid_tld_root_queries = [query for query in root_queries if query["hostname"].split('.')[-1] in self.tlds]

			n_queries_to_outside = len([query for query in these_queries if query["src_ip"] == self.resolver_ip])
			n_root_queries = len(root_queries)
			n_valid_tld_root_queries = len(valid_tld_root_queries)
			n_queries_client = len([query for query in these_queries if query["src_ip"] == self.local_ip and query["dst_port"] == 53])
			n_answers_client = len([query for query in these_queries if query["src_ip"] == self.local_ip and query["src_port"] == 53])
			browsing_time = self.active_browsing_times[capture_key]
			try:
				total_plt = sum([page_load['load_event_end'] for page_load in self.plt_stats[capture_key]])
				n_page_loads = len(self.plt_stats[capture_key])
			except KeyError:
				total_plt = 'NA'
				n_page_loads = 'NA'
			# Tabulate all DNS latency, and all root DNS latency incurred by client
			latencies = self.get_latencies_from_queries(capture_key)

			total_client_latency = np.sum([el["latency"] for el in latencies['client']])
			total_root_latency = np.sum([el["latency"] for el in latencies["resolver"] if el["to_root"]])
			total_valid_root_latency = np.sum([el["latency"] for el in latencies['resolver'] if el['to_root'] and el['valid_tld']])
			out_stats = "{} {} {} {} {} {} {} {} {} {} {} {}\n".format(capture_key, total_time, browsing_time, n_queries_to_outside, 
				n_root_queries, n_valid_tld_root_queries, n_queries_client, n_answers_client, 
				total_client_latency, total_valid_root_latency, total_plt, n_page_loads)
			with open(os.path.join(self.captures_dir, "out.txt"), 'a') as f:
				f.write(out_stats)

			# print("Capture: {}, total time in hours: {}, total queries to outside: {}, total queries to root: {}, valid TLD queries to root: {}".format(
			# 	capture_key, total_time, n_queries_to_outside, n_root_queries, n_valid_tld_root_queries))
			# print("Client queries: {}, resolver answers: {}, root cache miss rate: {}, valid root cache miss rate: {}".format(
			# 	n_queries_client, n_answers_client, n_root_queries / n_queries_client, n_valid_tld_root_queries / n_queries_client))
			# browsing_time_seconds = self.active_browsing_times[capture_key] * 60
			# print("Total browsing time (min): {}, total DNS latency: {} ({} percent), total root DNS latency: {} ({} percent), total valid TLD root DNS latency: {}".format(
			# 	browsing_time_seconds//60, total_client_latency, total_client_latency * 100.0 / browsing_time_seconds, 
			# 	total_root_latency, total_root_latency * 100.0 / browsing_time_seconds, total_valid_root_latency))

			# # Look at what was queried from the roots
			# queried_tlds = [query["hostname"].split(".")[-1] for query in root_queries]
			# u,c = np.unique(queried_tlds, return_counts=True)
			# print(sorted(zip(u,c), key = lambda el : el[1]))
			# # Ditto, for valid TLD
			# queried_tlds = [query["hostname"].split(".")[-1] for query in valid_tld_root_queries]
			# u,c = np.unique(queried_tlds, return_counts=True)
			# print(sorted(zip(u,c), key = lambda el : el[1]))

	def get_latencies_from_queries(self, capture_key):
		# first, group all questions and answers into transactions
		# transactions have matching flow identifiers, correspond to the same record, append complete within N seconds

		# transactions are either between client and resolver, or between resolver and outside world
		# each transaction maps (questioner_ip, answerer_ip, sender_port, hostname, record_type) to timing objects
		# with fields start_time, end_time, latency
		transactions = { 
			"client": {},
			"resolver": {}
		}

		for dns_packet in self.queries[capture_key]:
			# 4 cases
			if dns_packet["src_ip"] == self.local_ip and dns_packet["dst_port"] == 53:
				# outgoing client query
				transaction_key = (dns_packet["src_ip"], dns_packet["dst_ip"], dns_packet["src_port"],
					dns_packet["hostname"], dns_packet["query_type"])
				try:
					transactions["client"][transaction_key].append({
						"start_time": dns_packet["time"],
						"end_time": None,
						"latency": None,
						"to_root": False,
						"valid_tld": dns_packet["hostname"].split('.')[-1] in self.tlds,
					})

				except KeyError:
					transactions["client"][transaction_key] = [{
						"start_time": dns_packet["time"],
						"end_time": None,
						"latency": None,
						"to_root": False,
						"valid_tld": dns_packet["hostname"].split('.')[-1] in self.tlds,
					}]
			elif dns_packet["src_ip"] == self.local_ip and dns_packet["src_port"] == 53:
				# answer to client query
				transaction_key = (dns_packet["dst_ip"], dns_packet["src_ip"], dns_packet["dst_port"],
					dns_packet["hostname"], dns_packet["query_type"])
				try:
					corresponding_question = transactions["client"][transaction_key][-1]
				except KeyError:
					continue
				corresponding_question["end_time"] = dns_packet["time"]
				corresponding_question["latency"] = dns_packet["time"] - corresponding_question["start_time"]
			elif dns_packet["src_ip"] == self.resolver_ip and dns_packet["dst_port"] == 53:
				# outgoing resolver query
				transaction_key = (dns_packet["src_ip"], dns_packet["dst_ip"], dns_packet["src_port"],
					dns_packet["hostname"], dns_packet["query_type"])
				try:
					transactions["resolver"][transaction_key].append({
						"start_time": dns_packet["time"],
						"end_time": None,
						"latency": None,
						"to_root": dns_packet["to_root"],
						"valid_tld": dns_packet["hostname"].split('.')[-1] in self.tlds,
					})

				except KeyError:
					transactions["resolver"][transaction_key] = [{
						"start_time": dns_packet["time"],
						"end_time": None,
						"latency": None,
						"to_root": dns_packet["to_root"],
						"valid_tld": dns_packet["hostname"].split('.')[-1] in self.tlds,
					}]
			elif dns_packet["dst_ip"] == self.resolver_ip and dns_packet["src_port"] == 53:
				# answer to resolver query
				transaction_key = (dns_packet["dst_ip"], dns_packet["src_ip"], dns_packet["dst_port"],
					dns_packet["hostname"], dns_packet["query_type"])
				corresponding_question = transactions["resolver"][transaction_key][-1]
				corresponding_question["end_time"] = dns_packet["time"]
				corresponding_question["latency"] = dns_packet["time"] - corresponding_question["start_time"]
			else:
				raise ValueError("DNS Packet {} matches no pattern".format(dns_packet))
		latencies = {
			"client": [],
			"resolver": []
		}
		i=0
		for k in latencies:
			for uid in transactions[k]:
				for el in transactions[k][uid]:
					if el["latency"] is None:
						if k != "client":
							i += 1
						continue
					latencies[k].append({
						"latency": el["latency"], 
						"to_root": el["to_root"],
						"valid_tld": el["valid_tld"],
					})
		# These almost always occur because the resolver gets shut down
		print("Couldn't match {} resolver questions with answers.".format(i))
		return latencies

	def load_plt_stats(self):
		# loads data generated by Calvin's plugin which measures PLT from 
		# all web pages
		# I only save plt stats when I've captured all them from a particular day
		# hence, we organize them by day
		# all stats are saved in the captures directory, with file ending plt_stats
		ids_seen = {}
		for stats_file in glob.glob(os.path.join(self.captures_dir, "*.plt_stats")):
			for row in open(stats_file, 'r'):
				plt_obj = json.loads(row)
				try:
					plt_obj['entry']['domComplete']
				except:
					continue
				_id = plt_obj['id']
				try: 
					ids_seen[_id];
					continue
				except KeyError: 
					ids_seen[_id] = None
				t_report = plt_obj['timestamp'] / 1000
				capture_key = datetime.datetime.fromtimestamp(
					float(t_report)
				).strftime('%m%d%y')	
				try:
					self.plt_stats[capture_key]
				except KeyError:
					self.plt_stats[capture_key] = []

				self.plt_stats[capture_key].append({
					"dom_complete": plt_obj['entry']["domComplete"]/1000,
					"load_event_end": plt_obj['entry']['loadEventEnd']/1000,		
				})

	def load_data(self):
		self.load_plt_stats()
		self.load_captures()

	def run(self):
		self.load_data()
		self.print_relevant_statistics()

if __name__ == "__main__":

	# This is tabulated via the 'WebTime tracker' App, which is active across browsers on all user accounts on my PC
	# I add up all the time from all the accounts
	# you would replace this with your statistics

	active_browsing_times = {
			"081920": 1 * 60 + 57 + 52, # minutes
			"082020": 39 + 21 + 2*60,
			"082120": 26 + 1*60 + 3 + 1*60+57,
			"082220": 1*60+53,
			"082320": 49,
			"082420": 36 + 21 + 2*60+1,
			"082520": 26 + 49 + 3*60 + 39,
			"082620": 55 + 3,
			"082720": 1*60 + 2 + 33 + 1*60 + 55,
			"082820": 1*60+10 + 17 + 2*60+23, # problem parsing this pcap, perhaps nix
			"082920": 20,
			"083020": 0,
			"083120": 22+ 1*60 + 10 + 3*60+13,
			"090120": 11 + 1*60 + 9 + 3*60 + 54,
			"090220": 1*60 + 3*60,
			"090320": 42 + 40 + 1*60 + 6, 
			"090420": 53 + 2*60 + 35,
			"090520": 60 + 41 + 30,
			"090620": 49,
			"090720": 9 + 1*60 + 1,
			"090820": 19 + 4*60 + 24,
			"090920": 1*60 + 37,
			"091020": 52 + 3*60 + 43,
			"091120": 1*60 + 17 + 3*60 + 43,
			"091220": 9 + 27,
			"091320": 0,
			"091420": 1*60 + 2 + 5 + 4*60 + 16,
			"091520": 4 + 4*60 + 54,
		}

	e2ea = E2E_Analyzer(skip_load_captures=True, active_browsing_times=active_browsing_times,
		original_captures_dir="/mnt/c/users/tomko/AppData/Local/Temp")
	e2ea.run()